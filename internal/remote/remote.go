// Package remote applies the configuration an admin sets in the portal.
//
// The agent fetches it from the ingest server (GET <server>/config), keeps
// the last one in the state directory, and applies it at startup over the
// local configuration. When a new version arrives the agent restarts to
// apply it (like a self-upgrade), so a configuration in use never depends on
// the network.
//
// The host owner decides how far to trust it with YOMINS_REMOTE_CONFIG:
// "full" (default), "limited" (no settings that choose what is read: log
// paths, scrape URLs), or "off". Log files outside the local allow list are
// never read whatever the server says.
package remote

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/yominsops/yomins-agent/internal/config"
	"github.com/yominsops/yomins-agent/internal/logs"
)

// Modes of YOMINS_REMOTE_CONFIG.
const (
	ModeFull    = "full"
	ModeLimited = "limited"
	ModeOff     = "off"
)

// Config mirrors the server's agentconfig.Config: every field optional.
type Config struct {
	Interval           *string             `json:"interval,omitempty"`
	DisabledCollectors []string            `json:"disabled_collectors,omitempty"`
	Logs               *LogsConfig         `json:"logs,omitempty"`
	Integrations       *IntegrationsConfig `json:"integrations,omitempty"`
	Events             *EventsConfig       `json:"events,omitempty"`
}

type LogsConfig struct {
	Enabled *bool    `json:"enabled,omitempty"`
	Paths   []string `json:"paths,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	Redact  []string `json:"redact,omitempty"`
}

type IntegrationsConfig struct {
	Enabled        *bool    `json:"enabled,omitempty"`
	NginxStatusURL *string  `json:"nginx_status_url,omitempty"`
	ScrapeURLs     []string `json:"scrape_urls,omitempty"`
}

type EventsConfig struct {
	Enabled          *bool `json:"enabled,omitempty"`
	Auth             *bool `json:"auth,omitempty"`
	Process          *bool `json:"process,omitempty"`
	Network          *bool `json:"network,omitempty"`
	System           *bool `json:"system,omitempty"`
	ProcessLifecycle *bool `json:"process_lifecycle,omitempty"`
}

// Stored is what is kept on disk and served by the ingest server.
type Stored struct {
	Version string `json:"version"`
	Config  Config `json:"config"`
}

const fileName = "remote_config.json"

// Load reads the stored configuration; ok is false when there is none.
func Load(stateDir string) (Stored, bool) {
	var s Stored
	b, err := os.ReadFile(filepath.Join(stateDir, fileName))
	if err != nil || json.Unmarshal(b, &s) != nil || s.Version == "" {
		return Stored{}, false
	}
	return s, true
}

// Save writes the configuration atomically.
func Save(stateDir string, s Stored) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	p := filepath.Join(stateDir, fileName)
	if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// Validate refuses values the agent could not act on.
func Validate(c Config) error {
	if c.Interval != nil {
		d, err := time.ParseDuration(*c.Interval)
		if err != nil || d < 10*time.Second || d > 10*time.Minute {
			return fmt.Errorf("interval %q out of range", *c.Interval)
		}
	}
	if c.Logs != nil {
		for _, p := range c.Logs.Redact {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("redact pattern %q: %w", p, err)
			}
		}
		for _, g := range c.Logs.Paths {
			if _, glob := logs.SplitTyped(g); !filepath.IsAbs(glob) {
				return errors.New("log paths must be absolute")
			}
		}
		for _, g := range c.Logs.Exclude {
			if !filepath.IsAbs(g) {
				return errors.New("log paths must be absolute")
			}
		}
	}
	return nil
}

// Apply sets the remote values over cfg according to mode. Local lists
// (log paths, scrape URLs) are extended, not replaced: what the host owner
// configured stays.
func Apply(cfg *config.Config, c Config, mode string) {
	if mode == ModeOff {
		return
	}
	if c.Interval != nil {
		if d, err := time.ParseDuration(*c.Interval); err == nil {
			cfg.Interval = d
		}
	}
	if c.DisabledCollectors != nil {
		cfg.DisabledCollectors = c.DisabledCollectors
	}
	if l := c.Logs; l != nil {
		if l.Enabled != nil {
			cfg.Logs = "off"
			if *l.Enabled {
				cfg.Logs = "auto"
			}
		}
		if mode == ModeFull {
			cfg.LogPaths = append(cfg.LogPaths, l.Paths...)
		}
		cfg.LogExclude = append(cfg.LogExclude, l.Exclude...)
		cfg.LogRedact = append(cfg.LogRedact, l.Redact...)
	}
	if i := c.Integrations; i != nil {
		if i.Enabled != nil {
			cfg.DisableIntegrations = !*i.Enabled
		}
		if mode == ModeFull {
			if i.NginxStatusURL != nil && cfg.NginxStatusURL == "" {
				cfg.NginxStatusURL = *i.NginxStatusURL
			}
			cfg.ScrapeURLs = append(cfg.ScrapeURLs, i.ScrapeURLs...)
		}
	}
	if e := c.Events; e != nil {
		set := func(dst *bool, v *bool, disable bool) {
			if v != nil {
				*dst = *v
				if disable {
					*dst = !*v
				}
			}
		}
		set(&cfg.DisableEvents, e.Enabled, true)
		set(&cfg.DisableAuthEvents, e.Auth, true)
		set(&cfg.DisableProcessEvents, e.Process, true)
		set(&cfg.DisableNetworkEvents, e.Network, true)
		set(&cfg.DisableSystemEvents, e.System, true)
		set(&cfg.MonitorProcessLifecycle, e.ProcessLifecycle, false)
	}
}
