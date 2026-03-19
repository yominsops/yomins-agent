package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all agent runtime configuration.
type Config struct {
	Server             string
	Token              string
	Interval           time.Duration
	LogLevel           string
	HostnameOverride   string
	DisableFilesystems bool
	DisableNetwork     bool
	InsecureSkipVerify bool
	StateDir           string
}

// Load parses configuration from CLI flags and environment variables.
// Precedence (highest to lowest): CLI flag → environment variable → default.
func Load() (*Config, error) {
	cfg := &Config{}

	fs := flag.NewFlagSet("yomins-agent", flag.ContinueOnError)
	fs.StringVar(&cfg.Server, "server", "", "YominsOps ingestion endpoint URL (YOMINS_SERVER)")
	fs.StringVar(&cfg.Token, "token", "", "Project-scoped authentication token (YOMINS_TOKEN)")
	fs.DurationVar(&cfg.Interval, "interval", 60*time.Second, "Metrics push interval (YOMINS_INTERVAL)")
	fs.StringVar(&cfg.LogLevel, "log-level", "info", "Log level: debug, info, warn, error (YOMINS_LOG_LEVEL)")
	fs.StringVar(&cfg.HostnameOverride, "hostname-override", "", "Override reported hostname (YOMINS_HOSTNAME_OVERRIDE)")
	fs.BoolVar(&cfg.DisableFilesystems, "disable-filesystems", false, "Disable filesystem/disk metrics (YOMINS_DISABLE_FILESYSTEMS)")
	fs.BoolVar(&cfg.DisableNetwork, "disable-network", false, "Disable network interface metrics (YOMINS_DISABLE_NETWORK)")
	fs.BoolVar(&cfg.InsecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification (dev only)")
	fs.StringVar(&cfg.StateDir, "state-dir", "/var/lib/yomins-agent", "Directory for persistent agent state (YOMINS_STATE_DIR)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return nil, fmt.Errorf("parse flags: %w", err)
	}

	// Track which flags were explicitly set on the command line.
	explicitFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	// Overlay environment variables only for flags not set on the CLI.
	overlayEnv(cfg, explicitFlags)

	return cfg, nil
}

// overlayEnv applies environment variable values to fields not set via CLI.
func overlayEnv(cfg *Config, explicit map[string]bool) {
	if !explicit["server"] {
		if v := os.Getenv("YOMINS_SERVER"); v != "" {
			cfg.Server = v
		}
	}
	if !explicit["token"] {
		if v := os.Getenv("YOMINS_TOKEN"); v != "" {
			cfg.Token = v
		}
	}
	if !explicit["interval"] {
		if v := os.Getenv("YOMINS_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				cfg.Interval = d
			}
		}
	}
	if !explicit["log-level"] {
		if v := os.Getenv("YOMINS_LOG_LEVEL"); v != "" {
			cfg.LogLevel = v
		}
	}
	if !explicit["hostname-override"] {
		if v := os.Getenv("YOMINS_HOSTNAME_OVERRIDE"); v != "" {
			cfg.HostnameOverride = v
		}
	}
	if !explicit["disable-filesystems"] {
		if v := os.Getenv("YOMINS_DISABLE_FILESYSTEMS"); isTruthy(v) {
			cfg.DisableFilesystems = true
		}
	}
	if !explicit["disable-network"] {
		if v := os.Getenv("YOMINS_DISABLE_NETWORK"); isTruthy(v) {
			cfg.DisableNetwork = true
		}
	}
	if !explicit["state-dir"] {
		if v := os.Getenv("YOMINS_STATE_DIR"); v != "" {
			cfg.StateDir = v
		}
	}
}

// Validate returns an error if required configuration is missing or invalid.
func (c *Config) Validate() error {
	var errs []string
	if c.Server == "" {
		errs = append(errs, "--server (or YOMINS_SERVER) is required")
	}
	if c.Token == "" {
		errs = append(errs, "--token (or YOMINS_TOKEN) is required")
	}
	if c.Interval <= 0 {
		errs = append(errs, "--interval must be a positive duration")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func isTruthy(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes"
}
