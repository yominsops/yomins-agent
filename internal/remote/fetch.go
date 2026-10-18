package remote

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
	"github.com/yominsops/yomins-agent/internal/transport"
)

// Fetcher polls the server for configuration changes.
type Fetcher struct {
	Server   string
	Token    string
	Hostname string
	StateDir string
	Mode     string
	Interval time.Duration // default 60s
	// Current is the version in use ("" when none).
	Current string
	// Started is when the agent started: restarts are spaced at least
	// MinUptime apart so a flapping configuration cannot trip systemd's
	// start limit.
	Started   time.Time
	MinUptime time.Duration // default 2m
	// Restart is called once a new configuration is saved.
	Restart func(version string)
	Session *transport.Session
	Client  *http.Client
}

// Run polls until ctx is done or a restart was requested.
func (f *Fetcher) Run(ctx context.Context) {
	if f.Mode == ModeOff {
		return
	}
	if f.Interval <= 0 {
		f.Interval = time.Minute
	}
	if f.MinUptime <= 0 {
		f.MinUptime = 2 * time.Minute
	}
	if f.Client == nil {
		f.Client = &http.Client{Timeout: 15 * time.Second}
	}
	t := time.NewTicker(f.Interval)
	defer t.Stop()
	for {
		if s, changed := f.check(ctx); changed {
			if wait := f.MinUptime - time.Since(f.Started); wait > 0 {
				slog.Info("remote config: new version, applying after a short wait", "version", s.Version, "in", wait.Round(time.Second))
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
			slog.Info("remote config: new version, restarting to apply it", "version", s.Version, "was", f.Current)
			f.Restart(s.Version)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// check fetches the configuration; changed is true when a new valid one was saved.
func (f *Fetcher) check(ctx context.Context) (Stored, bool) {
	if f.Session != nil && f.Session.Paused() {
		return Stored{}, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.Server+"/config", nil)
	if err != nil {
		return Stored{}, false
	}
	req.Header.Set("Authorization", "Bearer "+f.Token)
	req.Header.Set("X-Yomins-Hostname", f.Hostname)
	if f.Current != "" {
		req.Header.Set("If-None-Match", strconv.Quote(f.Current))
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		slog.Debug("remote config: fetch failed", "error", err)
		return Stored{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 304 unchanged; 404 an ingest server without remote configuration.
		return Stored{}, false
	}
	var s Stored
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&s); err != nil || s.Version == "" {
		slog.Warn("remote config: unreadable answer", "error", err)
		return Stored{}, false
	}
	if s.Version == f.Current {
		return Stored{}, false
	}
	if err := Validate(s.Config); err != nil {
		slog.Warn("remote config: refused", "version", s.Version, "error", err)
		return Stored{}, false
	}
	if err := Save(f.StateDir, s); err != nil {
		slog.Warn("remote config: cannot save", "error", err)
		return Stored{}, false
	}
	return s, true
}

// InfoCollector reports which configuration the agent runs with.
type InfoCollector struct {
	Version string // "" when there is no remote configuration
	Mode    string
}

func (c InfoCollector) Name() string { return "remote_config" }

func (c InfoCollector) Collect(context.Context) ([]metrics.MetricPoint, error) {
	source := "local"
	if c.Version != "" && c.Mode != ModeOff {
		source = "remote"
	}
	return []metrics.MetricPoint{{Name: "agent_config_info", Help: "Always 1; the configuration the agent applies (version of the remote one, source, trust mode)",
		Type: metrics.Gauge, Value: 1, Labels: map[string]string{"version": c.Version, "config_source": source, "mode": c.Mode}}}, nil
}
