// Package upgrade implements the self-upgrade mechanism for yomins-agent.
//
// The upgrade flow is split between the agent (unprivileged) and a root-owned
// systemd ExecStartPre script (systemd/apply-upgrade.sh):
//
//  1. The agent calls RunOnce (on startup) or RunPeriodic (every AutoUpgradeInterval).
//  2. If a newer release is found, the binary is downloaded, SHA256-verified, and
//     staged at <stateDir>/upgrade/new.  A "pending" marker is written.
//  3. The agent exits cleanly (os.Exit(0)); systemd restarts it.
//  4. On the next start, apply-upgrade.sh (root) detects the pending marker,
//     backs up the old binary, and atomically replaces it.
//  5. After the first successful metrics push the agent calls Commit(), which
//     writes a "committed" marker.  If the agent crashes before committing,
//     apply-upgrade.sh automatically rolls back to the backup on the next start.
package upgrade

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Config holds upgrade-specific settings passed in from the main config.
type Config struct {
	StateDir       string
	CurrentVersion string        // from version.Version; "dev" disables upgrade
	Interval       time.Duration // how often to check; 0 disables periodic checks
	Disabled       bool
}

// Manager owns the upgrade check logic.
type Manager struct {
	cfg Config
}

// NewManager creates a Manager with the provided configuration.
func NewManager(cfg Config) *Manager {
	return &Manager{cfg: cfg}
}

// RunOnce performs a single check-and-stage cycle.  If a newer version is
// found and staged, it calls os.Exit(0) so systemd can restart the agent and
// apply-upgrade.sh can apply the new binary.  All errors are logged and
// swallowed so that upgrade failures never prevent the agent from running.
func (m *Manager) RunOnce(ctx context.Context) {
	if m.cfg.Disabled {
		slog.Debug("auto-upgrade disabled, skipping check")
		return
	}
	if m.cfg.CurrentVersion == "dev" {
		slog.Debug("dev build, skipping upgrade check")
		return
	}

	slog.Debug("checking for upgrade", "current_version", m.cfg.CurrentVersion)

	latest, err := latestRelease(ctx, m.cfg.CurrentVersion)
	if err != nil {
		slog.Warn("upgrade check failed: could not fetch latest release", "error", err)
		return
	}

	newer, err := isNewer(m.cfg.CurrentVersion, latest)
	if err != nil {
		slog.Warn("upgrade check failed: version comparison error",
			"current", m.cfg.CurrentVersion, "latest", latest, "error", err)
		return
	}
	if !newer {
		slog.Debug("already at latest version", "version", m.cfg.CurrentVersion)
		return
	}

	slog.Info("newer version available, downloading", "current", m.cfg.CurrentVersion, "latest", latest)

	if err := stageUpgrade(ctx, m.cfg.StateDir, latest); err != nil {
		slog.Error("upgrade staging failed", "error", err)
		return
	}

	// Write the pending marker.  apply-upgrade.sh checks for this on next start.
	pendingPath := filepath.Join(m.cfg.StateDir, "upgrade", "pending")
	if err := os.WriteFile(pendingPath, []byte(latest+"\n"), 0600); err != nil {
		slog.Error("failed to write upgrade pending marker", "error", err)
		// Clean up staged binary so we don't apply an uncommitted upgrade.
		_ = os.Remove(filepath.Join(m.cfg.StateDir, "upgrade", "new"))
		return
	}

	slog.Info("upgrade staged, restarting to apply",
		"current", m.cfg.CurrentVersion, "pending", latest)
	os.Exit(0)
}

// RunPeriodic starts a background goroutine that calls RunOnce on the
// configured interval.  The goroutine exits when ctx is cancelled.
// It is a no-op if Interval is 0 or Disabled is true.
func (m *Manager) RunPeriodic(ctx context.Context) {
	if m.cfg.Disabled || m.cfg.Interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(m.cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.RunOnce(ctx)
			}
		}
	}()
}

// Commit writes the "committed" marker to signal that the new binary started
// successfully and pushed metrics.  apply-upgrade.sh uses this on the next
// start to determine whether a rollback is needed.  It is idempotent.
func (m *Manager) Commit() error {
	committedPath := filepath.Join(m.cfg.StateDir, "upgrade", "committed")
	// Only write if the "applied" marker exists (i.e. an upgrade was just applied).
	appliedPath := filepath.Join(m.cfg.StateDir, "upgrade", "applied")
	if _, err := os.Stat(appliedPath); os.IsNotExist(err) {
		return nil // no pending upgrade to commit
	}
	return os.WriteFile(committedPath, []byte("ok\n"), 0600)
}
