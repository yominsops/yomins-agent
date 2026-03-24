package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yominsops/yomins-agent/internal/agent"
	"github.com/yominsops/yomins-agent/internal/collector"
	"github.com/yominsops/yomins-agent/internal/config"
	"github.com/yominsops/yomins-agent/internal/identity"
	"github.com/yominsops/yomins-agent/internal/transport"
	"github.com/yominsops/yomins-agent/internal/upgrade"
	"github.com/yominsops/yomins-agent/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	// 1. Load and validate configuration.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.Version {
		fmt.Println(version.Info())
		return nil
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// 2. Configure structured logger.
	setupLogger(cfg.LogLevel)
	slog.Info("yomins-agent", "version", version.Info())

	// 3. Resolve hostname.
	hostname := cfg.HostnameOverride
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 4. Load or generate persistent agent identity.
	id := identity.Load(cfg.StateDir)
	slog.Info("agent identity", "agent_id", id.AgentID)

	// 4b. Check for available upgrades and stage if found.
	// RunOnce calls os.Exit(0) if an upgrade is staged; otherwise it returns
	// quickly (< 15s timeout) and normal startup continues.
	upgradeManager := upgrade.NewManager(upgrade.Config{
		StateDir:       cfg.StateDir,
		CurrentVersion: version.Version,
		Interval:       cfg.AutoUpgradeInterval,
		Disabled:       cfg.DisableAutoUpgrade,
	})
	upgradeManager.RunOnce(ctx)

	// 5. Build collector registry.
	collectors := buildCollectors(cfg)
	reg := collector.NewRegistry(collectors...)

	// 6. Create self-metrics collector.
	self := collector.NewSelfMetricsCollector(id.AgentID, time.Now())

	// 7. Create HTTP transport.
	tp := transport.NewHTTPTransport(transport.HTTPConfig{
		Server:             cfg.Server,
		Token:              cfg.Token,
		Interval:           cfg.Interval,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})

	// 8. Create and run agent.
	ag := agent.New(agent.Config{
		Interval:        cfg.Interval,
		AgentID:         id.AgentID,
		Hostname:        hostname,
		Version:         version.Version,
		ShutdownTimeout: 10 * time.Second,
		OnFirstPushSuccess: func() {
			if err := upgradeManager.Commit(); err != nil {
				slog.Warn("upgrade commit failed", "error", err)
			}
		},
	}, reg, tp, self)

	upgradeManager.RunPeriodic(ctx)

	return ag.Run(ctx)
}

// buildCollectors constructs the collector slice based on configuration flags.
func buildCollectors(cfg *config.Config) []collector.Collector {
	collectors := []collector.Collector{
		collector.NewCPUCollector(),
		collector.NewMemoryCollector(),
		collector.NewSystemCollector(),
		collector.NewInfoCollector(collector.InfoConfig{
			DisableKernelCareInfo:  cfg.DisableKernelCareInfo,
			VirtualizationOverride: cfg.VirtualizationOverride,
		}),
	}
	if !cfg.DisableFilesystems {
		if len(cfg.ExcludeMountpoints) > 0 {
			collectors = append(collectors, collector.NewDiskCollectorWithFilters(cfg.ExcludeMountpoints))
		} else {
			collectors = append(collectors, collector.NewDiskCollector())
		}
	}
	if !cfg.DisableNetwork {
		if len(cfg.ExcludeInterfaces) > 0 {
			// Always prepend "lo" so loopback remains excluded regardless of the user list.
			excludes := append([]string{"lo"}, cfg.ExcludeInterfaces...)
			collectors = append(collectors, collector.NewNetworkCollectorWithFilters(excludes))
		} else {
			collectors = append(collectors, collector.NewNetworkCollector())
		}
	}
	return collectors
}

// setupLogger configures the global slog logger for the given level.
func setupLogger(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}
