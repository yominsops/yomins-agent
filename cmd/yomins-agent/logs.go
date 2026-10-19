package main

import (
	"context"
	"log/slog"

	"github.com/yominsops/yomins-agent/internal/config"
	"github.com/yominsops/yomins-agent/internal/logs"
	"github.com/yominsops/yomins-agent/internal/transport"
)

// startLogPipeline discovers the host's logs and ships them in the
// background. It returns the stats to report with the metrics, or nil when
// log collection is off.
func startLogPipeline(ctx context.Context, cfg *config.Config, hostname, agentID string, session *transport.Session) *logs.Stats {
	if cfg.Logs != "auto" || cfg.Server == "" || cfg.Token == "" {
		return nil
	}
	allow := cfg.LogAllow
	if len(allow) == 0 {
		allow = logs.DefaultAllow
	}
	redactor, err := logs.NewRedactor(cfg.LogRedact)
	if err != nil {
		slog.Error("logs: redaction rules invalid, logs not collected", "error", err)
		return nil
	}

	plan := logs.Discover(cfg.LogPaths, cfg.LogExclude)
	positions := logs.LoadPositions(cfg.StateDir)
	stats := logs.NewStats()

	fileSource := logs.NewFileSource(plan.Files, allow, positions)
	stats.Watch(fileSource.Watched)
	stats.WatchDenied(fileSource.Denied)
	sources := []logs.Source{fileSource}
	if plan.Journal {
		sources = append(sources, logs.NewJournalSource(nil, positions))
	}
	names := make([]string, 0, len(plan.Files))
	for _, f := range plan.Files {
		names = append(names, f.Source)
	}
	slog.Info("logs: collecting", "sources", names, "journal", plan.Journal)

	poster := transport.NewPoster(cfg.Server, cfg.Token, cfg.InsecureSkipVerify, session)
	shipper := logs.NewShipper(logs.ShipperConfig{Hostname: hostname, AgentID: agentID}, poster, redactor, stats)
	go logs.NewPipeline(sources, shipper, positions).Run(ctx)
	return stats
}
