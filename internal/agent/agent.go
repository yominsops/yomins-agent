package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/yominsops/yomins-agent/internal/collector"
	"github.com/yominsops/yomins-agent/internal/metrics"
	"github.com/yominsops/yomins-agent/internal/transport"
)

// Agent orchestrates the collection → encode → push pipeline on a ticker.
type Agent struct {
	registry  *collector.Registry
	transport transport.Transport
	self      *collector.SelfMetricsCollector
	interval  time.Duration
	agentID   string
	hostname  string
	version   string
}

// Config holds the parameters needed to create an Agent.
type Config struct {
	Interval time.Duration
	AgentID  string
	Hostname string
	Version  string
}

// New creates an Agent with the provided dependencies.
func New(cfg Config, reg *collector.Registry, tp transport.Transport, self *collector.SelfMetricsCollector) *Agent {
	return &Agent{
		registry:  reg,
		transport: tp,
		self:      self,
		interval:  cfg.Interval,
		agentID:   cfg.AgentID,
		hostname:  cfg.Hostname,
		version:   cfg.Version,
	}
}

// Run starts the agent loop, blocking until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	slog.Info("agent started", "interval", a.interval, "agent_id", a.agentID, "hostname", a.hostname)

	// Run one tick immediately so metrics appear right away.
	a.tick(ctx)

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("agent shutting down")
			return ctx.Err()
		case <-ticker.C:
			a.tick(ctx)
		}
	}
}

// tick performs one full collect → encode → push cycle.
func (a *Agent) tick(ctx context.Context) {
	collectStart := time.Now()
	points, collectorErrs := a.registry.CollectAll(ctx)
	collectDuration := time.Since(collectStart)

	if len(collectorErrs) > 0 {
		for name, err := range collectorErrs {
			slog.Warn("collector error", "collector", name, "error", err)
		}
	}
	a.self.RecordCollection(collectDuration, collectorErrs)

	// Append self-metrics after recording so they reflect this tick's stats.
	selfPoints, _ := a.self.Collect(ctx)
	points = append(points, selfPoints...)

	ms := metrics.MetricSet{
		Points:      points,
		AgentID:     a.agentID,
		Hostname:    a.hostname,
		Version:     a.version,
		Source:      "yomins_agent",
		CollectedAt: time.Now(),
	}

	pushStart := time.Now()
	err := a.transport.Push(ctx, ms)
	pushDuration := time.Since(pushStart)

	a.self.RecordPush(pushDuration, err)

	if err != nil {
		slog.Error("push failed", "error", err, "duration", pushDuration.Round(time.Millisecond))
	} else {
		slog.Info("push succeeded",
			"points", len(ms.Points),
			"collect_ms", collectDuration.Milliseconds(),
			"push_ms", pushDuration.Milliseconds(),
		)
	}
}
