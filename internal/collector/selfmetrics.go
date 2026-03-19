package collector

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
	"github.com/yominsops/yomins-agent/internal/version"
)

// SelfMetricsCollector tracks agent internal health metrics.
// All fields are protected by a mutex since RecordPush/RecordCollection
// are called from the agent loop potentially concurrently with Collect.
type SelfMetricsCollector struct {
	mu sync.Mutex

	agentID   string
	startedAt time.Time

	pushSuccessTotal    float64
	pushErrorTotal      float64
	lastPushSuccessTS   float64 // Unix timestamp
	collectionDurationS float64 // last collection duration in seconds
	pushDurationS       float64 // last push duration in seconds
	collectorErrors     map[string]float64
}

// NewSelfMetricsCollector creates a new SelfMetricsCollector.
func NewSelfMetricsCollector(agentID string, startedAt time.Time) *SelfMetricsCollector {
	return &SelfMetricsCollector{
		agentID:         agentID,
		startedAt:       startedAt,
		collectorErrors: make(map[string]float64),
	}
}

// RecordCollection updates internal state after a collection pass.
func (s *SelfMetricsCollector) RecordCollection(duration time.Duration, errs map[string]error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collectionDurationS = duration.Seconds()
	for name := range errs {
		s.collectorErrors[name]++
	}
}

// RecordPush updates internal state after a push attempt.
func (s *SelfMetricsCollector) RecordPush(duration time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pushDurationS = duration.Seconds()
	if err != nil {
		s.pushErrorTotal++
	} else {
		s.pushSuccessTotal++
		s.lastPushSuccessTS = float64(time.Now().Unix())
	}
}

func (s *SelfMetricsCollector) Name() string { return "self" }

func (s *SelfMetricsCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	uptime := time.Since(s.startedAt).Seconds()

	pts := []metrics.MetricPoint{
		{
			Name:  "agent_push_success_total",
			Help:  "Total number of successful metric push operations",
			Type:  metrics.Counter,
			Value: s.pushSuccessTotal,
		},
		{
			Name:  "agent_push_error_total",
			Help:  "Total number of failed metric push operations",
			Type:  metrics.Counter,
			Value: s.pushErrorTotal,
		},
		{
			Name:  "agent_last_push_success_timestamp",
			Help:  "Unix timestamp of the last successful push",
			Type:  metrics.Gauge,
			Value: s.lastPushSuccessTS,
		},
		{
			Name:  "agent_collection_duration_seconds",
			Help:  "Duration of the last full collection pass in seconds",
			Type:  metrics.Gauge,
			Value: s.collectionDurationS,
		},
		{
			Name:  "agent_push_duration_seconds",
			Help:  "Duration of the last push attempt in seconds",
			Type:  metrics.Gauge,
			Value: s.pushDurationS,
		},
		{
			Name:  "agent_uptime_seconds",
			Help:  "Agent process uptime in seconds",
			Type:  metrics.Gauge,
			Value: uptime,
		},
		{
			Name: "agent_build_info",
			Help: "Agent build information",
			Type: metrics.Gauge,
			// Always 1; dimensions are in labels.
			Value: 1,
			Labels: map[string]string{
				"version":    version.Version,
				"commit":     version.Commit,
				"build_date": version.BuildDate,
				"go_version": runtime.Version(),
				"os":         runtime.GOOS,
				"arch":       runtime.GOARCH,
			},
		},
	}

	// Append per-collector error counters.
	for name, count := range s.collectorErrors {
		pts = append(pts, metrics.MetricPoint{
			Name:  "agent_collector_error_total",
			Help:  "Total errors per collector",
			Type:  metrics.Counter,
			Value: count,
			Labels: map[string]string{
				"collector": name,
			},
		})
	}

	return pts, nil
}
