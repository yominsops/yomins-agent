package collector_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/collector"
	"github.com/yominsops/yomins-agent/internal/metrics"
)

func TestSelfMetricsCollector_Name(t *testing.T) {
	s := collector.NewSelfMetricsCollector("test-id", time.Now())
	if s.Name() != "self" {
		t.Errorf("Name() = %q, want self", s.Name())
	}
}

func TestSelfMetricsCollector_InitialState(t *testing.T) {
	s := collector.NewSelfMetricsCollector("test-id", time.Now())
	pts, err := s.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	byName := pointsByName(pts)

	if byName["agent_push_success_total"].Value != 0 {
		t.Errorf("initial push_success_total = %v, want 0", byName["agent_push_success_total"].Value)
	}
	if byName["agent_push_error_total"].Value != 0 {
		t.Errorf("initial push_error_total = %v, want 0", byName["agent_push_error_total"].Value)
	}
	if byName["agent_build_info"].Value != 1 {
		t.Errorf("build_info = %v, want 1", byName["agent_build_info"].Value)
	}
}

func TestSelfMetricsCollector_RecordPushSuccess(t *testing.T) {
	s := collector.NewSelfMetricsCollector("test-id", time.Now())
	s.RecordPush(10*time.Millisecond, nil)
	s.RecordPush(20*time.Millisecond, nil)

	pts, _ := s.Collect(context.Background())
	byName := pointsByName(pts)

	if byName["agent_push_success_total"].Value != 2 {
		t.Errorf("push_success_total = %v, want 2", byName["agent_push_success_total"].Value)
	}
	if byName["agent_push_error_total"].Value != 0 {
		t.Errorf("push_error_total = %v, want 0", byName["agent_push_error_total"].Value)
	}
	if byName["agent_last_push_success_timestamp"].Value == 0 {
		t.Error("last_push_success_timestamp should be non-zero after success")
	}
}

func TestSelfMetricsCollector_RecordPushError(t *testing.T) {
	s := collector.NewSelfMetricsCollector("test-id", time.Now())
	s.RecordPush(5*time.Millisecond, errors.New("push failed"))

	pts, _ := s.Collect(context.Background())
	byName := pointsByName(pts)

	if byName["agent_push_error_total"].Value != 1 {
		t.Errorf("push_error_total = %v, want 1", byName["agent_push_error_total"].Value)
	}
	if byName["agent_push_success_total"].Value != 0 {
		t.Errorf("push_success_total = %v, want 0", byName["agent_push_success_total"].Value)
	}
}

func TestSelfMetricsCollector_RecordCollection(t *testing.T) {
	s := collector.NewSelfMetricsCollector("test-id", time.Now())
	errs := map[string]error{"cpu": errors.New("cpu err")}
	s.RecordCollection(500*time.Millisecond, errs)

	pts, _ := s.Collect(context.Background())
	byName := pointsByName(pts)

	if byName["agent_collection_duration_seconds"].Value != 0.5 {
		t.Errorf("collection_duration = %v, want 0.5", byName["agent_collection_duration_seconds"].Value)
	}

	// Find the per-collector error counter.
	var found bool
	for _, p := range pts {
		if p.Name == "agent_collector_error_total" && p.Labels["collector"] == "cpu" {
			if p.Value != 1 {
				t.Errorf("collector_error_total{cpu} = %v, want 1", p.Value)
			}
			found = true
		}
	}
	if !found {
		t.Error("agent_collector_error_total{collector=cpu} not found")
	}
}

func TestSelfMetricsCollector_UptimeIncreases(t *testing.T) {
	start := time.Now().Add(-5 * time.Second)
	s := collector.NewSelfMetricsCollector("test-id", start)

	pts, _ := s.Collect(context.Background())
	byName := pointsByName(pts)

	if byName["agent_uptime_seconds"].Value < 5 {
		t.Errorf("uptime = %v, expected >= 5", byName["agent_uptime_seconds"].Value)
	}
}

// pointsByName returns the first MetricPoint for each metric name.
func pointsByName(pts []metrics.MetricPoint) map[string]metrics.MetricPoint {
	m := make(map[string]metrics.MetricPoint)
	for _, p := range pts {
		if _, exists := m[p.Name]; !exists {
			m[p.Name] = p
		}
	}
	return m
}
