package collector_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/collector"
	"github.com/yominsops/yomins-agent/internal/metrics"
)

// mockCPUReader implements cpuReader for testing.
type mockCPUReader struct {
	values []float64
	err    error
}

func (m *mockCPUReader) PercentWithContext(_ context.Context, _ time.Duration, _ bool) ([]float64, error) {
	return m.values, m.err
}

func TestCPUCollector_Name(t *testing.T) {
	c := collector.NewCPUCollectorWithReader(&mockCPUReader{values: []float64{0}})
	if c.Name() != "cpu" {
		t.Errorf("Name() = %q, want cpu", c.Name())
	}
}

func TestCPUCollector_Collect(t *testing.T) {
	mock := &mockCPUReader{values: []float64{42.5}}
	c := collector.NewCPUCollectorWithReader(mock)

	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pts) != 1 {
		t.Fatalf("points count = %d, want 1", len(pts))
	}
	pt := pts[0]
	if pt.Name != "cpu_usage_percent" {
		t.Errorf("Name = %q, want cpu_usage_percent", pt.Name)
	}
	if pt.Type != metrics.Gauge {
		t.Errorf("Type = %v, want Gauge", pt.Type)
	}
	if pt.Value != 42.5 {
		t.Errorf("Value = %v, want 42.5", pt.Value)
	}
}

func TestCPUCollector_ReaderError(t *testing.T) {
	mock := &mockCPUReader{err: errors.New("read error")}
	c := collector.NewCPUCollectorWithReader(mock)

	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestCPUCollector_EmptyResult(t *testing.T) {
	mock := &mockCPUReader{values: []float64{}}
	c := collector.NewCPUCollectorWithReader(mock)

	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error for empty result, got nil")
	}
}
