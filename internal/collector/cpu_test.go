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

// mockCPUTimesReader implements CPUTimesReader for testing.
type mockCPUTimesReader struct {
	values []collector.CPUTimesStat
	err    error
}

func (m *mockCPUTimesReader) TimesWithContext(_ context.Context, _ bool) ([]collector.CPUTimesStat, error) {
	return m.values, m.err
}

func TestCPUCollector_IowaitSkippedOnFirstCall(t *testing.T) {
	tr := &mockCPUTimesReader{
		values: []collector.CPUTimesStat{{User: 100, System: 50, Idle: 800, Iowait: 50}},
	}
	c := collector.NewCPUCollectorWithReaders(&mockCPUReader{values: []float64{25.0}}, tr)

	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// First call: no prev snapshot, so only cpu_usage_percent.
	if len(pts) != 1 {
		t.Errorf("points count = %d, want 1 (first call, no delta yet)", len(pts))
	}
	if pts[0].Name != "cpu_usage_percent" {
		t.Errorf("Name = %q, want cpu_usage_percent", pts[0].Name)
	}
}

func TestCPUCollector_IowaitSecondCall(t *testing.T) {
	// Initial snapshot: total = 1000s
	tr := &mockCPUTimesReader{
		values: []collector.CPUTimesStat{{User: 90, System: 0, Idle: 900, Iowait: 10}},
	}
	c := collector.NewCPUCollectorWithReaders(&mockCPUReader{values: []float64{25.0}}, tr)

	// First call primes the prev snapshot.
	_, _ = c.Collect(context.Background())

	// Second snapshot: total delta=100, iowait delta=10 → 10%
	tr.values = []collector.CPUTimesStat{{User: 90, System: 0, Idle: 990, Iowait: 20}}

	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pts) != 2 {
		t.Fatalf("points count = %d, want 2", len(pts))
	}

	var iowaitPt *metrics.MetricPoint
	for i := range pts {
		if pts[i].Name == "cpu_iowait_percent" {
			iowaitPt = &pts[i]
		}
	}
	if iowaitPt == nil {
		t.Fatal("cpu_iowait_percent not found in points")
	}
	if iowaitPt.Value != 10.0 {
		t.Errorf("iowait = %v, want 10.0", iowaitPt.Value)
	}
	if iowaitPt.Type != metrics.Gauge {
		t.Errorf("type = %v, want Gauge", iowaitPt.Type)
	}
}

func TestCPUCollector_IowaitTimesReaderError(t *testing.T) {
	tr := &mockCPUTimesReader{err: errors.New("times read error")}
	c := collector.NewCPUCollectorWithReaders(&mockCPUReader{values: []float64{25.0}}, tr)

	// Should not fail Collect; iowait simply absent.
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pts) != 1 {
		t.Errorf("points count = %d, want 1 (times error → no iowait)", len(pts))
	}
}

func TestCPUCollector_WithReaderHasNoIowait(t *testing.T) {
	// Backward-compat: NewCPUCollectorWithReader never emits iowait.
	c := collector.NewCPUCollectorWithReader(&mockCPUReader{values: []float64{50.0}})
	// Multiple calls to confirm iowait never appears.
	for range 3 {
		pts, _ := c.Collect(context.Background())
		for _, p := range pts {
			if p.Name == "cpu_iowait_percent" {
				t.Error("unexpected cpu_iowait_percent from NewCPUCollectorWithReader")
			}
		}
	}
}
