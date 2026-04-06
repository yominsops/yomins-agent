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
		values: []collector.CPUTimesStat{{User: 100, System: 50, Idle: 800, Nice: 25, Iowait: 50, Irq: 5, Softirq: 10, Steal: 2}},
	}
	c := collector.NewCPUCollectorWithReaders(&mockCPUReader{values: []float64{25.0}}, tr)

	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// First call: no prev snapshot, so no iowait percentage yet.
	if len(pts) != 9 {
		t.Errorf("points count = %d, want 9 (usage + 8 cpu_seconds_total modes)", len(pts))
	}
	if pts[0].Name != "cpu_usage_percent" {
		t.Errorf("Name = %q, want cpu_usage_percent", pts[0].Name)
	}
	for _, p := range pts[1:] {
		if p.Name != "cpu_seconds_total" {
			t.Errorf("unexpected metric %q, want cpu_seconds_total", p.Name)
		}
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
	if len(pts) != 10 {
		t.Fatalf("points count = %d, want 10", len(pts))
	}

	var iowaitPt *metrics.MetricPoint
	var counterModes int
	for i := range pts {
		if pts[i].Name == "cpu_iowait_percent" {
			iowaitPt = &pts[i]
		}
		if pts[i].Name == "cpu_seconds_total" {
			counterModes++
			if pts[i].Type != metrics.Counter {
				t.Errorf("cpu_seconds_total type = %v, want Counter", pts[i].Type)
			}
			if pts[i].Labels["mode"] == "" {
				t.Error("cpu_seconds_total missing mode label")
			}
		}
	}
	if iowaitPt == nil {
		t.Fatal("cpu_iowait_percent not found in points")
	}
	if counterModes != 8 {
		t.Fatalf("cpu_seconds_total count = %d, want 8", counterModes)
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
		t.Errorf("points count = %d, want 1 (times error → no cpu_seconds_total and no iowait)", len(pts))
	}
}

func TestCPUCollector_EmitsCPUModeCounters(t *testing.T) {
	tr := &mockCPUTimesReader{
		values: []collector.CPUTimesStat{{
			User: 100, System: 50, Idle: 800, Nice: 20, Iowait: 10, Irq: 2, Softirq: 3, Steal: 4,
		}},
	}
	c := collector.NewCPUCollectorWithReaders(&mockCPUReader{values: []float64{25.0}}, tr)

	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	want := map[string]float64{
		"user":    100,
		"system":  50,
		"idle":    800,
		"nice":    20,
		"iowait":  10,
		"irq":     2,
		"softirq": 3,
		"steal":   4,
	}

	got := map[string]float64{}
	for _, p := range pts {
		if p.Name != "cpu_seconds_total" {
			continue
		}
		got[p.Labels["mode"]] = p.Value
		if p.Type != metrics.Counter {
			t.Errorf("cpu_seconds_total{%q} type = %v, want Counter", p.Labels["mode"], p.Type)
		}
	}

	if len(got) != len(want) {
		t.Fatalf("cpu_seconds_total modes = %d, want %d", len(got), len(want))
	}
	for mode, wantValue := range want {
		if got[mode] != wantValue {
			t.Errorf("cpu_seconds_total{mode=%q} = %v, want %v", mode, got[mode], wantValue)
		}
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
