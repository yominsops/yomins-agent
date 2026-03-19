package collector_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yominsops/yomins-agent/internal/collector"
	"github.com/yominsops/yomins-agent/internal/metrics"
)

// stubCollector is a minimal Collector for registry tests.
type stubCollector struct {
	name string
	pts  []metrics.MetricPoint
	err  error
}

func (s *stubCollector) Name() string { return s.name }
func (s *stubCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	return s.pts, s.err
}

func TestRegistry_CollectAll_AllSucceed(t *testing.T) {
	c1 := &stubCollector{name: "a", pts: []metrics.MetricPoint{{Name: "m1", Value: 1}}}
	c2 := &stubCollector{name: "b", pts: []metrics.MetricPoint{{Name: "m2", Value: 2}}}
	reg := collector.NewRegistry(c1, c2)

	pts, errs := reg.CollectAll(context.Background())
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if len(pts) != 2 {
		t.Errorf("points count = %d, want 2", len(pts))
	}
}

func TestRegistry_CollectAll_OneFailure_PartialResults(t *testing.T) {
	c1 := &stubCollector{name: "good", pts: []metrics.MetricPoint{{Name: "m1", Value: 1}}}
	c2 := &stubCollector{name: "bad", err: errors.New("collector failed")}
	reg := collector.NewRegistry(c1, c2)

	pts, errs := reg.CollectAll(context.Background())

	if len(pts) != 1 {
		t.Errorf("points count = %d, want 1 (partial results)", len(pts))
	}
	if len(errs) != 1 {
		t.Errorf("errors count = %d, want 1", len(errs))
	}
	if _, ok := errs["bad"]; !ok {
		t.Error("expected error for collector 'bad'")
	}
}

func TestRegistry_CollectAll_Empty(t *testing.T) {
	reg := collector.NewRegistry()
	pts, errs := reg.CollectAll(context.Background())
	if len(pts) != 0 || len(errs) != 0 {
		t.Errorf("expected empty results, got pts=%d errs=%d", len(pts), len(errs))
	}
}

func TestRegistry_CollectAll_AllFail_EmptyPoints(t *testing.T) {
	c1 := &stubCollector{name: "x", err: errors.New("fail")}
	c2 := &stubCollector{name: "y", err: errors.New("fail")}
	reg := collector.NewRegistry(c1, c2)

	pts, errs := reg.CollectAll(context.Background())
	if len(pts) != 0 {
		t.Errorf("expected 0 points, got %d", len(pts))
	}
	if len(errs) != 2 {
		t.Errorf("expected 2 errors, got %d", len(errs))
	}
}
