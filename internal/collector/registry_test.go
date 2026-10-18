package collector_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

// slowCollector blocks until release is closed, ignoring its context the way
// an uninterruptible call (statfs on a hung mount) would.
type slowCollector struct {
	name    string
	release chan struct{}
}

func (s *slowCollector) Name() string { return s.name }
func (s *slowCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	<-s.release
	return []metrics.MetricPoint{{Name: s.name + "_late"}}, nil
}

func TestRegistry_CollectAll_TimeoutDoesNotBlockOthers(t *testing.T) {
	slow := &slowCollector{name: "slow", release: make(chan struct{})}
	fast := &stubCollector{name: "fast", pts: []metrics.MetricPoint{{Name: "m"}}}
	reg := collector.NewRegistry(slow, fast).WithTimeout(50 * time.Millisecond)

	start := time.Now()
	pts, errs := reg.CollectAll(context.Background())
	if time.Since(start) > time.Second {
		t.Fatalf("pass took %v, want about the timeout", time.Since(start))
	}
	if len(pts) != 1 || pts[0].Name != "m" {
		t.Errorf("points = %v, want only the fast collector's", pts)
	}
	if errs["slow"] == nil || !strings.Contains(errs["slow"].Error(), "timed out") {
		t.Errorf("slow error = %v, want a timeout", errs["slow"])
	}

	// Still stuck: not started again, reported as still running.
	_, errs = reg.CollectAll(context.Background())
	if errs["slow"] == nil || !strings.Contains(errs["slow"].Error(), "still running") {
		t.Errorf("slow error = %v, want still running", errs["slow"])
	}

	// Once it returns it runs again.
	close(slow.release)
	time.Sleep(20 * time.Millisecond)
	pts, errs = reg.CollectAll(context.Background())
	if len(errs) != 0 || len(pts) != 2 {
		t.Errorf("after release: pts=%v errs=%v", pts, errs)
	}
}

func TestRegistry_CollectAll_KeepsRegistrationOrder(t *testing.T) {
	var cs []collector.Collector
	for _, n := range []string{"a", "b", "c", "d"} {
		cs = append(cs, &stubCollector{name: n, pts: []metrics.MetricPoint{{Name: n}}})
	}
	pts, _ := collector.NewRegistry(cs...).CollectAll(context.Background())
	var got []string
	for _, p := range pts {
		got = append(got, p.Name)
	}
	if strings.Join(got, "") != "abcd" {
		t.Errorf("order = %v", got)
	}
}
