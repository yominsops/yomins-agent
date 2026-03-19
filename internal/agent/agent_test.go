package agent_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/agent"
	"github.com/yominsops/yomins-agent/internal/collector"
	"github.com/yominsops/yomins-agent/internal/metrics"
)

// mockTransport records Push calls.
type mockTransport struct {
	pushCount int32
	pushErr   error
}

func (m *mockTransport) Push(_ context.Context, _ metrics.MetricSet) error {
	atomic.AddInt32(&m.pushCount, 1)
	return m.pushErr
}

// mockCollector returns a fixed set of points.
type mockCollector struct {
	name string
	pts  []metrics.MetricPoint
	err  error
}

func (c *mockCollector) Name() string { return c.name }
func (c *mockCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	return c.pts, c.err
}

func makeAgent(tp *mockTransport, collectors ...collector.Collector) *agent.Agent {
	reg := collector.NewRegistry(collectors...)
	self := collector.NewSelfMetricsCollector("test-id", time.Now())
	cfg := agent.Config{
		Interval: 100 * time.Millisecond,
		AgentID:  "test-id",
		Hostname: "test-host",
		Version:  "0.0.1",
	}
	return agent.New(cfg, reg, tp, self)
}

func TestAgent_TickCallsTransport(t *testing.T) {
	tp := &mockTransport{}
	mc := &mockCollector{
		name: "test",
		pts:  []metrics.MetricPoint{{Name: "m1", Value: 1}},
	}
	a := makeAgent(tp, mc)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	_ = a.Run(ctx) // runs until cancelled

	// Should have ticked at least twice (1 immediate + 1+ from ticker at 100ms interval in 250ms).
	if atomic.LoadInt32(&tp.pushCount) < 2 {
		t.Errorf("pushCount = %d, want >= 2", tp.pushCount)
	}
}

func TestAgent_TransportErrorDoesNotCrash(t *testing.T) {
	tp := &mockTransport{pushErr: errors.New("push failed")}
	mc := &mockCollector{name: "test", pts: []metrics.MetricPoint{{Name: "m1", Value: 1}}}
	a := makeAgent(tp, mc)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	// Must not panic.
	_ = a.Run(ctx)

	if atomic.LoadInt32(&tp.pushCount) == 0 {
		t.Error("expected at least one push attempt")
	}
}

func TestAgent_ContextCancellation(t *testing.T) {
	tp := &mockTransport{}
	a := makeAgent(tp)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := a.Run(ctx)
	// context.Canceled is expected.
	if err == nil {
		t.Error("expected non-nil error after context cancellation")
	}
}

func TestAgent_CollectorErrorIsolated(t *testing.T) {
	tp := &mockTransport{}
	good := &mockCollector{name: "good", pts: []metrics.MetricPoint{{Name: "m1", Value: 1}}}
	bad := &mockCollector{name: "bad", err: errors.New("collector broke")}
	a := makeAgent(tp, good, bad)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Must not panic; push must still be called with partial results.
	_ = a.Run(ctx)

	if atomic.LoadInt32(&tp.pushCount) == 0 {
		t.Error("expected push to be called despite collector error")
	}
}
