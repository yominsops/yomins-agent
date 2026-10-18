package collector

import (
	"context"
	"os/exec"
	"sync"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// runner runs an external command; tests replace it.
type runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

// everyCollector runs an expensive collector at most once per ttl and
// reports its last result in between, so a package manager or a certificate
// scan runs a few times a day while the metrics go out with every push.
type everyCollector struct {
	inner Collector
	ttl   time.Duration
	now   func() time.Time

	mu  sync.Mutex
	at  time.Time
	pts []metrics.MetricPoint
	err error
}

// Every wraps c so that it runs at most once per ttl.
func Every(ttl time.Duration, c Collector) Collector {
	return &everyCollector{inner: c, ttl: ttl, now: time.Now}
}

func (e *everyCollector) Name() string { return e.inner.Name() }

func (e *everyCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.at.IsZero() && e.now().Sub(e.at) < e.ttl {
		return e.pts, e.err
	}
	e.pts, e.err = e.inner.Collect(ctx)
	e.at = e.now()
	if e.err != nil {
		e.at = e.now().Add(-e.ttl + 5*time.Minute) // try again in 5 minutes
	}
	return e.pts, e.err
}
