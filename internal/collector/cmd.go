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
//
// The run itself is not bound by the push: dnf on a small RHEL host can take
// longer than a collection pass may, and a run cut short would leave the
// metrics out for the whole ttl. So it runs in the background, up to
// maxRun, and each push reports the last finished result. Only the first
// run is waited for, as long as the pass allows.
type everyCollector struct {
	inner  Collector
	ttl    time.Duration
	maxRun time.Duration
	now    func() time.Time

	mu      sync.Mutex
	at      time.Time // when the last run finished; zero before the first
	pts     []metrics.MetricPoint
	err     error
	running chan struct{} // closed when the current run ends; nil when idle
}

// everyMaxRun bounds one background run of an Every collector.
const everyMaxRun = 5 * time.Minute

// Every wraps c so that it runs at most once per ttl.
func Every(ttl time.Duration, c Collector) Collector {
	return &everyCollector{inner: c, ttl: ttl, maxRun: everyMaxRun, now: time.Now}
}

func (e *everyCollector) Name() string { return e.inner.Name() }

func (e *everyCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	e.mu.Lock()
	if e.running == nil && (e.at.IsZero() || e.now().Sub(e.at) >= e.ttl) {
		e.running = make(chan struct{})
		go e.refresh(e.running)
	}
	first, running := e.at.IsZero(), e.running
	e.mu.Unlock()

	if first && running != nil {
		select {
		case <-running:
		case <-ctx.Done():
			return nil, nil // still running; reported once it has finished
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.pts, e.err
}

func (e *everyCollector) refresh(done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), e.maxRun)
	defer cancel()
	pts, err := e.inner.Collect(ctx)

	e.mu.Lock()
	defer e.mu.Unlock()
	e.pts, e.err, e.at = pts, err, e.now()
	if err != nil {
		e.at = e.now().Add(-e.ttl + 5*time.Minute) // try again in 5 minutes
	}
	e.running = nil
	close(done)
}

// wait blocks until a background run, if any, has finished (tests).
func (e *everyCollector) wait() {
	e.mu.Lock()
	ch := e.running
	e.mu.Unlock()
	if ch != nil {
		<-ch
	}
}
