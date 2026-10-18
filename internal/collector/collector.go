package collector

import (
	"context"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// Collector is implemented by every system metrics source.
// Name returns a stable identifier used in logs and self-metrics labelling.
// Collect gathers the current snapshot. Implementations must be safe to call
// concurrently (stateful collectors must protect shared state with a mutex).
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]metrics.MetricPoint, error)
}

// isExcluded returns true if name is present in the excludes list.
// The comparison is exact (case-sensitive).
func isExcluded(name string, excludes []string) bool {
	for _, ex := range excludes {
		if ex == name {
			return true
		}
	}
	return false
}

// matchesAnyGlob reports whether name matches at least one shell glob pattern.
// Uses path.Match semantics: * matches any sequence of non-separator characters.
// Invalid patterns are silently skipped (never match).
func matchesAnyGlob(name string, patterns []string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// DefaultCollectTimeout bounds one collector's Collect call when the registry
// has no other timeout set.
const DefaultCollectTimeout = 20 * time.Second

// Registry holds a set of enabled Collectors.
type Registry struct {
	collectors []Collector
	timeout    time.Duration

	mu   sync.Mutex
	busy map[string]bool // collectors whose last Collect has not returned yet
}

// NewRegistry creates a Registry from the provided collectors.
func NewRegistry(collectors ...Collector) *Registry {
	return &Registry{collectors: collectors, timeout: DefaultCollectTimeout, busy: map[string]bool{}}
}

// WithTimeout sets how long one collector may take before the pass goes on
// without it. Non-positive values keep the default.
func (r *Registry) WithTimeout(d time.Duration) *Registry {
	if d > 0 {
		r.timeout = d
	}
	return r
}

// CollectAll runs all collectors concurrently, each bounded by the registry
// timeout, and returns their points in registration order. Per-collector
// errors are recorded without stopping the pass; partial results are always
// returned.
//
// A collector that overruns is reported as timed out and the pass returns
// without it. Some calls cannot be interrupted (statfs on a hung NFS mount,
// an external tool), so such a collector is not started again until its last
// call has returned; meanwhile it is reported as still running.
func (r *Registry) CollectAll(ctx context.Context) ([]metrics.MetricPoint, map[string]error) {
	type result struct {
		pts []metrics.MetricPoint
		err error
	}
	results := make([]result, len(r.collectors))
	var wg sync.WaitGroup

	for i, c := range r.collectors {
		name := c.Name()
		if !r.start(name) {
			results[i].err = fmt.Errorf("previous collection still running")
			continue
		}
		done := make(chan result, 1)
		cctx, cancel := context.WithTimeout(ctx, r.timeout)
		go func() {
			defer r.finish(name)
			pts, err := c.Collect(cctx)
			done <- result{pts, err}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			select {
			case res := <-done:
				results[i] = res
			case <-cctx.Done():
				results[i].err = fmt.Errorf("timed out after %s", r.timeout)
			}
		}()
	}
	wg.Wait()

	var points []metrics.MetricPoint
	errs := make(map[string]error)
	for i, res := range results {
		if res.err != nil {
			errs[r.collectors[i].Name()] = res.err
			continue
		}
		points = append(points, res.pts...)
	}
	return points, errs
}

func (r *Registry) start(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy[name] {
		return false
	}
	r.busy[name] = true
	return true
}

func (r *Registry) finish(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.busy, name)
}
