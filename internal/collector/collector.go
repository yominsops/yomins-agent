package collector

import (
	"context"

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

// Registry holds a set of enabled Collectors.
type Registry struct {
	collectors []Collector
}

// NewRegistry creates a Registry from the provided collectors.
func NewRegistry(collectors ...Collector) *Registry {
	return &Registry{collectors: collectors}
}

// CollectAll runs all collectors sequentially, accumulates results, and records
// per-collector errors without stopping the overall collection pass.
// Partial results are always returned even when some collectors fail.
func (r *Registry) CollectAll(ctx context.Context) ([]metrics.MetricPoint, map[string]error) {
	var points []metrics.MetricPoint
	errs := make(map[string]error)

	for _, c := range r.collectors {
		pts, err := c.Collect(ctx)
		if err != nil {
			errs[c.Name()] = err
			continue
		}
		points = append(points, pts...)
	}

	return points, errs
}
