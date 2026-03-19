package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// CPUReader abstracts the gopsutil CPU call for testability.
type CPUReader interface {
	PercentWithContext(ctx context.Context, interval time.Duration, percpu bool) ([]float64, error)
}

// CPUCollector collects aggregate CPU usage.
// Note: the first Collect call always returns 0.0 because gopsutil needs two
// samples to compute a delta. This is expected and documented behaviour.
type CPUCollector struct {
	reader CPUReader
}

// NewCPUCollector returns a CPUCollector backed by the real OS.
func NewCPUCollector() *CPUCollector {
	return &CPUCollector{reader: realCPUReader{}}
}

// NewCPUCollectorWithReader returns a CPUCollector with an injected reader (for testing).
func NewCPUCollectorWithReader(r CPUReader) *CPUCollector {
	return &CPUCollector{reader: r}
}

func (c *CPUCollector) Name() string { return "cpu" }

func (c *CPUCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	pcts, err := c.reader.PercentWithContext(ctx, 0, false)
	if err != nil {
		return nil, fmt.Errorf("cpu percent: %w", err)
	}
	if len(pcts) == 0 {
		return nil, fmt.Errorf("cpu percent: empty result")
	}
	return []metrics.MetricPoint{
		{
			Name:  "cpu_usage_percent",
			Help:  "Total CPU usage percentage (0-100)",
			Type:  metrics.Gauge,
			Value: pcts[0],
		},
	}, nil
}
