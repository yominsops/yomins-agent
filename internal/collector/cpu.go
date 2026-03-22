package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// CPUReader abstracts the gopsutil CPU call for testability.
type CPUReader interface {
	PercentWithContext(ctx context.Context, interval time.Duration, percpu bool) ([]float64, error)
}

// CPUTimesStat holds cumulative CPU time counters (seconds since boot).
type CPUTimesStat struct {
	User   float64
	System float64
	Idle   float64
	Iowait float64
}

// CPUTimesReader abstracts the gopsutil cpu.Times call for testability.
// It returns a single aggregate (percpu=false) snapshot.
type CPUTimesReader interface {
	TimesWithContext(ctx context.Context, percpu bool) ([]CPUTimesStat, error)
}

// CPUCollector collects aggregate CPU usage.
// Note: the first Collect call always returns 0.0 because gopsutil needs two
// samples to compute a delta. This is expected and documented behaviour.
// The same applies to cpu_iowait_percent: the metric is absent on the first call.
type CPUCollector struct {
	reader      CPUReader
	timesReader CPUTimesReader // nil when created via NewCPUCollectorWithReader
	mu          sync.Mutex
	prevTimes   *CPUTimesStat
}

// NewCPUCollector returns a CPUCollector backed by the real OS.
func NewCPUCollector() *CPUCollector {
	rr := realCPUReader{}
	return &CPUCollector{reader: rr, timesReader: rr}
}

// NewCPUCollectorWithReader returns a CPUCollector with an injected reader (for testing).
// IOWait is not collected when created this way (timesReader is nil).
func NewCPUCollectorWithReader(r CPUReader) *CPUCollector {
	return &CPUCollector{reader: r}
}

// NewCPUCollectorWithReaders returns a CPUCollector with injected percent and times readers.
// Used in tests that need to exercise the iowait metric.
func NewCPUCollectorWithReaders(r CPUReader, tr CPUTimesReader) *CPUCollector {
	return &CPUCollector{reader: r, timesReader: tr}
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

	pts := []metrics.MetricPoint{
		{
			Name:  "cpu_usage_percent",
			Help:  "Total CPU usage percentage (0-100)",
			Type:  metrics.Gauge,
			Value: pcts[0],
		},
	}

	if c.timesReader != nil {
		if iowait, ok := c.computeIowait(ctx); ok {
			pts = append(pts, metrics.MetricPoint{
				Name:  "cpu_iowait_percent",
				Help:  "CPU time spent waiting for I/O (0-100)",
				Type:  metrics.Gauge,
				Value: iowait,
			})
		}
	}

	return pts, nil
}

// computeIowait fetches current CPU times, computes iowait percentage against the
// previous snapshot, and stores the new snapshot. Returns (0, false) on the first
// call or when the delta is invalid.
func (c *CPUCollector) computeIowait(ctx context.Context) (float64, bool) {
	times, err := c.timesReader.TimesWithContext(ctx, false)
	if err != nil || len(times) == 0 {
		return 0, false
	}
	cur := times[0]

	c.mu.Lock()
	defer c.mu.Unlock()

	prev := c.prevTimes
	c.prevTimes = &cur

	if prev == nil {
		// First call: no delta available yet.
		return 0, false
	}

	totalDelta := (cur.User + cur.System + cur.Idle + cur.Iowait) -
		(prev.User + prev.System + prev.Idle + prev.Iowait)
	if totalDelta <= 0 {
		return 0, false
	}

	iowaitDelta := cur.Iowait - prev.Iowait
	return (iowaitDelta / totalDelta) * 100.0, true
}
