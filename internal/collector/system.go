package collector

import (
	"context"
	"fmt"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// LoadAvgStat holds load average values.
type LoadAvgStat struct {
	Load1  float64
	Load5  float64
	Load15 float64
}

// SystemReader abstracts gopsutil host and load calls.
type SystemReader interface {
	UptimeWithContext(ctx context.Context) (uint64, error)
	LoadAvgWithContext(ctx context.Context) (*LoadAvgStat, error)
}

// SystemCollector collects system-level metrics: uptime and load averages.
type SystemCollector struct {
	reader SystemReader
}

// NewSystemCollector returns a SystemCollector backed by the real OS.
func NewSystemCollector() *SystemCollector {
	return &SystemCollector{reader: realSystemReader{}}
}

// NewSystemCollectorWithReader returns a SystemCollector with an injected reader.
func NewSystemCollectorWithReader(r SystemReader) *SystemCollector {
	return &SystemCollector{reader: r}
}

func (c *SystemCollector) Name() string { return "system" }

func (c *SystemCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	uptime, err := c.reader.UptimeWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("uptime: %w", err)
	}

	load, err := c.reader.LoadAvgWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("load average: %w", err)
	}

	return []metrics.MetricPoint{
		{
			Name:  "system_uptime_seconds",
			Help:  "System uptime in seconds",
			Type:  metrics.Gauge,
			Value: float64(uptime),
		},
		{
			Name:   "system_load_average",
			Help:   "System load average",
			Type:   metrics.Gauge,
			Value:  load.Load1,
			Labels: map[string]string{"period": "1m"},
		},
		{
			Name:   "system_load_average",
			Help:   "System load average",
			Type:   metrics.Gauge,
			Value:  load.Load5,
			Labels: map[string]string{"period": "5m"},
		},
		{
			Name:   "system_load_average",
			Help:   "System load average",
			Type:   metrics.Gauge,
			Value:  load.Load15,
			Labels: map[string]string{"period": "15m"},
		},
	}, nil
}
