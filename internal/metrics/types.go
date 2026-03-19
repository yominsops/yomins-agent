package metrics

import "time"

// MetricType distinguishes between monotonically increasing counters and instantaneous gauges.
type MetricType int

const (
	Gauge MetricType = iota
	Counter
)

// MetricPoint represents a single time-series data point from a collector.
// Labels carry additional dimensions beyond the global agent labels injected
// at encode time (e.g. mountpoint, interface name).
type MetricPoint struct {
	Name      string
	Help      string
	Type      MetricType
	Value     float64
	Labels    map[string]string
	Timestamp time.Time
}

// MetricSet is a complete snapshot collected during one agent tick.
// It carries both the points and the agent-level identity fields that
// are injected as labels during encoding.
type MetricSet struct {
	Points      []MetricPoint
	AgentID     string
	Hostname    string
	Version     string
	Source      string
	CollectedAt time.Time
}
