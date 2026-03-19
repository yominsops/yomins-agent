package collector

import (
	"context"
	"fmt"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// IOCountersStat holds network interface statistics.
type IOCountersStat struct {
	Name        string
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
}

// NetworkReader abstracts the gopsutil network I/O call.
type NetworkReader interface {
	IOCountersWithContext(ctx context.Context, pernic bool) ([]IOCountersStat, error)
}

// NetworkCollector collects per-interface network I/O counters.
// Counters are exposed as Prometheus Counter type (monotonically increasing since boot).
// The loopback interface ("lo") is filtered out.
type NetworkCollector struct {
	reader NetworkReader
}

// NewNetworkCollector returns a NetworkCollector backed by the real OS.
func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{reader: realNetworkReader{}}
}

// NewNetworkCollectorWithReader returns a NetworkCollector with an injected reader.
func NewNetworkCollectorWithReader(r NetworkReader) *NetworkCollector {
	return &NetworkCollector{reader: r}
}

func (c *NetworkCollector) Name() string { return "network" }

func (c *NetworkCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	counters, err := c.reader.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("network io counters: %w", err)
	}

	var pts []metrics.MetricPoint
	for _, iface := range counters {
		if iface.Name == "lo" {
			continue
		}
		lbls := map[string]string{"interface": iface.Name}
		pts = append(pts,
			metrics.MetricPoint{Name: "network_bytes_sent_total", Help: "Total bytes sent since boot", Type: metrics.Counter, Value: float64(iface.BytesSent), Labels: lbls},
			metrics.MetricPoint{Name: "network_bytes_recv_total", Help: "Total bytes received since boot", Type: metrics.Counter, Value: float64(iface.BytesRecv), Labels: lbls},
			metrics.MetricPoint{Name: "network_packets_sent_total", Help: "Total packets sent since boot", Type: metrics.Counter, Value: float64(iface.PacketsSent), Labels: lbls},
			metrics.MetricPoint{Name: "network_packets_recv_total", Help: "Total packets received since boot", Type: metrics.Counter, Value: float64(iface.PacketsRecv), Labels: lbls},
		)
	}

	return pts, nil
}
