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
	Errin       uint64
	Errout      uint64
	Dropin      uint64
	Dropout     uint64
}

// NetworkReader abstracts the gopsutil network I/O call.
type NetworkReader interface {
	IOCountersWithContext(ctx context.Context, pernic bool) ([]IOCountersStat, error)
}

// NetworkCollector collects per-interface network I/O counters.
// Counters are exposed as Prometheus Counter type (monotonically increasing since boot).
// The loopback interface ("lo") is always filtered out unless a custom excludes list
// is provided via NewNetworkCollectorWithFilters.
type NetworkCollector struct {
	reader   NetworkReader
	excludes []string
}

// NewNetworkCollector returns a NetworkCollector backed by the real OS.
// The loopback interface "lo" is excluded by default.
func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{reader: realNetworkReader{}, excludes: []string{"lo"}}
}

// NewNetworkCollectorWithReader returns a NetworkCollector with an injected reader.
// The loopback interface "lo" is excluded by default.
func NewNetworkCollectorWithReader(r NetworkReader) *NetworkCollector {
	return &NetworkCollector{reader: r, excludes: []string{"lo"}}
}

// NewNetworkCollectorWithFilters returns a NetworkCollector backed by the real OS
// that skips the interfaces in excludes. The caller is responsible for including
// "lo" in the list if loopback should be excluded.
func NewNetworkCollectorWithFilters(excludes []string) *NetworkCollector {
	return &NetworkCollector{reader: realNetworkReader{}, excludes: excludes}
}

// NewNetworkCollectorWithReaderAndExcludes returns a NetworkCollector with an
// injected reader and a custom interface exclusion list. Intended for use in tests.
func NewNetworkCollectorWithReaderAndExcludes(r NetworkReader, excludes []string) *NetworkCollector {
	return &NetworkCollector{reader: r, excludes: excludes}
}

func (c *NetworkCollector) Name() string { return "network" }

func (c *NetworkCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	counters, err := c.reader.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("network io counters: %w", err)
	}

	var pts []metrics.MetricPoint
	for _, iface := range counters {
		if isExcluded(iface.Name, c.excludes) {
			continue
		}
		lbls := map[string]string{"interface": iface.Name}
		pts = append(pts,
			metrics.MetricPoint{Name: "network_bytes_sent_total", Help: "Total bytes sent since boot", Type: metrics.Counter, Value: float64(iface.BytesSent), Labels: lbls},
			metrics.MetricPoint{Name: "network_bytes_recv_total", Help: "Total bytes received since boot", Type: metrics.Counter, Value: float64(iface.BytesRecv), Labels: lbls},
			metrics.MetricPoint{Name: "network_packets_sent_total", Help: "Total packets sent since boot", Type: metrics.Counter, Value: float64(iface.PacketsSent), Labels: lbls},
			metrics.MetricPoint{Name: "network_packets_recv_total", Help: "Total packets received since boot", Type: metrics.Counter, Value: float64(iface.PacketsRecv), Labels: lbls},
			metrics.MetricPoint{Name: "network_errors_in_total", Help: "Total inbound network errors since boot", Type: metrics.Counter, Value: float64(iface.Errin), Labels: lbls},
			metrics.MetricPoint{Name: "network_errors_out_total", Help: "Total outbound network errors since boot", Type: metrics.Counter, Value: float64(iface.Errout), Labels: lbls},
			metrics.MetricPoint{Name: "network_drops_in_total", Help: "Total inbound packets dropped since boot", Type: metrics.Counter, Value: float64(iface.Dropin), Labels: lbls},
			metrics.MetricPoint{Name: "network_drops_out_total", Help: "Total outbound packets dropped since boot", Type: metrics.Counter, Value: float64(iface.Dropout), Labels: lbls},
		)
	}

	return pts, nil
}
