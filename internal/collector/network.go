package collector

import (
	"context"
	"fmt"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// DefaultNetworkIncludePatterns is the built-in include list used when no
// include patterns are specified by the user.
var DefaultNetworkIncludePatterns = []string{"eth*", "ens*", "enp*", "eno*", "wlan*", "wlp*"}

// DefaultNetworkExcludePatterns is the built-in exclude list used in exclude
// mode (no includes) when the user has not supplied a custom exclude list.
var DefaultNetworkExcludePatterns = []string{"lo", "docker*", "veth*", "br-*", "tun*", "wg*"}

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

// InterfaceStateReader returns the set of UP interface names. Used in exclude
// mode to further filter out inactive virtual interfaces.
type InterfaceStateReader interface {
	UpInterfaceNames(ctx context.Context) (map[string]bool, error)
}

// NetworkCollector collects per-interface network I/O counters.
//
// Filtering modes:
//   - Include mode (includes non-empty): only interfaces matching an include
//     glob pattern are reported. UP-state is not checked in this mode.
//   - Exclude mode (includes empty): interfaces matching an exclude pattern
//     are dropped; the remainder are further filtered to UP-only when a
//     stateReader is available.
//
// If neither includes nor excludes are specified, DefaultNetworkIncludePatterns
// is applied (include mode).
type NetworkCollector struct {
	reader      NetworkReader
	stateReader InterfaceStateReader // nil → skip UP-state check
	includes    []string             // glob patterns; non-empty → include mode
	excludes    []string             // glob patterns; used when includes is empty
}

// NewNetworkCollector returns a collector using the built-in default include
// patterns and the real OS state reader.
func NewNetworkCollector() *NetworkCollector {
	r := realNetworkReader{}
	return &NetworkCollector{
		reader:      r,
		stateReader: r,
		includes:    DefaultNetworkIncludePatterns,
	}
}

// NewNetworkCollectorWithReader returns a collector with an injected IO reader
// and the default include patterns. The UP-state check is disabled (no
// stateReader). Intended for unit tests.
func NewNetworkCollectorWithReader(r NetworkReader) *NetworkCollector {
	return &NetworkCollector{
		reader:   r,
		includes: DefaultNetworkIncludePatterns,
	}
}

// NewNetworkCollectorWithFilters returns a collector backed by the real OS with
// explicit include and exclude glob patterns. When includes is non-empty the
// collector operates in include mode; otherwise it uses exclude mode with the
// UP-state check.
func NewNetworkCollectorWithFilters(includes, excludes []string) *NetworkCollector {
	r := realNetworkReader{}
	return &NetworkCollector{
		reader:      r,
		stateReader: r,
		includes:    includes,
		excludes:    excludes,
	}
}

// NewNetworkCollectorWithReaderAndFilters returns a collector with a fully
// injected reader and explicit filter patterns. Intended for unit tests.
func NewNetworkCollectorWithReaderAndFilters(r NetworkReader, includes, excludes []string) *NetworkCollector {
	return &NetworkCollector{
		reader:   r,
		includes: includes,
		excludes: excludes,
	}
}

// NewNetworkCollectorWithReaderAndExcludes is a compatibility shim for existing
// tests. It sets up exclude mode with the given list and no UP-state check.
func NewNetworkCollectorWithReaderAndExcludes(r NetworkReader, excludes []string) *NetworkCollector {
	return NewNetworkCollectorWithReaderAndFilters(r, nil, excludes)
}

func (c *NetworkCollector) Name() string { return "network" }

// shouldInclude reports whether iface should be included in metrics output.
// upNames may be nil, in which case the UP-state check is skipped.
func (c *NetworkCollector) shouldInclude(name string, upNames map[string]bool) bool {
	if len(c.includes) > 0 {
		return matchesAnyGlob(name, c.includes)
	}
	// Exclude mode.
	excl := c.excludes
	if len(excl) == 0 {
		excl = DefaultNetworkExcludePatterns
	}
	if matchesAnyGlob(name, excl) {
		return false
	}
	if upNames != nil {
		return upNames[name]
	}
	return true
}

func (c *NetworkCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	counters, err := c.reader.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("network io counters: %w", err)
	}

	// In exclude mode, fetch UP interface names for physical-interface detection.
	var upNames map[string]bool
	if len(c.includes) == 0 && c.stateReader != nil {
		upNames, _ = c.stateReader.UpInterfaceNames(ctx) // degrade gracefully on error
	}

	var pts []metrics.MetricPoint
	for _, iface := range counters {
		if !c.shouldInclude(iface.Name, upNames) {
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
