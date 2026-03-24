package collector

import (
	"context"
	"strconv"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// SystemInfoStat holds static OS and virtualization identity fields.
type SystemInfoStat struct {
	Distribution        string
	DistributionVersion string
	KernelVersion       string
	Virtualization      string
}

// CPUInfoStat holds CPU hardware description.
type CPUInfoStat struct {
	Model   string
	Cores   int // physical cores
	Threads int // logical threads
}

// PackageUpdateTimes holds Unix timestamps of the last detected kernel and
// general software package updates. A zero value means the data was not available.
type PackageUpdateTimes struct {
	LastKernelUpdate   int64
	LastSoftwareUpdate int64
}

// KernelCareInfoStat holds KernelCare detection results.
// When Installed is false the metric is omitted entirely.
type KernelCareInfoStat struct {
	Installed bool
	Version   string
}

// InfoReader abstracts all OS-level reads for InfoCollector.
type InfoReader interface {
	SystemInfoWithContext(ctx context.Context) (*SystemInfoStat, error)
	CPUInfoWithContext(ctx context.Context) (*CPUInfoStat, error)
	PackageUpdateTimesWithContext(ctx context.Context) (*PackageUpdateTimes, error)
	KernelCareInfoWithContext(ctx context.Context) (*KernelCareInfoStat, error)
}

// InfoConfig carries the subset of agent config relevant to InfoCollector.
type InfoConfig struct {
	DisableKernelCareInfo  bool
	VirtualizationOverride string
}

// InfoCollector collects static system and CPU metadata as info-style metrics.
type InfoCollector struct {
	reader InfoReader
	cfg    InfoConfig
}

// NewInfoCollector returns an InfoCollector backed by the real OS reader.
func NewInfoCollector(cfg InfoConfig) *InfoCollector {
	return &InfoCollector{reader: newRealInfoReader(cfg.VirtualizationOverride), cfg: cfg}
}

// NewInfoCollectorWithReader returns an InfoCollector with an injected reader (for testing).
func NewInfoCollectorWithReader(r InfoReader, cfg InfoConfig) *InfoCollector {
	return &InfoCollector{reader: r, cfg: cfg}
}

func (c *InfoCollector) Name() string { return "info" }

func (c *InfoCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint

	// system_info
	si, err := c.reader.SystemInfoWithContext(ctx)
	if err == nil && si != nil {
		pts = append(pts, metrics.MetricPoint{
			Name:  "system_info",
			Help:  "Static system software information",
			Type:  metrics.Gauge,
			Value: 1,
			Labels: map[string]string{
				"distribution":         si.Distribution,
				"distribution_version": si.DistributionVersion,
				"kernel_version":       si.KernelVersion,
				"virtualization":       si.Virtualization,
			},
		})
	}

	// cpu_info
	ci, err := c.reader.CPUInfoWithContext(ctx)
	if err == nil && ci != nil {
		pts = append(pts, metrics.MetricPoint{
			Name:  "cpu_info",
			Help:  "CPU hardware information",
			Type:  metrics.Gauge,
			Value: 1,
			Labels: map[string]string{
				"model":   ci.Model,
				"cores":   strconv.Itoa(ci.Cores),
				"threads": strconv.Itoa(ci.Threads),
			},
		})
	}

	// package update timestamps
	put, err := c.reader.PackageUpdateTimesWithContext(ctx)
	if err == nil && put != nil {
		if put.LastKernelUpdate > 0 {
			pts = append(pts, metrics.MetricPoint{
				Name:  "system_last_kernel_update_timestamp",
				Help:  "Unix timestamp of last kernel package update",
				Type:  metrics.Gauge,
				Value: float64(put.LastKernelUpdate),
			})
		}
		if put.LastSoftwareUpdate > 0 {
			pts = append(pts, metrics.MetricPoint{
				Name:  "system_last_software_update_timestamp",
				Help:  "Unix timestamp of last software package update",
				Type:  metrics.Gauge,
				Value: float64(put.LastSoftwareUpdate),
			})
		}
	}

	// kernelcare_info
	if !c.cfg.DisableKernelCareInfo {
		kc, err := c.reader.KernelCareInfoWithContext(ctx)
		if err == nil && kc != nil && kc.Installed {
			pts = append(pts, metrics.MetricPoint{
				Name:  "kernelcare_info",
				Help:  "KernelCare installation info (1 if installed)",
				Type:  metrics.Gauge,
				Value: 1,
				Labels: map[string]string{
					"version": kc.Version,
				},
			})
		}
	}

	return pts, nil
}
