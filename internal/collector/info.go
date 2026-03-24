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

// MemoryModuleStat describes a single populated DIMM slot.
type MemoryModuleStat struct {
	SizeMB       int    // e.g. 8192
	Type         string // e.g. "DDR4"
	SpeedMhz     int    // e.g. 2666
	Manufacturer string // e.g. "Samsung"
	Locator      string // slot label e.g. "DIMM_A1"
}

// MemoryInfo holds total system RAM and, when available, per-DIMM module details.
type MemoryInfo struct {
	TotalMB int              // always populated
	Modules []MemoryModuleStat // populated only when dmidecode is available
}

// DiskHardwareStat describes a single physical block device.
type DiskHardwareStat struct {
	Device    string // e.g. "sda", "nvme0n1"
	Model     string // e.g. "Samsung SSD 870 EVO 1TB"
	SizeGB    int    // decimal GB (÷ 10^9)
	Type      string // "ssd", "hdd", "nvme"
	Transport string // "sata", "sas", "nvme", "unknown"
}

// NetworkHardwareStat describes a single physical network interface.
type NetworkHardwareStat struct {
	Interface string // e.g. "eth0"
	SpeedMbps int    // link speed in Mbps; 0 = unknown
	State     string // "up", "down", "unknown"
	Duplex    string // "full", "half", "unknown"
}

// SystemHardwareStat describes the server's vendor and product identity.
type SystemHardwareStat struct {
	Vendor  string // e.g. "Dell Inc."
	Product string // e.g. "PowerEdge R740"
}

// InfoReader abstracts all OS-level reads for InfoCollector.
type InfoReader interface {
	SystemInfoWithContext(ctx context.Context) (*SystemInfoStat, error)
	CPUInfoWithContext(ctx context.Context) (*CPUInfoStat, error)
	PackageUpdateTimesWithContext(ctx context.Context) (*PackageUpdateTimes, error)
	KernelCareInfoWithContext(ctx context.Context) (*KernelCareInfoStat, error)
	MemoryInfoWithContext(ctx context.Context) (*MemoryInfo, error)
	DiskHardwareWithContext(ctx context.Context) ([]DiskHardwareStat, error)
	NetworkHardwareWithContext(ctx context.Context) ([]NetworkHardwareStat, error)
	SystemHardwareWithContext(ctx context.Context) (*SystemHardwareStat, error)
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

	// memory_hardware_info (total) + memory_module_info (per DIMM when dmidecode available)
	memInfo, err := c.reader.MemoryInfoWithContext(ctx)
	if err == nil && memInfo != nil {
		if memInfo.TotalMB > 0 {
			pts = append(pts, metrics.MetricPoint{
				Name:  "memory_hardware_info",
				Help:  "Physical memory total",
				Type:  metrics.Gauge,
				Value: 1,
				Labels: map[string]string{
					"total_mb": strconv.Itoa(memInfo.TotalMB),
				},
			})
		}
		for i, m := range memInfo.Modules {
			pts = append(pts, metrics.MetricPoint{
				Name:  "memory_module_info",
				Help:  "Physical memory module information",
				Type:  metrics.Gauge,
				Value: 1,
				Labels: map[string]string{
					"index":        strconv.Itoa(i),
					"size_mb":      strconv.Itoa(m.SizeMB),
					"type":         m.Type,
					"speed_mhz":    strconv.Itoa(m.SpeedMhz),
					"manufacturer": m.Manufacturer,
					"locator":      m.Locator,
				},
			})
		}
	}

	// disk_hardware_info (one point per physical block device)
	disks, err := c.reader.DiskHardwareWithContext(ctx)
	if err == nil {
		for _, d := range disks {
			pts = append(pts, metrics.MetricPoint{
				Name:  "disk_hardware_info",
				Help:  "Physical disk hardware information",
				Type:  metrics.Gauge,
				Value: 1,
				Labels: map[string]string{
					"device":    d.Device,
					"model":     d.Model,
					"size_gb":   strconv.Itoa(d.SizeGB),
					"type":      d.Type,
					"transport": d.Transport,
				},
			})
		}
	}

	// network_hardware_info (one point per physical NIC)
	nics, err := c.reader.NetworkHardwareWithContext(ctx)
	if err == nil {
		for _, n := range nics {
			pts = append(pts, metrics.MetricPoint{
				Name:  "network_hardware_info",
				Help:  "Physical network interface hardware information",
				Type:  metrics.Gauge,
				Value: 1,
				Labels: map[string]string{
					"interface":  n.Interface,
					"speed_mbps": strconv.Itoa(n.SpeedMbps),
					"state":      n.State,
					"duplex":     n.Duplex,
				},
			})
		}
	}

	// hardware_info (server vendor + product)
	hw, err := c.reader.SystemHardwareWithContext(ctx)
	if err == nil && hw != nil {
		pts = append(pts, metrics.MetricPoint{
			Name:  "hardware_info",
			Help:  "Server hardware identity",
			Type:  metrics.Gauge,
			Value: 1,
			Labels: map[string]string{
				"vendor":  hw.Vendor,
				"product": hw.Product,
			},
		})
	}

	return pts, nil
}
