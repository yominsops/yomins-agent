package collector

import (
	"context"
	"fmt"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// PartitionStat holds filesystem partition info.
type PartitionStat struct {
	Mountpoint string
	Fstype     string
	Device     string
}

// DiskUsageStat holds disk usage for a single mountpoint.
type DiskUsageStat struct {
	Total             uint64
	Free              uint64
	Used              uint64
	UsedPercent       float64
	InodesTotal       uint64
	InodesUsed        uint64
	InodesFree        uint64
	InodesUsedPercent float64
}

// DiskReader abstracts gopsutil disk calls.
type DiskReader interface {
	PartitionsWithContext(ctx context.Context, all bool) ([]PartitionStat, error)
	UsageWithContext(ctx context.Context, path string) (*DiskUsageStat, error)
}

// DiskCollector collects per-filesystem disk usage metrics.
type DiskCollector struct {
	reader   DiskReader
	excludes []string
}

// NewDiskCollector returns a DiskCollector backed by the real OS.
func NewDiskCollector() *DiskCollector {
	return &DiskCollector{reader: realDiskReader{}}
}

// NewDiskCollectorWithReader returns a DiskCollector with an injected reader.
func NewDiskCollectorWithReader(r DiskReader) *DiskCollector {
	return &DiskCollector{reader: r}
}

// NewDiskCollectorWithFilters returns a DiskCollector backed by the real OS that
// skips the given mountpoints.
func NewDiskCollectorWithFilters(excludes []string) *DiskCollector {
	return &DiskCollector{reader: realDiskReader{}, excludes: excludes}
}

// NewDiskCollectorWithReaderAndExcludes returns a DiskCollector with an injected
// reader and a mountpoint exclusion list. Intended for use in tests.
func NewDiskCollectorWithReaderAndExcludes(r DiskReader, excludes []string) *DiskCollector {
	return &DiskCollector{reader: r, excludes: excludes}
}

func (c *DiskCollector) Name() string { return "disk" }

func (c *DiskCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	partitions, err := c.reader.PartitionsWithContext(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("disk partitions: %w", err)
	}

	var pts []metrics.MetricPoint
	for _, p := range partitions {
		if isExcluded(p.Mountpoint, c.excludes) {
			continue
		}
		usage, err := c.reader.UsageWithContext(ctx, p.Mountpoint)
		if err != nil {
			// Skip individual partition errors; they may be transient or permission-related.
			continue
		}

		lbls := map[string]string{
			"mountpoint": p.Mountpoint,
			"fstype":     p.Fstype,
			"device":     p.Device,
		}

		pts = append(pts,
			metrics.MetricPoint{Name: "disk_total_bytes", Help: "Total disk space in bytes", Type: metrics.Gauge, Value: float64(usage.Total), Labels: lbls},
			metrics.MetricPoint{Name: "disk_free_bytes", Help: "Free disk space in bytes", Type: metrics.Gauge, Value: float64(usage.Free), Labels: lbls},
			metrics.MetricPoint{Name: "disk_used_bytes", Help: "Used disk space in bytes", Type: metrics.Gauge, Value: float64(usage.Used), Labels: lbls},
			metrics.MetricPoint{Name: "disk_used_percent", Help: "Disk usage percentage (0-100)", Type: metrics.Gauge, Value: usage.UsedPercent, Labels: lbls},
			metrics.MetricPoint{Name: "disk_inodes_total", Help: "Total inodes", Type: metrics.Gauge, Value: float64(usage.InodesTotal), Labels: lbls},
			metrics.MetricPoint{Name: "disk_inodes_used", Help: "Used inodes", Type: metrics.Gauge, Value: float64(usage.InodesUsed), Labels: lbls},
			metrics.MetricPoint{Name: "disk_inodes_free", Help: "Free inodes", Type: metrics.Gauge, Value: float64(usage.InodesFree), Labels: lbls},
			metrics.MetricPoint{Name: "disk_inodes_used_percent", Help: "Inode usage percentage (0-100)", Type: metrics.Gauge, Value: usage.InodesUsedPercent, Labels: lbls},
		)
	}

	return pts, nil
}
