package collector

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// DiskIOCollector reports per-device I/O from /proc/diskstats: what
// "the disk is slow" looks like (rates, time busy, queue) rather than how
// full it is. Whole disks, RAID (md) and device-mapper volumes are reported;
// partitions, loop and ram devices are not.
type DiskIOCollector struct {
	paths HostPaths
}

// NewDiskIOCollector creates the collector.
func NewDiskIOCollector(paths HostPaths) *DiskIOCollector { return &DiskIOCollector{paths: paths} }

func (c *DiskIOCollector) Name() string { return "diskio" }

const sectorBytes = 512 // /proc/diskstats counts 512-byte sectors whatever the device's size

func (c *DiskIOCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	lines, err := readLines(c.paths.proc("diskstats"))
	if err != nil {
		return nil, fmt.Errorf("diskstats: %w", err)
	}
	var pts []metrics.MetricPoint
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 14 {
			continue
		}
		dev := f[2]
		if !c.wanted(dev) {
			continue
		}
		n := func(i int) float64 { v, _ := strconv.ParseFloat(f[i], 64); return v }
		l := map[string]string{"device": dev}
		pts = append(pts,
			counter("disk_reads_completed_total", "Reads completed", n(3), l),
			counter("disk_writes_completed_total", "Writes completed", n(7), l),
			counter("disk_read_bytes_total", "Bytes read", n(5)*sectorBytes, l),
			counter("disk_written_bytes_total", "Bytes written", n(9)*sectorBytes, l),
			counter("disk_read_time_seconds_total", "Time spent on reads (sum over requests)", n(6)/1000, l),
			counter("disk_write_time_seconds_total", "Time spent on writes (sum over requests)", n(10)/1000, l),
			counter("disk_io_time_seconds_total", "Time the device was busy; its rate is the utilisation", n(12)/1000, l),
			counter("disk_io_time_weighted_seconds_total", "Busy time weighted by queue depth", n(13)/1000, l),
			gauge("disk_io_now", "I/Os in progress", n(11), l),
		)
	}
	return pts, nil
}

// wanted keeps whole devices: a name under /sys/block, except loop/ram/zram
// and optical drives.
func (c *DiskIOCollector) wanted(dev string) bool {
	for _, p := range []string{"loop", "ram", "zram", "sr", "fd"} {
		if strings.HasPrefix(dev, p) {
			return false
		}
	}
	_, err := os.Stat(c.paths.sys("block", dev))
	return err == nil
}
