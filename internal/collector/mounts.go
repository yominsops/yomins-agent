package collector

import (
	"context"
	"os"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// MountsCollector reports filesystems mounted read-only. A disk error makes
// ext4/xfs remount read-only and the applications then fail on every write
// while "disk usage" looks fine.
type MountsCollector struct {
	paths HostPaths
}

// NewMountsCollector creates the collector.
func NewMountsCollector(paths HostPaths) *MountsCollector { return &MountsCollector{paths: paths} }

func (c *MountsCollector) Name() string { return "mounts" }

// realFS are the filesystem types holding data; pseudo filesystems, images
// and network mounts are left out.
var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "reiserfs": true, "jfs": true, "vfat": false}

func (c *MountsCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	// PID 1's view: the agent's own mount namespace is read-only by design
	// (systemd ProtectSystem=strict) and would report every filesystem as ro.
	lines, err := readLines(c.paths.proc("1", "mounts"))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var pts []metrics.MetricPoint
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 4 || !realFS[f[2]] || seen[f[1]] {
			continue
		}
		if fi, err := os.Stat(c.paths.root(f[1])); err == nil && !fi.IsDir() {
			continue // a file bind-mounted into a container (/etc/hosts)
		}
		seen[f[1]] = true
		ro := 0.0
		for _, o := range strings.Split(f[3], ",") {
			if o == "ro" {
				ro = 1
			}
		}
		pts = append(pts, gauge("filesystem_readonly", "1 when the filesystem is mounted read-only", ro,
			map[string]string{"mountpoint": f[1], "device": f[0], "fstype": f[2]}))
	}
	return pts, nil
}
