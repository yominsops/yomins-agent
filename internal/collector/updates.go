package collector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// UpdatesCollector reports pending package updates (security ones apart)
// and whether a reboot is needed: a patched kernel or library is not in use
// until then. Package managers are slow, so wrap it with Every.
type UpdatesCollector struct {
	paths   HostPaths
	run     runner
	lookup  func(string) (string, error)
	release func() string
}

// NewUpdatesCollector creates the collector.
func NewUpdatesCollector(paths HostPaths) *UpdatesCollector {
	return &UpdatesCollector{paths: paths, run: execRunner, lookup: exec.LookPath, release: kernelRelease}
}

func (c *UpdatesCollector) Name() string { return "updates" }

func (c *UpdatesCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	all, security, ok := c.pending(ctx)
	if ok {
		pts = append(pts,
			gauge("system_updates_pending", "Packages with an update available", float64(all), map[string]string{"kind": "all"}),
			gauge("system_updates_pending", "Packages with an update available", float64(security), map[string]string{"kind": "security"}))
	}
	reboot := 0.0
	if _, err := os.Stat(c.paths.root("run", "reboot-required")); err == nil {
		reboot = 1
	} else if newest := newestKernel(c.paths.root("boot")); newest != "" && c.release() != "" && newest != c.release() {
		reboot = 1
	}
	pts = append(pts, gauge("system_reboot_required", "1 when installed updates (a kernel, core libraries) need a reboot to take effect", reboot, nil))
	return pts, nil
}

// pending counts upgradable packages with apt or dnf, from their caches
// (refreshing them needs root; unattended-upgrades / dnf-automatic do it).
func (c *UpdatesCollector) pending(ctx context.Context) (all, security int, ok bool) {
	if _, err := c.lookup("apt-get"); err == nil {
		out, err := c.run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
		if err != nil {
			return 0, 0, false
		}
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.HasPrefix(line, "Inst ") {
				continue
			}
			all++
			if strings.Contains(line, "-security") || strings.Contains(line, "Debian-Security") {
				security++
			}
		}
		return all, security, true
	}
	if _, err := c.lookup("dnf"); err == nil {
		out, _ := c.run(ctx, "dnf", "-q", "--cacheonly", "check-update") // exit 100 when updates exist
		all = countPackageLines(string(out))
		out, _ = c.run(ctx, "dnf", "-q", "--cacheonly", "updateinfo", "list", "--security")
		security = countPackageLines(string(out))
		return all, security, true
	}
	return 0, 0, false
}

func countPackageLines(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && !strings.HasSuffix(f[0], ":") && !strings.HasPrefix(line, "Obsoleting") {
			n++
		}
	}
	return n
}

// newestKernel returns the release of the most recently installed kernel
// image in /boot ("6.1.0-26-arm64" from vmlinuz-6.1.0-26-arm64).
func newestKernel(boot string) string {
	matches, _ := filepath.Glob(filepath.Join(boot, "vmlinuz-*"))
	type k struct {
		rel string
		mod int64
	}
	var ks []k
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil || strings.Contains(m, "rescue") {
			continue
		}
		ks = append(ks, k{strings.TrimPrefix(filepath.Base(m), "vmlinuz-"), fi.ModTime().UnixNano()})
	}
	if len(ks) == 0 {
		return ""
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].mod > ks[j].mod })
	return ks[0].rel
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
