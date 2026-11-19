package collector

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// CloudLinuxCollector reports CloudLinux OS state that matters to a shared
// hosting server: whether LVE (per-account resource limits) is on, how many
// accounts there are, how often they hit a limit (an account at its entry
// process or memory limit serves 508 and 503 errors), and CageFS.
//
// It reads only files: /etc/sysconfig/lve, /proc/lve/list and
// /etc/cagefs. /proc/lve/list is parsed by its header, whose columns differ
// between LVE versions; the fault counters are the columns named f<LIMIT>
// (fEP, fMEM, fPMEM, fNPROC, fIO, fIOPS). Elsewhere it reports nothing.
type CloudLinuxCollector struct {
	paths HostPaths

	mu   sync.Mutex
	prev map[string]map[string]float64 // LVE id → fault column → value
}

// NewCloudLinuxCollector creates the collector.
func NewCloudLinuxCollector(paths HostPaths) *CloudLinuxCollector {
	return &CloudLinuxCollector{paths: paths}
}

func (c *CloudLinuxCollector) Name() string { return "cloudlinux" }

func (c *CloudLinuxCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	if lines, err := readLines(c.paths.root("etc", "sysconfig", "lve")); err == nil {
		enabled := true // the kernel default when the variable is absent
		for _, l := range lines {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "LVE_ENABLE="); ok {
				enabled = strings.EqualFold(strings.Trim(v, `"' `), "yes")
			}
		}
		pts = append(pts, gauge("cloudlinux_lve_enabled", "1 when LVE limits accounts' CPU, memory, I/O and processes (LVE_ENABLE in /etc/sysconfig/lve)", b2f(enabled), nil))
	}
	if lines, err := readLines(c.paths.proc("lve", "list")); err == nil {
		pts = append(pts, c.lveList(lines)...)
	}
	pts = append(pts, c.cagefs()...)
	return pts, nil
}

func (c *CloudLinuxCollector) lveList(lines []string) []metrics.MetricPoint {
	if len(lines) == 0 {
		return nil
	}
	header := strings.Fields(lines[0])
	if len(header) == 0 {
		return nil
	}
	// "4:LVE EP lCPU ...": a format version glued to the first column.
	if _, name, ok := strings.Cut(header[0], ":"); ok {
		header[0] = name
	}
	if !strings.EqualFold(header[0], "LVE") {
		return nil
	}
	col := map[string]int{}
	var faults []string
	for i, h := range header {
		col[h] = i
		if len(h) > 1 && h[0] == 'f' && strings.ToUpper(h[1:]) == h[1:] {
			faults = append(faults, h)
		}
	}
	sort.Strings(faults)

	accounts := 0
	sums := map[string]float64{}
	usage := map[string]float64{}
	cur := map[string]map[string]float64{}
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) != len(header) {
			continue
		}
		id := f[0]
		if id == "0" { // the default limits, not an account
			continue
		}
		accounts++
		cur[id] = map[string]float64{}
		for _, h := range faults {
			if v, err := strconv.ParseFloat(f[col[h]], 64); err == nil {
				sums[h] += v
				cur[id][h] = v
			}
		}
		for _, h := range []string{"EP", "NPROC"} {
			if i, ok := col[h]; ok {
				if v, err := strconv.ParseFloat(f[i], 64); err == nil {
					usage[h] += v
				}
			}
		}
	}

	pts := []metrics.MetricPoint{gauge("cloudlinux_lve_accounts", "Accounts with their own LVE (resource limits)", float64(accounts), nil)}
	for _, h := range faults {
		pts = append(pts, counter("cloudlinux_lve_faults_total", "Times accounts hit an LVE limit, by limit (ep: entry processes, 508 errors; mem/pmem: memory, 503 errors; nproc: processes; io/iops: disk), all accounts together", sums[h], map[string]string{"limit": strings.ToLower(h[1:])}))
	}
	if v, ok := usage["EP"]; ok {
		pts = append(pts, gauge("cloudlinux_lve_entry_processes", "Entry processes (concurrent PHP/CGI requests) of all accounts", v, nil))
	}
	if v, ok := usage["NPROC"]; ok {
		pts = append(pts, gauge("cloudlinux_lve_processes", "Processes of all accounts", v, nil))
	}

	// Accounts that hit a limit since the last collection: on a busy shared
	// server the fault totals always grow, this says how many sites suffer.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prev != nil {
		hit := map[string]int{}
		for id, now := range cur {
			before, ok := c.prev[id]
			if !ok {
				continue
			}
			for h, v := range now {
				if v > before[h] {
					hit[h]++
				}
			}
		}
		for _, h := range faults {
			pts = append(pts, gauge("cloudlinux_lve_accounts_at_limit", "Accounts that hit this LVE limit since the previous collection", float64(hit[h]), map[string]string{"limit": strings.ToLower(h[1:])}))
		}
	}
	c.prev = cur
	return pts
}

// cagefs reports whether CageFS (each account in its own view of the
// filesystem) is installed, and the accounts listed as exceptions: in
// "Enable All" mode /etc/cagefs/users.disabled holds the accounts left out,
// in "Disable All" mode /etc/cagefs/users.enabled holds the only ones in.
func (c *CloudLinuxCollector) cagefs() []metrics.MetricPoint {
	if fi, err := os.Stat(c.paths.root("usr", "share", "cagefs-skeleton")); err != nil || !fi.IsDir() {
		if _, err := os.Stat(c.paths.root("etc", "cagefs")); err != nil {
			return nil
		}
		return []metrics.MetricPoint{gauge("cloudlinux_cagefs_initialized", "1 when the CageFS skeleton exists (cagefsctl --init has run)", 0, nil)}
	}
	pts := []metrics.MetricPoint{gauge("cloudlinux_cagefs_initialized", "1 when the CageFS skeleton exists (cagefsctl --init has run)", 1, nil)}
	for _, list := range []string{"enabled", "disabled"} {
		dir := c.paths.root("etc", "cagefs", "users."+list)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		n := 0
		_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				n++
			}
			return nil
		})
		pts = append(pts, gauge("cloudlinux_cagefs_listed_users", "Accounts in /etc/cagefs/users.<list>: the exceptions to the CageFS mode (users.disabled in Enable All, users.enabled in Disable All)", float64(n), map[string]string{"list": list}))
	}
	return pts
}
