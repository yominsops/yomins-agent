package collector

import (
	"context"
	"strconv"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
	"github.com/yominsops/yomins-agent/internal/procfs"
)

// KernelCollector reports what the basic CPU/memory metrics leave out:
// memory by kind, paging and OOM kills, process states (zombies, tasks
// stuck in I/O), forks, context switches, open files and the connection
// tracking table — each a classic cause of an outage.
type KernelCollector struct {
	paths HostPaths
	procs procfs.Source
}

// NewKernelCollector creates the collector.
func NewKernelCollector(paths HostPaths) *KernelCollector {
	return &KernelCollector{paths: paths, procs: procfs.New()}
}

func (c *KernelCollector) Name() string { return "kernel" }

var meminfoFields = map[string][2]string{
	"Cached":       {"memory_cached_bytes", "Page cache"},
	"Buffers":      {"memory_buffers_bytes", "Block device buffers"},
	"Dirty":        {"memory_dirty_bytes", "Memory waiting to be written to disk"},
	"Writeback":    {"memory_writeback_bytes", "Memory being written to disk"},
	"Shmem":        {"memory_shared_bytes", "Shared memory (tmpfs included)"},
	"SReclaimable": {"memory_slab_reclaimable_bytes", "Kernel slab that can be reclaimed"},
	"SUnreclaim":   {"memory_slab_unreclaimable_bytes", "Kernel slab that cannot be reclaimed"},
	"Committed_AS": {"memory_committed_bytes", "Memory promised to processes"},
	"CommitLimit":  {"memory_commit_limit_bytes", "Commit limit"},
}

var vmstatFields = map[string][2]string{
	"pgmajfault": {"memory_major_page_faults_total", "Page faults that had to read from disk"},
	"pswpin":     {"memory_swap_in_pages_total", "Pages swapped in"},
	"pswpout":    {"memory_swap_out_pages_total", "Pages swapped out"},
	"oom_kill":   {"memory_oom_kills_total", "Processes killed by the OOM killer"},
}

func (c *KernelCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint

	if lines, err := readLines(c.paths.proc("meminfo")); err == nil {
		for _, line := range lines {
			k, rest, ok := strings.Cut(line, ":")
			m, known := meminfoFields[k]
			if !ok || !known {
				continue
			}
			f := strings.Fields(rest)
			if len(f) == 0 {
				continue
			}
			v, _ := strconv.ParseFloat(f[0], 64)
			if len(f) > 1 && f[1] == "kB" {
				v *= 1024
			}
			pts = append(pts, gauge(m[0], m[1], v, nil))
		}
	}

	if lines, err := readLines(c.paths.proc("vmstat")); err == nil {
		for _, line := range lines {
			f := strings.Fields(line)
			if len(f) != 2 {
				continue
			}
			if m, ok := vmstatFields[f[0]]; ok {
				v, _ := strconv.ParseFloat(f[1], 64)
				pts = append(pts, counter(m[0], m[1], v, nil))
			}
		}
	}

	if lines, err := readLines(c.paths.proc("stat")); err == nil {
		for _, line := range lines {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseFloat(f[1], 64)
			switch f[0] {
			case "ctxt":
				pts = append(pts, counter("system_context_switches_total", "Context switches", v, nil))
			case "intr":
				pts = append(pts, counter("system_interrupts_total", "Interrupts", v, nil))
			case "processes":
				pts = append(pts, counter("system_forks_total", "Processes and threads created", v, nil))
			}
		}
	}

	// Processes by state from the same cheap /proc pass the process events use.
	if procs, err := c.procs.List(ctx); err == nil {
		states := map[string]float64{"running": 0, "sleeping": 0, "blocked": 0, "zombie": 0, "other": 0}
		for _, p := range procs {
			switch p.State {
			case 'R':
				states["running"]++
			case 'S', 'I':
				states["sleeping"]++
			case 'D':
				states["blocked"]++
			case 'Z':
				states["zombie"]++
			default:
				states["other"]++
			}
		}
		for st, n := range states {
			pts = append(pts, gauge("system_processes", "Processes by state (blocked: waiting on I/O, uninterruptible)", n, map[string]string{"state": st}))
		}
	}

	// Open files: allocated, unused, max.
	if b, err := readLines(c.paths.proc("sys", "fs", "file-nr")); err == nil && len(b) > 0 {
		f := strings.Fields(b[0])
		if len(f) == 3 {
			alloc, _ := strconv.ParseFloat(f[0], 64)
			max, _ := strconv.ParseFloat(f[2], 64)
			pts = append(pts,
				gauge("system_open_files", "File handles allocated", alloc, nil),
				gauge("system_open_files_limit", "File handle limit (fs.file-max)", max, nil))
		}
	}

	// Connection tracking: when the table is full the kernel drops packets.
	if n, ok := readUint(c.paths.proc("sys", "net", "netfilter", "nf_conntrack_count")); ok {
		pts = append(pts, gauge("network_conntrack_entries", "Tracked connections", float64(n), nil))
		if max, ok := readUint(c.paths.proc("sys", "net", "netfilter", "nf_conntrack_max")); ok {
			pts = append(pts, gauge("network_conntrack_limit", "Connection tracking table size", float64(max), nil))
		}
	}
	return pts, nil
}
