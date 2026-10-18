package collector

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
	"github.com/yominsops/yomins-agent/internal/procfs"
)

// ProcessGroupsCollector reports the processes using the most CPU and
// memory, grouped by name (all php-fpm workers together), so "what is
// eating the server" has an answer in the graphs. Only the top groups are
// sent, which keeps the number of series small.
type ProcessGroupsCollector struct {
	procs procfs.Source
	top   int
	now   func() time.Time

	mu   sync.Mutex
	prev map[int32]procTicks
	at   time.Time
}

type procTicks struct {
	start, cpu uint64
}

// NewProcessGroupsCollector creates the collector reporting the top groups by CPU and by memory.
func NewProcessGroupsCollector(top int) *ProcessGroupsCollector {
	return &ProcessGroupsCollector{procs: procfs.New(), top: top, now: time.Now}
}

func (c *ProcessGroupsCollector) Name() string { return "process_groups" }

type procGroup struct {
	name  string
	cpu   float64 // percent of one core since the last pass
	rss   float64
	count float64
}

func (c *ProcessGroupsCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	procs, err := c.procs.List(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	elapsed := now.Sub(c.at).Seconds()
	first := c.prev == nil
	groups := map[string]*procGroup{}
	next := make(map[int32]procTicks, len(procs))
	for _, p := range procs {
		if p.State == 'Z' {
			continue
		}
		g := groups[p.Name]
		if g == nil {
			g = &procGroup{name: p.Name}
			groups[p.Name] = g
		}
		g.count++
		g.rss += float64(p.RSS)
		if prev, ok := c.prev[p.PID]; ok && prev.start == p.Start && p.CPU >= prev.cpu && elapsed > 0 {
			g.cpu += float64(p.CPU-prev.cpu) / c.procs.ClockTicks() / elapsed * 100
		}
		next[p.PID] = procTicks{start: p.Start, cpu: p.CPU}
	}
	c.prev, c.at = next, now

	list := make([]*procGroup, 0, len(groups))
	for _, g := range groups {
		list = append(list, g)
	}
	pick := map[string]*procGroup{}
	sort.Slice(list, func(i, j int) bool { return list[i].rss > list[j].rss })
	for _, g := range list[:min(c.top, len(list))] {
		pick[g.name] = g
	}
	if !first {
		sort.Slice(list, func(i, j int) bool { return list[i].cpu > list[j].cpu })
		for _, g := range list[:min(c.top, len(list))] {
			pick[g.name] = g
		}
	}
	var pts []metrics.MetricPoint
	for _, g := range pick {
		l := map[string]string{"process": g.name}
		pts = append(pts,
			gauge("process_group_memory_bytes", "Resident memory of the processes with this name", g.rss, l),
			gauge("process_group_count", "Processes with this name", g.count, l))
		if !first {
			pts = append(pts, gauge("process_group_cpu_percent", "CPU of the processes with this name since the last collection, percent of one core", g.cpu, l))
		}
	}
	return pts, nil
}
