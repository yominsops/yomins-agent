package collector

import (
	"context"
	"strconv"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// PressureCollector reports Linux pressure stall information (PSI, kernel
// 4.20+): the share of time tasks waited for CPU, memory or I/O. It answers
// "why is it slow" better than utilisation: a host can be at 60% CPU and
// stalling. Hosts without PSI report nothing.
type PressureCollector struct {
	paths HostPaths
}

// NewPressureCollector creates the collector.
func NewPressureCollector(paths HostPaths) *PressureCollector { return &PressureCollector{paths: paths} }

func (c *PressureCollector) Name() string { return "pressure" }

func (c *PressureCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	for _, res := range []string{"cpu", "memory", "io"} {
		lines, err := readLines(c.paths.proc("pressure", res))
		if err != nil {
			continue
		}
		for _, line := range lines {
			kind, rest, ok := strings.Cut(line, " ")
			if !ok || (kind != "some" && kind != "full") {
				continue
			}
			l := map[string]string{"resource": res, "kind": kind}
			for _, kv := range strings.Fields(rest) {
				k, v, _ := strings.Cut(kv, "=")
				f, err := strconv.ParseFloat(v, 64)
				if err != nil {
					continue
				}
				switch k {
				case "total":
					pts = append(pts, counter("pressure_stalled_seconds_total", "Time tasks were stalled on the resource (some: at least one task, full: all)", f/1e6, l))
				case "avg60":
					pts = append(pts, gauge("pressure_stalled_percent", "Share of the last minute tasks were stalled, 0–100", f, l))
				}
			}
		}
	}
	return pts, nil
}
