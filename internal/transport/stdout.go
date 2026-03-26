package transport

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// StdoutTransport implements Transport by pretty-printing each MetricSet to
// stdout instead of sending it over HTTP. Intended for --dry-run mode.
type StdoutTransport struct {
	tick atomic.Uint64
}

// NewStdoutTransport returns a StdoutTransport ready for use.
func NewStdoutTransport() *StdoutTransport {
	return &StdoutTransport{}
}

// Push prints the MetricSet to stdout in a human-readable grouped format.
func (t *StdoutTransport) Push(_ context.Context, ms metrics.MetricSet) error {
	n := t.tick.Add(1)
	ts := ms.CollectedAt
	if ts.IsZero() {
		ts = time.Now()
	}

	fmt.Printf("\n=== [%s] Tick #%d — hostname: %s ===\n",
		ts.Format("2006-01-02 15:04:05"), n, ms.Hostname)

	// Group points by the first "_"-delimited word of the metric name.
	groups := make(map[string][]metrics.MetricPoint)
	for _, p := range ms.Points {
		prefix := strings.SplitN(p.Name, "_", 2)[0]
		groups[prefix] = append(groups[prefix], p)
	}

	// Sort group names.
	groupNames := make([]string, 0, len(groups))
	for g := range groups {
		groupNames = append(groupNames, g)
	}
	sort.Strings(groupNames)

	for _, g := range groupNames {
		pts := groups[g]

		// Sort points within the group: by name, then by label string.
		sort.Slice(pts, func(i, j int) bool {
			if pts[i].Name != pts[j].Name {
				return pts[i].Name < pts[j].Name
			}
			return labelString(pts[i].Labels) < labelString(pts[j].Labels)
		})

		fmt.Printf("\n[%s]\n", g)
		for _, p := range pts {
			key := p.Name
			if len(p.Labels) > 0 {
				key += "{" + labelString(p.Labels) + "}"
			}
			fmt.Printf("  %-60s %20g\n", key, p.Value)
		}
	}

	fmt.Println("\n---")
	return nil
}

// labelString formats a label map as "key=val,key=val" with sorted keys.
func labelString(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ",")
}
