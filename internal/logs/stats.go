package logs

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// Stats counts what the log pipeline did, reported with the agent's metrics.
type Stats struct {
	mu       sync.Mutex
	lines    map[string]float64 // by source
	bytes    float64
	drops    map[string]float64 // by reason
	retries  float64
	lastShip time.Time
	watchers []func() int
	derived  *lineMetrics
}

// NewStats returns empty counters.
func NewStats() *Stats {
	return &Stats{lines: map[string]float64{}, drops: map[string]float64{}, derived: newLineMetrics()}
}

// Watch registers a function reporting how many files are followed.
func (s *Stats) Watch(f func() int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.watchers = append(s.watchers, f)
}

func (s *Stats) shipped(batch []Entry, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range batch {
		s.lines[e.Source]++
	}
	s.bytes += float64(n)
	s.lastShip = time.Now()
}

// observe feeds a line read by a source into the derived metrics.
func (s *Stats) observe(e Entry) { s.derived.observe(e) }

func (s *Stats) dropped(reason string) { s.droppedN(reason, 1) }

func (s *Stats) droppedN(reason string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drops[reason] += float64(n)
}

func (s *Stats) retry() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retries++
}

// Name implements collector.Collector.
func (s *Stats) Name() string { return "logs" }

// Collect implements collector.Collector.
func (s *Stats) Collect(context.Context) ([]metrics.MetricPoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pts []metrics.MetricPoint
	for _, src := range sortedKeys(s.lines) {
		pts = append(pts, metrics.MetricPoint{Name: "agent_logs_lines_total", Help: "Log lines delivered, by source", Type: metrics.Counter,
			Value: s.lines[src], Labels: map[string]string{"log_source": src}})
	}
	for _, r := range sortedKeys(s.drops) {
		pts = append(pts, metrics.MetricPoint{Name: "agent_logs_dropped_total", Help: "Log lines dropped, by reason", Type: metrics.Counter,
			Value: s.drops[r], Labels: map[string]string{"reason": r}})
	}
	pts = append(pts,
		metrics.MetricPoint{Name: "agent_logs_bytes_total", Help: "Bytes of log lines delivered (before compression)", Type: metrics.Counter, Value: s.bytes},
		metrics.MetricPoint{Name: "agent_logs_retries_total", Help: "Log batch delivery attempts that failed", Type: metrics.Counter, Value: s.retries},
	)
	if !s.lastShip.IsZero() {
		pts = append(pts, metrics.MetricPoint{Name: "agent_logs_last_delivery_timestamp", Help: "Unix time of the last delivered log batch", Type: metrics.Gauge,
			Value: float64(s.lastShip.Unix())})
	}
	watched := 0
	for _, f := range s.watchers {
		watched += f()
	}
	pts = append(pts, s.derived.points()...)
	pts = append(pts, metrics.MetricPoint{Name: "agent_logs_files_watched", Help: "Log files followed now", Type: metrics.Gauge, Value: float64(watched)})
	return pts, nil
}

func sortedKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
