package logs

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// lineMetrics turns the lines going through the pipeline into metrics: line
// counts by source and level (an error spike can alert from metrics alone),
// and for web server access logs requests by vhost and status class, a
// response time histogram and bytes sent. Graphs then work from metrics;
// searching logs is for the details.
type lineMetrics struct {
	mu       sync.Mutex
	lines    map[[2]string]float64 // source, level
	requests map[[2]string]float64 // vhost, status class
	bytes    map[string]float64    // vhost
	hist     map[string]*histogram // vhost
}

// maxVhosts bounds the vhost label; the rest are counted as "other".
const maxVhosts = 50

var durationBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type histogram struct {
	counts []float64 // per bucket, cumulative at collection
	sum    float64
	n      float64
}

func newLineMetrics() *lineMetrics {
	return &lineMetrics{lines: map[[2]string]float64{}, requests: map[[2]string]float64{}, bytes: map[string]float64{}, hist: map[string]*histogram{}}
}

func (m *lineMetrics) observe(e Entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	level := e.Level
	if level == "" {
		level = "none"
	}
	m.lines[[2]string{e.Source, level}]++

	status := e.Fields["status"]
	if (e.Source != "nginx" && e.Source != "apache") || len(status) != 3 {
		return
	}
	vhost := e.Fields["vhost"]
	if vhost == "" {
		vhost = vhostFromFile(e.Path)
	}
	if _, known := m.bytes[vhost]; !known && len(m.bytes) >= maxVhosts {
		vhost = "other"
	}
	m.requests[[2]string{vhost, status[:1] + "xx"}]++
	b, _ := strconv.ParseFloat(e.Fields["bytes"], 64)
	m.bytes[vhost] += b
	if d, err := strconv.ParseFloat(e.Fields["request_time"], 64); err == nil {
		h := m.hist[vhost]
		if h == nil {
			h = &histogram{counts: make([]float64, len(durationBuckets))}
			m.hist[vhost] = h
		}
		for i, ub := range durationBuckets {
			if d <= ub {
				h.counts[i]++
			}
		}
		h.sum += d
		h.n++
	}
}

// vhostFromFile names a vhost after its log file: metro.dp.ua.access.log → metro.dp.ua.
func vhostFromFile(path string) string {
	base := filepath.Base(path)
	for _, suf := range []string{".access.log", "-access.log", "_access.log", ".analytics.log", ".log"} {
		if v, ok := strings.CutSuffix(base, suf); ok {
			base = v
			break
		}
	}
	base = strings.TrimPrefix(base, "prom_")
	if base == "" || base == "access" || base == "other_vhosts_access" {
		return "default"
	}
	return base
}

func (m *lineMetrics) points() []metrics.MetricPoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	var pts []metrics.MetricPoint
	for _, k := range sortedPairs(m.lines) {
		pts = append(pts, metrics.MetricPoint{Name: "log_lines_total", Help: "Log lines read, by source and level", Type: metrics.Counter,
			Value: m.lines[k], Labels: map[string]string{"log_source": k[0], "level": k[1]}})
	}
	for _, k := range sortedPairs(m.requests) {
		pts = append(pts, metrics.MetricPoint{Name: "http_requests_total", Help: "Requests in the web server's access logs, by vhost and status class", Type: metrics.Counter,
			Value: m.requests[k], Labels: map[string]string{"vhost": k[0], "status_class": k[1]}})
	}
	vhosts := make([]string, 0, len(m.bytes))
	for v := range m.bytes {
		vhosts = append(vhosts, v)
	}
	sort.Strings(vhosts)
	for _, v := range vhosts {
		pts = append(pts, metrics.MetricPoint{Name: "http_response_bytes_total", Help: "Bytes sent, from the access logs", Type: metrics.Counter, Value: m.bytes[v], Labels: map[string]string{"vhost": v}})
		h := m.hist[v]
		if h == nil {
			continue
		}
		for i, ub := range durationBuckets {
			pts = append(pts, metrics.MetricPoint{Name: "http_request_duration_seconds_bucket", Help: "Request time from the access logs", Type: metrics.Counter,
				Value: h.counts[i], Labels: map[string]string{"vhost": v, "le": strconv.FormatFloat(ub, 'g', -1, 64)}})
		}
		pts = append(pts,
			metrics.MetricPoint{Name: "http_request_duration_seconds_bucket", Help: "Request time from the access logs", Type: metrics.Counter, Value: h.n, Labels: map[string]string{"vhost": v, "le": "+Inf"}},
			metrics.MetricPoint{Name: "http_request_duration_seconds_sum", Help: "Request time from the access logs", Type: metrics.Counter, Value: h.sum, Labels: map[string]string{"vhost": v}},
			metrics.MetricPoint{Name: "http_request_duration_seconds_count", Help: "Request time from the access logs", Type: metrics.Counter, Value: h.n, Labels: map[string]string{"vhost": v}},
		)
	}
	return pts
}

func sortedPairs(m map[[2]string]float64) [][2]string {
	keys := make([][2]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	return keys
}
