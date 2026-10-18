package logs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestStats_Collect(t *testing.T) {
	s := NewStats()
	s.Watch(func() int { return 3 })
	s.shipped([]Entry{{Source: "nginx"}, {Source: "nginx"}, {Source: "syslog"}}, 120)
	s.droppedN("refused", 2)
	s.retry()
	pts, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Name+"/"+p.Labels["log_source"]+p.Labels["reason"]] = p.Value
	}
	want := map[string]float64{
		"agent_logs_lines_total/nginx": 2, "agent_logs_lines_total/syslog": 1, "agent_logs_dropped_total/refused": 2,
		"agent_logs_bytes_total/": 120, "agent_logs_retries_total/": 1, "agent_logs_files_watched/": 3,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if _, ok := got["agent_logs_last_delivery_timestamp/"]; !ok {
		t.Error("last delivery timestamp missing")
	}
}

func TestPositions_SaveLoadAndCorruptFile(t *testing.T) {
	dir := t.TempDir()
	p := LoadPositions(dir)
	p.SetFile("/var/log/a", Position{Inode: 7, Offset: 42})
	p.SetJournalCursor("c1")
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	q := LoadPositions(dir)
	if pos, ok := q.File("/var/log/a"); !ok || pos.Offset != 42 || q.JournalCursor() != "c1" {
		t.Errorf("loaded %+v %q", pos, q.JournalCursor())
	}
	if err := os.WriteFile(filepath.Join(dir, "log_positions.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := LoadPositions(dir); len(r.Files) != 0 || r.JournalCursor() != "" {
		t.Error("a corrupt file must start empty")
	}
}

func TestLineMetrics(t *testing.T) {
	s := NewStats()
	for _, e := range []Entry{
		{Source: "nginx", Level: LevelInfo, Path: "/var/log/nginx/metro.dp.ua.access.log", Fields: map[string]string{"status": "200", "bytes": "100", "request_time": "0.07"}},
		{Source: "nginx", Level: LevelError, Path: "/var/log/nginx/metro.dp.ua.access.log", Fields: map[string]string{"status": "502", "bytes": "10", "request_time": "3"}},
		{Source: "nginx", Fields: map[string]string{"status": "200", "vhost": "api.example"}},
		{Source: "syslog", Level: LevelError},
	} {
		s.observe(e)
	}
	pts, _ := s.Collect(context.Background())
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Name+"|"+p.Labels["vhost"]+"|"+p.Labels["status_class"]+"|"+p.Labels["le"]+"|"+p.Labels["log_source"]+"|"+p.Labels["level"]] = p.Value
	}
	want := map[string]float64{
		"http_requests_total|metro.dp.ua|2xx|||":                  1,
		"http_requests_total|metro.dp.ua|5xx|||":                  1,
		"http_requests_total|api.example|2xx|||":                  1,
		"http_response_bytes_total|metro.dp.ua||||":               110,
		"http_request_duration_seconds_bucket|metro.dp.ua||0.1||": 1,
		"http_request_duration_seconds_bucket|metro.dp.ua||5||":   2,
		"http_request_duration_seconds_count|metro.dp.ua||||":     2,
		"log_lines_total||||syslog|error":                         1,
		"log_lines_total||||nginx|none":                           1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestVhostFromFile(t *testing.T) {
	for in, want := range map[string]string{
		"/var/log/nginx/metro.dp.ua.access.log": "metro.dp.ua", "/var/log/nginx/access.log": "default",
		"/var/log/nginx/prom_shop.example.access.log": "shop.example", "/var/log/apache2/site-access.log": "site",
	} {
		if got := vhostFromFile(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}
