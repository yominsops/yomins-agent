package logs

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/transport"
)

type logServer struct {
	mu     sync.Mutex
	lines  []map[string]string
	status []int // replies in order; 204 once exhausted
	calls  atomic.Int32
	hdr    http.Header
}

func (s *logServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := int(s.calls.Add(1)) - 1
	s.hdr = r.Header.Clone()
	if n < len(s.status) && s.status[n] != 204 {
		w.WriteHeader(s.status[n])
		return
	}
	body := io.Reader(r.Body)
	if r.Header.Get("Content-Encoding") == "gzip" {
		body, _ = gzip.NewReader(r.Body)
	}
	sc := bufio.NewScanner(body)
	for sc.Scan() {
		var m map[string]string
		_ = json.Unmarshal(sc.Bytes(), &m)
		s.lines = append(s.lines, m)
	}
	w.WriteHeader(http.StatusNoContent)
}

func shipAll(t *testing.T, srv *logServer, entries []Entry) *Stats {
	t.Helper()
	hs := httptest.NewServer(srv)
	defer hs.Close()
	r, _ := NewRedactor(nil)
	stats := NewStats()
	sh := NewShipper(ShipperConfig{MaxBatchLines: 2, FlushEvery: 10 * time.Millisecond, Hostname: "web-1", AgentID: "a1"},
		transport.NewPoster(hs.URL, "tok", false, nil), r, stats)
	sh.sleep = func(ctx context.Context, d time.Duration) bool { return ctx.Err() == nil }

	var acked atomic.Int32
	in := make(chan Entry, len(entries))
	for _, e := range entries {
		e.ack = func() { acked.Add(1) }
		in <- e
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sh.Run(ctx, in); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for int(acked.Load()) < len(entries) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if int(acked.Load()) != len(entries) {
		t.Fatalf("acked %d of %d", acked.Load(), len(entries))
	}
	return stats
}

func TestShipper_DeliversRedactedLinesInBatches(t *testing.T) {
	srv := &logServer{}
	ts := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	shipAll(t, srv, []Entry{
		{Time: ts, Msg: "login password=hunter2", Source: "app", Level: LevelWarn, Fields: map[string]string{"status": "200", "project_id": "forged"}},
		{Msg: "two", Source: "app"},
		{Msg: "three", Source: "nginx", Path: "/var/log/nginx/a.log"},
	})
	if srv.calls.Load() != 2 {
		t.Errorf("calls = %d, want 2 (batches of 2)", srv.calls.Load())
	}
	first := srv.lines[0]
	if first["_msg"] != "login password=***" || first["level"] != "warn" || first["status"] != "200" || first["_time"] != "2026-10-18T10:00:00Z" {
		t.Errorf("line = %v", first)
	}
	if _, ok := first["project_id"]; ok {
		t.Error("a parser field must not set project_id")
	}
	if srv.lines[1]["_time"] == "" || srv.lines[2]["path"] != "/var/log/nginx/a.log" {
		t.Errorf("lines = %v", srv.lines)
	}
	if srv.hdr.Get("X-Yomins-Hostname") != "web-1" || srv.hdr.Get("Content-Type") != ContentType {
		t.Errorf("headers = %v", srv.hdr)
	}
}

func TestShipper_RetriesUntilDelivered(t *testing.T) {
	srv := &logServer{status: []int{503, 429, 204}}
	stats := shipAll(t, srv, []Entry{{Msg: "kept", Source: "app"}})
	if len(srv.lines) != 1 || srv.lines[0]["_msg"] != "kept" {
		t.Errorf("lines = %v", srv.lines)
	}
	if stats.retries != 2 {
		t.Errorf("retries = %v, want 2", stats.retries)
	}
}

func TestShipper_DropsRefusedBatch(t *testing.T) {
	srv := &logServer{status: []int{400}}
	stats := shipAll(t, srv, []Entry{{Msg: "bad", Source: "app"}, {Msg: "bad too", Source: "app"}, {Msg: "fine", Source: "app"}})
	if stats.drops["refused"] != 2 || len(srv.lines) != 1 {
		t.Errorf("drops = %v, lines = %v", stats.drops, srv.lines)
	}
}
