package transport

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/events"
	"github.com/yominsops/yomins-agent/internal/metrics"
)

// clock is a settable time source for the session.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestSession() (*Session, *clock) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	s := NewSession()
	s.now = c.now
	return s, c
}

func testMetrics() metrics.MetricSet {
	return metrics.MetricSet{
		AgentID:  "a",
		Hostname: "h",
		Points:   []metrics.MetricPoint{{Name: "up", Type: metrics.Gauge, Value: 1}},
	}
}

func TestSession_PauseOnForbiddenUsesRetryAfter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set(reasonHeader, "service_blocked")
		w.Header().Set("Retry-After", "600")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s, clk := newTestSession()
	tp := NewHTTPTransport(HTTPConfig{Server: srv.URL, Token: "t", Interval: time.Second, Session: s})

	var rej *RejectedError
	err := tp.Push(context.Background(), testMetrics())
	if !errors.As(err, &rej) || rej.Status != 403 || rej.Reason != "service_blocked" || rej.RetryAfter != 10*time.Minute {
		t.Fatalf("Push error = %v (%+v)", err, rej)
	}
	if !errors.Is(tp.Push(context.Background(), testMetrics()), ErrPaused) {
		t.Fatal("second push should be skipped while paused")
	}
	if calls.Load() != 1 {
		t.Errorf("server called %d times, want 1", calls.Load())
	}

	clk.t = clk.t.Add(10*time.Minute + time.Second)
	if s.Paused() {
		t.Error("pause should end after Retry-After")
	}
}

func TestSession_PauseDoublesWithoutRetryAfter(t *testing.T) {
	s, clk := newTestSession()
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute}
	for _, w := range want {
		s.reject(&RejectedError{Status: 401, Reason: "unauthorized"})
		if got := s.until.Sub(clk.t); got != w {
			t.Errorf("pause = %v, want %v", got, w)
		}
	}
	for i := 0; i < 10; i++ {
		s.reject(&RejectedError{Status: 401, Reason: "unauthorized"})
	}
	if got := s.until.Sub(clk.t); got != maxPause {
		t.Errorf("pause = %v, want the %v cap", got, maxPause)
	}
}

func TestSession_SuccessResumes(t *testing.T) {
	s, _ := newTestSession()
	s.reject(&RejectedError{Status: 403, Reason: "x"})
	s.accepted(&http.Response{Header: http.Header{}})
	if s.Paused() || s.pause != 0 {
		t.Error("a successful push must clear the pause and its backoff")
	}
}

func TestRejection_ReasonFromBodyForOlderServers(t *testing.T) {
	resp := &http.Response{StatusCode: 403, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("service is blocked\n"))}
	if r := rejection(resp); r.Reason != "service is blocked" || r.RetryAfter != 0 {
		t.Errorf("rejection = %+v", r)
	}
}

func TestSession_GzipOnlyAfterServerSaysSo(t *testing.T) {
	var encodings []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encodings = append(encodings, r.Header.Get("Content-Encoding"))
		body := io.Reader(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Errorf("bad gzip: %v", err)
				return
			}
			body = zr
		}
		if b, _ := io.ReadAll(body); !strings.Contains(string(b), "big_metric") {
			t.Errorf("body lost its content")
		}
		w.Header().Set(acceptEncodingHeader, "gzip")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ms := testMetrics()
	for i := 0; i < 100; i++ {
		ms.Points = append(ms.Points, metrics.MetricPoint{Name: "big_metric", Type: metrics.Gauge, Value: float64(i),
			Labels: map[string]string{"n": strings.Repeat("x", i)}})
	}
	tp := NewHTTPTransport(HTTPConfig{Server: srv.URL, Token: "t", Interval: time.Second})
	for i := 0; i < 2; i++ {
		if err := tp.Push(context.Background(), ms); err != nil {
			t.Fatal(err)
		}
	}
	if len(encodings) != 2 || encodings[0] != "" || encodings[1] != "gzip" {
		t.Errorf("encodings = %q, want plain then gzip", encodings)
	}
}

func TestEventFlush_KeepsEventsWhilePaused(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	buf := events.NewRingBuffer(100)
	buf.Push(events.Event{ID: "1"})
	buf.Push(events.Event{ID: "2"})
	tp := NewEventHTTPTransport(EventFlushConfig{Server: srv.URL, Token: "t"}, buf)

	if err := tp.flush(context.Background()); !isRejection(err) {
		t.Fatalf("flush error = %v, want a rejection", err)
	}
	if err := tp.flush(context.Background()); err != nil {
		t.Fatalf("paused flush = %v, want nil", err)
	}
	if calls.Load() != 1 {
		t.Errorf("server called %d times, want 1", calls.Load())
	}
	if got := len(buf.Drain()); got != 2 {
		t.Errorf("%d events kept, want 2", got)
	}
}

func TestEventFlush_DropsBatchTheServerRefuses(t *testing.T) {
	var got []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p eventsPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		got = append(got, len(p.Events))
		if len(got) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	buf := events.NewRingBuffer(100)
	for _, id := range []string{"1", "2", "3"} {
		buf.Push(events.Event{ID: id})
	}
	tp := NewEventHTTPTransport(EventFlushConfig{Server: srv.URL, Token: "t", BatchSize: 2}, buf)
	if err := tp.flush(context.Background()); err != nil {
		t.Fatalf("flush = %v", err)
	}
	if len(got) != 2 || got[0] != 2 || got[1] != 1 {
		t.Errorf("batches = %v, want [2 1]", got)
	}
	if n := len(buf.Drain()); n != 0 {
		t.Errorf("%d events re-queued, want 0", n)
	}
}
