package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/events"
	"github.com/yominsops/yomins-agent/internal/transport"
)

func makeEvent(id string) events.Event {
	return events.Event{
		ID:        id,
		Timestamp: time.Now(),
		Type:      events.EventAuthLoginSuccess,
		Category:  events.CategoryAccessEvent,
		Severity:  events.SeverityInfo,
		Host:      events.HostInfo{Hostname: "test-host"},
		Agent:     events.AgentInfo{Name: "yomins-agent", Version: "0.1.0"},
	}
}


func TestEventHTTPTransport_FlushEmptyBuffer(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	buf := events.NewRingBuffer(100)
	tp := transport.NewEventHTTPTransport(transport.EventFlushConfig{
		Server:        srv.URL,
		Token:         "tok",
		FlushInterval: time.Hour, // won't tick during test
	}, buf)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	tp.Run(ctx) //nolint:errcheck

	if atomic.LoadInt32(&calls) != 0 {
		t.Errorf("expected 0 HTTP calls for empty buffer, got %d", calls)
	}
}

func TestEventHTTPTransport_BatchSplitting(t *testing.T) {
	var batches []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Events []events.Event `json:"events"`
		}
		json.NewDecoder(r.Body).Decode(&payload) //nolint:errcheck
		batches = append(batches, len(payload.Events))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	buf := events.NewRingBuffer(1000)
	for i := 0; i < 5; i++ {
		buf.Push(makeEvent(string(rune('a' + i))))
	}

	tp := transport.NewEventHTTPTransport(transport.EventFlushConfig{
		Server:        srv.URL,
		Token:         "tok",
		FlushInterval: time.Hour,
		BatchSize:     2,
	}, buf)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	tp.Run(ctx) //nolint:errcheck

	// 5 events with batch size 2 → batches of [2, 2, 1]
	total := 0
	for _, n := range batches {
		total += n
	}
	if total != 5 {
		t.Errorf("total events sent = %d, want 5 (batches: %v)", total, batches)
	}
	if len(batches) != 3 {
		t.Errorf("expected 3 batches, got %d: %v", len(batches), batches)
	}
}

func TestEventHTTPTransport_204Success(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	buf := events.NewRingBuffer(100)
	buf.Push(makeEvent("evt-1"))

	tp := transport.NewEventHTTPTransport(transport.EventFlushConfig{
		Server:        srv.URL,
		Token:         "test-token",
		FlushInterval: time.Hour,
	}, buf)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	tp.Run(ctx) //nolint:errcheck

	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected 1 HTTP call, got %d", received)
	}
	if buf.Len() != 0 {
		t.Errorf("buffer not drained: %d events remain", buf.Len())
	}
}

func TestEventHTTPTransport_401NoPermanentError(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	buf := events.NewRingBuffer(100)
	buf.Push(makeEvent("evt-1"))

	tp := transport.NewEventHTTPTransport(transport.EventFlushConfig{
		Server:        srv.URL,
		Token:         "bad-token",
		FlushInterval: time.Hour,
	}, buf)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	tp.Run(ctx) //nolint:errcheck

	// 401 is permanent — must not be retried
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("expected 1 call (no retry on 401), got %d", calls)
	}
}

func TestEventHTTPTransport_FinalFlushOnContextCancel(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	buf := events.NewRingBuffer(100)

	tp := transport.NewEventHTTPTransport(transport.EventFlushConfig{
		Server:        srv.URL,
		Token:         "tok",
		FlushInterval: 10 * time.Second, // long interval, won't tick
	}, buf)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		tp.Run(ctx) //nolint:errcheck
		close(done)
	}()

	// Push an event after the transport is running.
	time.Sleep(20 * time.Millisecond)
	buf.Push(makeEvent("final-evt"))
	cancel() // trigger shutdown

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}

	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected 1 final-flush call, got %d", received)
	}
}
