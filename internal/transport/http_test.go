package transport_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
	"github.com/yominsops/yomins-agent/internal/transport"
)

func makeMetricSet() metrics.MetricSet {
	return metrics.MetricSet{
		AgentID:  "test-agent",
		Hostname: "test-host",
		Version:  "0.1.0",
		Source:   "yomins_agent",
		Points: []metrics.MetricPoint{
			{Name: "cpu_usage_percent", Help: "CPU", Type: metrics.Gauge, Value: 10.0},
		},
	}
}

func TestHTTPTransport_PushSuccess(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tp := transport.NewHTTPTransport(transport.HTTPConfig{
		Server:   srv.URL,
		Token:    "test-token",
		Interval: 60 * time.Second,
	})

	err := tp.Push(context.Background(), makeMetricSet())
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("server received %d requests, want 1", received)
	}
}

func TestHTTPTransport_RetryOn5xx(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		if n < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tp := transport.NewHTTPTransport(transport.HTTPConfig{
		Server:   srv.URL,
		Token:    "tok",
		Interval: 60 * time.Second,
	})

	err := tp.Push(context.Background(), makeMetricSet())
	if err != nil {
		t.Fatalf("Push: %v (expected retry to succeed)", err)
	}
	if atomic.LoadInt32(&callCount) < 2 {
		t.Errorf("callCount = %d, expected >= 2 (retry happened)", callCount)
	}
}

func TestHTTPTransport_NoRetryOn401(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	tp := transport.NewHTTPTransport(transport.HTTPConfig{
		Server:   srv.URL,
		Token:    "bad-token",
		Interval: 60 * time.Second,
	})

	err := tp.Push(context.Background(), makeMetricSet())
	if err == nil {
		t.Fatal("expected error for 401, got nil")
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("callCount = %d, want 1 (no retry on 401)", callCount)
	}
}

func TestHTTPTransport_NoRetryOn400(t *testing.T) {
	var callCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	tp := transport.NewHTTPTransport(transport.HTTPConfig{
		Server:   srv.URL,
		Token:    "tok",
		Interval: 60 * time.Second,
	})

	err := tp.Push(context.Background(), makeMetricSet())
	if err == nil {
		t.Fatal("expected error for 400, got nil")
	}
	if atomic.LoadInt32(&callCount) != 1 {
		t.Errorf("callCount = %d, want 1 (no retry on 400)", callCount)
	}
}

func TestHTTPTransport_ContextCancellation(t *testing.T) {
	// Server that sleeps longer than the client context timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(1 * time.Second):
		}
	}))
	defer srv.Close()

	tp := transport.NewHTTPTransport(transport.HTTPConfig{
		Server:   srv.URL,
		Token:    "tok",
		Interval: 60 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := tp.Push(ctx, makeMetricSet())
	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}
}

func TestHTTPTransport_InsecureSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tp := transport.NewHTTPTransport(transport.HTTPConfig{
		Server:             srv.URL,
		Token:              "tok",
		Interval:           60 * time.Second,
		InsecureSkipVerify: true,
	})

	err := tp.Push(context.Background(), makeMetricSet())
	if err != nil {
		t.Fatalf("Push with InsecureSkipVerify: %v", err)
	}
}

func TestHTTPTransport_TLSFailsWithoutInsecure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tp := transport.NewHTTPTransport(transport.HTTPConfig{
		Server:             srv.URL,
		Token:              "tok",
		Interval:           5 * time.Second,
		InsecureSkipVerify: false,
	})

	err := tp.Push(context.Background(), makeMetricSet())
	if err == nil {
		t.Fatal("expected TLS verification error, got nil")
	}
}
