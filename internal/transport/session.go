package transport

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// reasonHeader carries a machine-readable reason on a rejected push
	// (e.g. "service_blocked", "token_revoked", "hostname_mismatch").
	reasonHeader = "X-Yomins-Reason"
	// acceptEncodingHeader is set by an ingest server that accepts gzip bodies.
	// The agent sends plain bodies until it has seen it, so a new agent keeps
	// working against an older server.
	acceptEncodingHeader = "X-Yomins-Accept-Encoding"

	minPause = time.Minute
	maxPause = 30 * time.Minute
)

// ErrPaused is returned instead of pushing while the server has rejected the
// agent (401/403) and the pause has not run out yet.
var ErrPaused = errors.New("pushes paused: the server rejected this agent")

// RejectedError is a 401/403 from the server. It is permanent for the attempt;
// the session pauses every push until the pause ends.
type RejectedError struct {
	Status     int
	Reason     string
	RetryAfter time.Duration
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("server rejected the agent: %d %s", e.Status, e.Reason)
}

// Session is the state the metrics and event transports share about the
// server: whether it currently rejects this agent, and whether it takes gzip.
type Session struct {
	mu     sync.Mutex
	now    func() time.Time
	until  time.Time
	pause  time.Duration
	reason string
	gzipOK bool
}

// NewSession returns a session that pushes freely and sends plain bodies.
func NewSession() *Session {
	return &Session{now: time.Now}
}

// Paused reports whether pushes must be skipped now.
func (s *Session) Paused() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now().Before(s.until)
}

// reject records a 401/403: pushes stop for Retry-After when the server gave
// one, otherwise for a pause that doubles on every rejection in a row.
func (s *Session) reject(e *RejectedError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pause := e.RetryAfter
	if pause <= 0 {
		pause = min(max(s.pause*2, minPause), maxPause)
	}
	first := s.until.IsZero() || s.reason != e.Reason
	s.pause = pause
	s.until = s.now().Add(pause)
	s.reason = e.Reason
	if first {
		slog.Error("server rejected the agent, pausing pushes", "status", e.Status, "reason", e.Reason, "retry_in", pause)
	} else {
		slog.Warn("server still rejects the agent", "status", e.Status, "reason", e.Reason, "retry_in", pause)
	}
}

// accepted records a successful push and what the response says about gzip.
func (s *Session) accepted(resp *http.Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.until.IsZero() {
		slog.Info("server accepts the agent again, pushes resumed", "reason_was", s.reason)
	}
	s.until, s.pause, s.reason = time.Time{}, 0, ""
	if strings.Contains(resp.Header.Get(acceptEncodingHeader), "gzip") {
		s.gzipOK = true
	}
}

// encode returns the body to send and its Content-Encoding ("" for plain).
func (s *Session) encode(payload []byte) ([]byte, string) {
	s.mu.Lock()
	ok := s.gzipOK
	s.mu.Unlock()
	if !ok || len(payload) < 1024 {
		return payload, ""
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		return payload, ""
	}
	if err := zw.Close(); err != nil {
		return payload, ""
	}
	return buf.Bytes(), "gzip"
}

// isRejection reports whether err is (or wraps) ErrPaused or a 401/403; the
// session has already logged those, callers need not.
func isRejection(err error) bool {
	var rej *RejectedError
	return errors.Is(err, ErrPaused) || errors.As(err, &rej)
}

// IsRejection is isRejection for callers outside the package.
func IsRejection(err error) bool { return isRejection(err) }

// rejection builds the RejectedError for a 401/403 response.
func rejection(resp *http.Response) *RejectedError {
	reason := resp.Header.Get(reasonHeader)
	if reason == "" {
		// Older servers explain in the body only ("service is blocked", …).
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		reason = strings.TrimSpace(string(b))
	}
	if reason == "" {
		reason = http.StatusText(resp.StatusCode)
	}
	return &RejectedError{Status: resp.StatusCode, Reason: reason, RetryAfter: retryAfter(resp)}
}

// retryAfter parses a Retry-After header given in seconds (0 if absent).
func retryAfter(resp *http.Response) time.Duration {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}
