package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// RefusedError is a 4xx other than 401/403/429: the server will never take
// this payload, so the caller drops it instead of retrying.
type RefusedError struct{ Status int }

func (e *RefusedError) Error() string { return fmt.Sprintf("server refused the payload: %d", e.Status) }

// BusyError is a 429 or 5xx: try again, after RetryAfter when the server said.
type BusyError struct {
	Status     int
	RetryAfter time.Duration
}

func (e *BusyError) Error() string { return fmt.Sprintf("server busy: %d", e.Status) }

// Poster sends one payload per call to a path of the ingest server, sharing
// the session (rejection pause, gzip) with the other transports. It does not
// retry: the caller decides, since its data may be safe on disk.
type Poster struct {
	server  string
	token   string
	session *Session
	client  *http.Client
}

// NewPoster creates a Poster. session may be nil for a private one.
func NewPoster(server, token string, insecureSkipVerify bool, session *Session) *Poster {
	if session == nil {
		session = NewSession()
	}
	return &Poster{
		server:  server,
		token:   token,
		session: session,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify}, //nolint:gosec // explicitly opt-in flag
			},
		},
	}
}

// Paused reports whether the server currently rejects this agent.
func (p *Poster) Paused() bool { return p.session.Paused() }

// Post sends payload. Errors: ErrPaused, *RejectedError (401/403),
// *RefusedError (other 4xx), *BusyError (429/5xx), or a network error.
func (p *Poster) Post(ctx context.Context, path, contentType string, headers map[string]string, payload []byte) error {
	if p.session.Paused() {
		return ErrPaused
	}
	body, encoding := p.session.encode(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.server+path, bytes.NewReader(body))
	if err != nil {
		return &RefusedError{}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+p.token)
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch s := resp.StatusCode; {
	case s >= 200 && s < 300:
		p.session.accepted(resp)
		return nil
	case s == http.StatusUnauthorized || s == http.StatusForbidden:
		rej := rejection(resp)
		p.session.reject(rej)
		return rej
	case s == http.StatusTooManyRequests || s >= 500:
		return &BusyError{Status: s, RetryAfter: retryAfter(resp)}
	default:
		return &RefusedError{Status: s}
	}
}
