package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/yominsops/yomins-agent/internal/events"
)

const eventsRequestTimeout = 15 * time.Second

// EventFlushConfig holds parameters for EventHTTPTransport.
type EventFlushConfig struct {
	Server             string
	Token              string
	FlushInterval      time.Duration // default: 10s
	BatchSize          int           // default: 200
	InsecureSkipVerify bool
}

// EventHTTPTransport drains events from a RingBuffer and POSTs them in batches
// to the ingest server's /events endpoint.
type EventHTTPTransport struct {
	cfg    EventFlushConfig
	buf    *events.RingBuffer
	client *http.Client
}

// NewEventHTTPTransport creates an EventHTTPTransport.
func NewEventHTTPTransport(cfg EventFlushConfig, buf *events.RingBuffer) *EventHTTPTransport {
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 200
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // explicitly opt-in flag
	}
	return &EventHTTPTransport{
		cfg: cfg,
		buf: buf,
		client: &http.Client{
			Timeout: eventsRequestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}
}

// Run starts the flush loop. It flushes on every tick and performs one final
// flush after the context is cancelled to drain any remaining events.
// Blocks until ctx is done.
func (t *EventHTTPTransport) Run(ctx context.Context) error {
	ticker := time.NewTicker(t.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := t.flush(ctx); err != nil {
				slog.Warn("event flush failed", "error", err)
			}
		case <-ctx.Done():
			// Final drain before exit.
			flushCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := t.flush(flushCtx); err != nil {
				slog.Warn("event final flush failed", "error", err)
			}
			return ctx.Err()
		}
	}
}

// flush drains the ring buffer and sends all events in batches.
func (t *EventHTTPTransport) flush(ctx context.Context) error {
	all := t.buf.Drain()
	if len(all) == 0 {
		return nil
	}

	for i := 0; i < len(all); i += t.cfg.BatchSize {
		end := i + t.cfg.BatchSize
		if end > len(all) {
			end = len(all)
		}
		if err := t.postBatch(ctx, all[i:end]); err != nil {
			// Re-enqueue remaining events on failure so they are not lost.
			for _, e := range all[i:] {
				t.buf.Push(e)
			}
			return fmt.Errorf("post batch starting at %d: %w", i, err)
		}
	}
	return nil
}

type eventsPayload struct {
	Events []events.Event `json:"events"`
}

// postBatch sends one batch to the server with exponential backoff retry.
func (t *EventHTTPTransport) postBatch(ctx context.Context, batch []events.Event) error {
	body, err := json.Marshal(eventsPayload{Events: batch})
	if err != nil {
		return backoff.Permanent(fmt.Errorf("marshal events: %w", err))
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = time.Second
	bo.MaxInterval = 30 * time.Second
	bo.MaxElapsedTime = 60 * time.Second
	bo.Reset()

	attempt := 0
	notify := func(err error, next time.Duration) {
		attempt++
		slog.Warn("event batch post failed, retrying",
			"attempt", attempt,
			"events", len(batch),
			"error", err,
			"retry_in", next.Round(time.Millisecond),
		)
	}

	op := func() error {
		return t.doPost(ctx, body)
	}

	return backoff.RetryNotify(op, backoff.WithContext(bo, ctx), notify)
}

// doPost performs a single HTTP POST attempt.
func (t *EventHTTPTransport) doPost(ctx context.Context, body []byte) error {
	url := t.cfg.Server + "/events"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return backoff.Permanent(fmt.Errorf("create request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.cfg.Token)

	resp, err := t.client.Do(req)
	if err != nil {
		return err // network error — retryable
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// 4xx except 429 are permanent — do not retry.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return backoff.Permanent(fmt.Errorf("server returned %d (permanent) for POST %s", resp.StatusCode, url))
	}

	// 5xx and 429 — retryable.
	return fmt.Errorf("server returned %d", resp.StatusCode)
}
