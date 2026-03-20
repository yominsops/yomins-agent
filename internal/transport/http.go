package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

const requestTimeout = 15 * time.Second

// HTTPConfig holds the parameters for HTTPTransport.
type HTTPConfig struct {
	Server             string
	Token              string
	Interval           time.Duration
	InsecureSkipVerify bool
}

// HTTPTransport pushes metric payloads to a remote HTTPS endpoint.
// It retries on transient errors (5xx, network failures) with exponential
// backoff bounded to 90% of the collection interval to prevent tick overlap.
type HTTPTransport struct {
	cfg    HTTPConfig
	client *http.Client
}

// NewHTTPTransport creates an HTTPTransport from the given configuration.
func NewHTTPTransport(cfg HTTPConfig) *HTTPTransport {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // explicitly opt-in flag
	}
	return &HTTPTransport{
		cfg: cfg,
		client: &http.Client{
			Timeout: requestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}
}

// Push serialises the MetricSet and delivers it to the configured endpoint.
func (t *HTTPTransport) Push(ctx context.Context, ms metrics.MetricSet) error {
	payload, err := metrics.Encode(ms)
	if err != nil {
		return fmt.Errorf("encode metrics: %w", err)
	}

	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = time.Second
	bo.MaxInterval = 60 * time.Second
	bo.MaxElapsedTime = time.Duration(float64(t.cfg.Interval) * 0.9)
	bo.Reset()

	attempt := 0
	notify := func(err error, next time.Duration) {
		attempt++
		slog.Warn("push failed, retrying",
			"attempt", attempt,
			"error", err,
			"retry_in", next.Round(time.Millisecond),
		)
	}

	op := func() error {
		return t.do(ctx, payload)
	}

	if err := backoff.RetryNotify(op, backoff.WithContext(bo, ctx), notify); err != nil {
		return fmt.Errorf("push: %w", err)
	}
	return nil
}

// do performs a single HTTP POST attempt.
func (t *HTTPTransport) do(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.Server, bytes.NewReader(payload))
	if err != nil {
		return backoff.Permanent(fmt.Errorf("create request: %w", err))
	}

	req.Header.Set("Content-Type", metrics.ContentType)
	req.Header.Set("Authorization", "Bearer "+t.cfg.Token)

	resp, err := t.client.Do(req)
	if err != nil {
		// Network-level error — retryable.
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// 4xx errors (except 429) are permanent — do not retry.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return backoff.Permanent(fmt.Errorf("server returned %d (permanent error) for %s %s", resp.StatusCode, req.Method, req.URL))
	}

	// 5xx and 429 — retryable.
	return fmt.Errorf("server returned %d", resp.StatusCode)
}
