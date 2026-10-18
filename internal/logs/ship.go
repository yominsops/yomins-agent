package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/yominsops/yomins-agent/internal/transport"
)

// ContentType of a logs push: one JSON object per line.
const ContentType = "application/x-ndjson"

// reservedFields are set by the agent or the server; parser fields with these
// names are dropped rather than allowed to overwrite them.
var reservedFields = map[string]bool{
	"_time": true, "_msg": true, "_stream": true, "source": true, "file": true, "unit": true,
	"level": true, "host": true, "agent_id": true, "project_id": true, "customer_id": true,
}

// ShipperConfig tunes batching.
type ShipperConfig struct {
	MaxBatchLines int           // default 1000
	MaxBatchBytes int           // default 1 MiB (before compression)
	FlushEvery    time.Duration // default 2s
	Hostname      string        // sent as X-Yomins-Hostname, checked like the metrics' hostname
	AgentID       string
}

// Shipper batches entries from the sources and posts them to /logs. It
// retries a batch until it is delivered (or refused for good) before reading
// more, so a long outage stops the sources instead of losing lines: their
// positions only move on acknowledgement.
type Shipper struct {
	cfg    ShipperConfig
	poster *transport.Poster
	redact *Redactor
	stats  *Stats
	sleep  func(context.Context, time.Duration) bool
}

// NewShipper creates a shipper.
func NewShipper(cfg ShipperConfig, poster *transport.Poster, redact *Redactor, stats *Stats) *Shipper {
	if cfg.MaxBatchLines <= 0 {
		cfg.MaxBatchLines = 1000
	}
	if cfg.MaxBatchBytes <= 0 {
		cfg.MaxBatchBytes = 1 << 20
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 2 * time.Second
	}
	return &Shipper{cfg: cfg, poster: poster, redact: redact, stats: stats, sleep: sleepCtx}
}

// Run ships until ctx is done.
func (s *Shipper) Run(ctx context.Context, in <-chan Entry) {
	var (
		batch   []Entry
		buf     bytes.Buffer
		timer   = time.NewTimer(s.cfg.FlushEvery)
		pending bool
	)
	defer timer.Stop()
	flush := func() {
		if len(batch) > 0 {
			s.deliver(ctx, batch, buf.Bytes())
		}
		batch, pending = batch[:0], false
		buf.Reset()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-in:
			s.stats.observe(e)
			line, err := s.encode(e)
			if err != nil {
				s.stats.dropped("encode")
				if e.ack != nil {
					e.ack()
				}
				continue
			}
			if len(batch) > 0 && buf.Len()+len(line) > s.cfg.MaxBatchBytes {
				flush()
			}
			buf.Write(line)
			batch = append(batch, e)
			if !pending {
				timer.Reset(s.cfg.FlushEvery)
				pending = true
			}
			if len(batch) >= s.cfg.MaxBatchLines {
				flush()
			}
		case <-timer.C:
			flush()
		}
	}
}

// encode renders one entry as a JSON line, redacted.
func (s *Shipper) encode(e Entry) ([]byte, error) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	obj := make(map[string]string, 6+len(e.Fields))
	for k, v := range e.Fields {
		if !reservedFields[k] && k != "" {
			obj[k] = s.redact.Redact(v)
		}
	}
	obj["_time"] = e.Time.UTC().Format(time.RFC3339Nano)
	obj["_msg"] = s.redact.Redact(e.Msg)
	obj["source"] = e.Source
	if e.Path != "" {
		obj["file"] = e.Path
	}
	if e.Unit != "" {
		obj["unit"] = e.Unit
	}
	if e.Level != "" {
		obj["level"] = e.Level
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// deliver posts one batch until it is accepted or refused for good, then
// acknowledges its entries. It gives up only when ctx is done.
func (s *Shipper) deliver(ctx context.Context, batch []Entry, payload []byte) {
	headers := map[string]string{"X-Yomins-Hostname": s.cfg.Hostname, "X-Yomins-Agent-Id": s.cfg.AgentID}
	wait := time.Second
	for {
		err := s.poster.Post(ctx, "/logs", ContentType, headers, payload)
		var refused *transport.RefusedError
		var busy *transport.BusyError
		switch {
		case err == nil:
			s.stats.shipped(batch, len(payload))
			ack(batch)
			return
		case errors.As(err, &refused):
			slog.Warn("logs: server refused a batch, dropped", "lines", len(batch), "status", refused.Status)
			s.stats.droppedN("refused", len(batch))
			ack(batch)
			return
		case transport.IsRejection(err):
			// Paused for the whole agent; the session logged it. Check again soon.
			wait = 10 * time.Second
		case errors.As(err, &busy) && busy.RetryAfter > 0:
			wait = busy.RetryAfter
		default:
			slog.Debug("logs: push failed, retrying", "error", err, "retry_in", wait)
		}
		s.stats.retry()
		if !s.sleep(ctx, wait) {
			return
		}
		wait = min(wait*2, time.Minute)
	}
}

func ack(batch []Entry) {
	for _, e := range batch {
		if e.ack != nil {
			e.ack()
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
