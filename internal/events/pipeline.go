package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
)

const defaultFanInDepth = 256

// PipelineConfig holds pipeline-level settings.
type PipelineConfig struct {
	// BufferSize is the maximum number of events held in the ring buffer.
	// Defaults to 10000.
	BufferSize int
	// FanInDepth is the depth of the internal fan-in channel.
	// Defaults to 256.
	FanInDepth int
}

// Pipeline wires EventCollectors to a shared RingBuffer.
// It starts one goroutine per collector plus one fan-in goroutine.
// Phase 1: every event is also logged as JSON via slog.Debug.
type Pipeline struct {
	collectors []EventCollector
	buf        *RingBuffer
	fanIn      chan Event
}

// NewPipeline constructs a Pipeline with the given config and collectors.
func NewPipeline(cfg PipelineConfig, collectors ...EventCollector) *Pipeline {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 10000
	}
	if cfg.FanInDepth <= 0 {
		cfg.FanInDepth = defaultFanInDepth
	}
	return &Pipeline{
		collectors: collectors,
		buf:        NewRingBuffer(cfg.BufferSize),
		fanIn:      make(chan Event, cfg.FanInDepth),
	}
}

// Buffer exposes the ring buffer so that a future transport can drain it.
func (p *Pipeline) Buffer() *RingBuffer {
	return p.buf
}

// Run starts all collectors and the fan-in loop. It blocks until ctx is done.
// Collector goroutines are started and waited on; Run returns once the fan-in
// channel is drained after all collectors have exited.
func (p *Pipeline) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	for _, c := range p.collectors {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Run(ctx, p.fanIn); err != nil {
				slog.Error("event collector exited with error", "collector", c.Name(), "error", err)
			}
		}()
	}

	// Close the fan-in channel once all collectors have exited so the fan-in
	// loop below can drain remaining events and return.
	go func() {
		wg.Wait()
		close(p.fanIn)
	}()

	// Fan-in loop: read from the channel, push to buffer, log each event.
	for ev := range p.fanIn {
		p.buf.Push(ev)
		if data, err := json.Marshal(ev); err == nil {
			slog.Debug("event", "type", string(ev.Type), "severity", string(ev.Severity), "payload", string(data))
		}
	}

	return nil
}
