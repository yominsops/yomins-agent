package events

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCollector is a test EventCollector that sends a fixed list of events
// and then blocks until the context is cancelled.
type fakeCollector struct {
	name   string
	events []Event
	ran    atomic.Bool
}

func (f *fakeCollector) Name() string { return f.name }

func (f *fakeCollector) Run(ctx context.Context, out chan<- Event) error {
	f.ran.Store(true)
	for _, ev := range f.events {
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
	<-ctx.Done()
	return nil
}

// errorCollector always returns an error from Run.
type errorCollector struct{}

func (e *errorCollector) Name() string { return "error-collector" }
func (e *errorCollector) Run(_ context.Context, _ chan<- Event) error {
	return context.DeadlineExceeded
}

func TestNewPipeline_Defaults(t *testing.T) {
	p := NewPipeline(PipelineConfig{})
	if p.buf.cap != 10000 {
		t.Errorf("default BufferSize = %d, want 10000", p.buf.cap)
	}
	if cap(p.fanIn) != defaultFanInDepth {
		t.Errorf("default FanInDepth = %d, want %d", cap(p.fanIn), defaultFanInDepth)
	}
}

func TestNewPipeline_CustomConfig(t *testing.T) {
	p := NewPipeline(PipelineConfig{BufferSize: 50, FanInDepth: 8})
	if p.buf.cap != 50 {
		t.Errorf("BufferSize = %d, want 50", p.buf.cap)
	}
	if cap(p.fanIn) != 8 {
		t.Errorf("FanInDepth = %d, want 8", cap(p.fanIn))
	}
}

func TestPipeline_Buffer(t *testing.T) {
	p := NewPipeline(PipelineConfig{BufferSize: 5})
	if p.Buffer() != p.buf {
		t.Error("Buffer() did not return the internal ring buffer")
	}
}

func TestPipeline_Run_CollectsEvents(t *testing.T) {
	ev1 := makeEvent(EventProcessStart)
	ev2 := makeEvent(EventAuthLogout)
	fc := &fakeCollector{
		name:   "fake",
		events: []Event{ev1, ev2},
	}

	p := NewPipeline(PipelineConfig{BufferSize: 10, FanInDepth: 8}, fc)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	p.Run(ctx) //nolint:errcheck

	got := p.Buffer().Drain()
	if len(got) != 2 {
		t.Fatalf("buffer len = %d, want 2", len(got))
	}
	if got[0].Type != EventProcessStart {
		t.Errorf("got[0].Type = %q, want %q", got[0].Type, EventProcessStart)
	}
	if got[1].Type != EventAuthLogout {
		t.Errorf("got[1].Type = %q, want %q", got[1].Type, EventAuthLogout)
	}
}

func TestPipeline_Run_MultipleCollectors(t *testing.T) {
	fc1 := &fakeCollector{name: "c1", events: []Event{makeEvent(EventProcessStart)}}
	fc2 := &fakeCollector{name: "c2", events: []Event{makeEvent(EventAuthLogout)}}
	fc3 := &fakeCollector{name: "c3", events: []Event{makeEvent(EventSystemReboot)}}

	p := NewPipeline(PipelineConfig{BufferSize: 10, FanInDepth: 8}, fc1, fc2, fc3)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	p.Run(ctx) //nolint:errcheck

	got := p.Buffer().Drain()
	if len(got) != 3 {
		t.Fatalf("buffer len = %d, want 3", len(got))
	}

	// Verify all 3 event types are present (order may vary across goroutines).
	seen := make(map[EventType]bool)
	for _, ev := range got {
		seen[ev.Type] = true
	}
	for _, want := range []EventType{EventProcessStart, EventAuthLogout, EventSystemReboot} {
		if !seen[want] {
			t.Errorf("event type %q not found in buffer", want)
		}
	}
}

func TestPipeline_Run_AllCollectorsStarted(t *testing.T) {
	fc1 := &fakeCollector{name: "c1"}
	fc2 := &fakeCollector{name: "c2"}

	p := NewPipeline(PipelineConfig{BufferSize: 10}, fc1, fc2)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	p.Run(ctx) //nolint:errcheck

	if !fc1.ran.Load() {
		t.Error("collector c1 was never started")
	}
	if !fc2.ran.Load() {
		t.Error("collector c2 was never started")
	}
}

func TestPipeline_Run_ErrorCollector_DoesNotCrash(t *testing.T) {
	good := &fakeCollector{name: "good", events: []Event{makeEvent(EventProcessStart)}}
	bad := &errorCollector{}

	p := NewPipeline(PipelineConfig{BufferSize: 10, FanInDepth: 8}, good, bad)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// Should not panic or block indefinitely.
	p.Run(ctx) //nolint:errcheck

	// The good collector's event should still arrive.
	got := p.Buffer().Drain()
	if len(got) != 1 {
		t.Fatalf("buffer len = %d, want 1", len(got))
	}
}

func TestPipeline_Run_EmptyCollectors(t *testing.T) {
	p := NewPipeline(PipelineConfig{BufferSize: 10})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should return immediately with no collectors.
	done := make(chan struct{})
	go func() {
		p.Run(ctx) //nolint:errcheck
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(500 * time.Millisecond):
		t.Error("Run did not return after all collectors exited")
	}
}

func TestPipeline_Run_ContextCancellation(t *testing.T) {
	// Collector that never sends anything — just blocks until cancelled.
	blocker := &fakeCollector{name: "blocker"}

	p := NewPipeline(PipelineConfig{BufferSize: 10}, blocker)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		p.Run(ctx) //nolint:errcheck
		close(done)
	}()

	// Let it start.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("Run did not return after context cancellation")
	}
}

func TestPipeline_Run_BufferOverflowDoesNotBlock(t *testing.T) {
	// Buffer size 2, but collector sends 10 events.
	many := make([]Event, 10)
	for i := range many {
		many[i] = makeEvent(EventProcessStart)
	}
	fc := &fakeCollector{name: "many", events: many}

	p := NewPipeline(PipelineConfig{BufferSize: 2, FanInDepth: 16}, fc)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Should not deadlock even though the buffer is smaller than the event stream.
	done := make(chan struct{})
	go func() {
		p.Run(ctx) //nolint:errcheck
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("Run blocked on buffer overflow")
	}

	buf := p.Buffer()
	if buf.Len() == 0 && buf.Dropped() == 0 {
		t.Error("expected some events in buffer or some dropped, got neither")
	}
}
