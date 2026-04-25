package events

import (
	"sync"
	"testing"
	"time"
)

func makeEvent(typ EventType) Event {
	return Event{
		ID:        "test-id",
		Timestamp: time.Now().UTC(),
		Type:      typ,
		Category:  CategorySystemCheck,
		Severity:  SeverityInfo,
	}
}

func TestRingBuffer_PanicOnZeroCapacity(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for capacity 0, got none")
		}
	}()
	NewRingBuffer(0)
}

func TestRingBuffer_PanicOnNegativeCapacity(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for negative capacity, got none")
		}
	}()
	NewRingBuffer(-1)
}

func TestRingBuffer_EmptyDrain(t *testing.T) {
	buf := NewRingBuffer(10)
	got := buf.Drain()
	if got != nil {
		t.Errorf("Drain of empty buffer = %v, want nil", got)
	}
	if buf.Len() != 0 {
		t.Errorf("Len after empty drain = %d, want 0", buf.Len())
	}
}

func TestRingBuffer_PushAndDrain(t *testing.T) {
	buf := NewRingBuffer(5)

	ev1 := makeEvent(EventProcessStart)
	ev2 := makeEvent(EventAuthLogout)
	buf.Push(ev1)
	buf.Push(ev2)

	if buf.Len() != 2 {
		t.Fatalf("Len = %d, want 2", buf.Len())
	}

	got := buf.Drain()
	if len(got) != 2 {
		t.Fatalf("Drain len = %d, want 2", len(got))
	}
	if got[0].Type != EventProcessStart {
		t.Errorf("got[0].Type = %q, want %q", got[0].Type, EventProcessStart)
	}
	if got[1].Type != EventAuthLogout {
		t.Errorf("got[1].Type = %q, want %q", got[1].Type, EventAuthLogout)
	}
}

func TestRingBuffer_DrainResetsBuffer(t *testing.T) {
	buf := NewRingBuffer(5)
	buf.Push(makeEvent(EventProcessStart))
	buf.Drain()

	if buf.Len() != 0 {
		t.Errorf("Len after drain = %d, want 0", buf.Len())
	}
	if got := buf.Drain(); got != nil {
		t.Errorf("second Drain = %v, want nil", got)
	}
}

func TestRingBuffer_FIFOOrder(t *testing.T) {
	const n = 8
	buf := NewRingBuffer(n)

	types := []EventType{
		EventAuthLoginSuccess, EventAuthLogout, EventProcessStart,
		EventProcessStop, EventNetworkConnectionOpen, EventSystemReboot,
		EventProcessSuspicious, EventSystemOOMKiller,
	}
	for _, typ := range types {
		buf.Push(makeEvent(typ))
	}

	got := buf.Drain()
	for i, ev := range got {
		if ev.Type != types[i] {
			t.Errorf("FIFO[%d]: got %q, want %q", i, ev.Type, types[i])
		}
	}
}

func TestRingBuffer_Overflow_DropOldest(t *testing.T) {
	buf := NewRingBuffer(3)

	buf.Push(makeEvent(EventProcessStart))  // will be dropped
	buf.Push(makeEvent(EventProcessStop))   // will be dropped
	buf.Push(makeEvent(EventAuthLogout))
	buf.Push(makeEvent(EventAuthLoginSuccess)) // overflow → drops EventProcessStart
	buf.Push(makeEvent(EventNetworkConnectionOpen)) // overflow → drops EventProcessStop

	if buf.Dropped() != 2 {
		t.Errorf("Dropped = %d, want 2", buf.Dropped())
	}
	if buf.Len() != 3 {
		t.Errorf("Len = %d, want 3", buf.Len())
	}

	got := buf.Drain()
	want := []EventType{EventAuthLogout, EventAuthLoginSuccess, EventNetworkConnectionOpen}
	for i, ev := range got {
		if ev.Type != want[i] {
			t.Errorf("overflow[%d]: got %q, want %q", i, ev.Type, want[i])
		}
	}
}

func TestRingBuffer_Overflow_WrapAround(t *testing.T) {
	// Fill exactly at capacity, drain, refill to test index wraparound.
	buf := NewRingBuffer(4)
	for i := 0; i < 4; i++ {
		buf.Push(makeEvent(EventProcessStart))
	}
	buf.Drain() // head=0, tail=0, size=0

	// Push again: indices should wrap cleanly.
	buf.Push(makeEvent(EventAuthLoginSuccess))
	buf.Push(makeEvent(EventAuthLogout))
	got := buf.Drain()
	if len(got) != 2 {
		t.Fatalf("after wraparound drain len = %d, want 2", len(got))
	}
	if got[0].Type != EventAuthLoginSuccess {
		t.Errorf("wraparound[0] = %q, want %q", got[0].Type, EventAuthLoginSuccess)
	}
}

func TestRingBuffer_CapacityOne(t *testing.T) {
	buf := NewRingBuffer(1)
	buf.Push(makeEvent(EventProcessStart))
	buf.Push(makeEvent(EventProcessStop)) // overflow

	if buf.Dropped() != 1 {
		t.Errorf("Dropped = %d, want 1", buf.Dropped())
	}
	got := buf.Drain()
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Type != EventProcessStop {
		t.Errorf("type = %q, want %q", got[0].Type, EventProcessStop)
	}
}

func TestRingBuffer_ConcurrentPushDrain(t *testing.T) {
	const (
		capacity  = 100
		producers = 4
		perWorker = 1000
	)
	buf := NewRingBuffer(capacity)

	var wg sync.WaitGroup
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				buf.Push(makeEvent(EventProcessStart))
			}
		}()
	}

	// Drain concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < producers*perWorker/capacity; i++ {
			buf.Drain()
		}
	}()

	wg.Wait()
	// No assertions on exact values — just verify no race/panic.
	_ = buf.Len()
	_ = buf.Dropped()
}

func TestRingBuffer_DroppedStartsZero(t *testing.T) {
	buf := NewRingBuffer(10)
	if buf.Dropped() != 0 {
		t.Errorf("Dropped = %d, want 0", buf.Dropped())
	}
}

func TestRingBuffer_MultipleDrainCycles(t *testing.T) {
	buf := NewRingBuffer(3)

	for cycle := 0; cycle < 5; cycle++ {
		buf.Push(makeEvent(EventProcessStart))
		buf.Push(makeEvent(EventProcessStop))
		got := buf.Drain()
		if len(got) != 2 {
			t.Errorf("cycle %d: Drain len = %d, want 2", cycle, len(got))
		}
	}
}
