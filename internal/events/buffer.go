package events

import "sync"

// RingBuffer is a bounded FIFO that drops the oldest event when full.
// It is goroutine-safe.
type RingBuffer struct {
	mu      sync.Mutex
	buf     []Event
	head    int    // index of the oldest element
	tail    int    // index of the next write position
	size    int    // number of elements currently stored
	cap     int    // maximum capacity
	dropped uint64 // total events dropped due to overflow
}

// NewRingBuffer creates a RingBuffer with the given capacity.
// Panics if capacity is less than 1.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity < 1 {
		panic("events: RingBuffer capacity must be >= 1")
	}
	return &RingBuffer{
		buf: make([]Event, capacity),
		cap: capacity,
	}
}

// Push adds an event to the buffer. If the buffer is full, the oldest event is
// silently dropped and the dropped counter is incremented.
func (r *RingBuffer) Push(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.size == r.cap {
		// Overwrite oldest element; advance head.
		r.buf[r.tail] = e
		r.head = (r.head + 1) % r.cap
		r.tail = (r.tail + 1) % r.cap
		r.dropped++
		return
	}

	r.buf[r.tail] = e
	r.tail = (r.tail + 1) % r.cap
	r.size++
}

// Drain returns all buffered events in FIFO order and resets the buffer to empty.
func (r *RingBuffer) Drain() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.size == 0 {
		return nil
	}

	out := make([]Event, r.size)
	for i := range out {
		out[i] = r.buf[(r.head+i)%r.cap]
	}
	r.head = 0
	r.tail = 0
	r.size = 0
	return out
}

// Len returns the current number of buffered events.
func (r *RingBuffer) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

// Dropped returns the total count of events dropped due to buffer overflow.
func (r *RingBuffer) Dropped() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}
