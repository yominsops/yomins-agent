//go:build linux

package network

import (
	"context"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/events"
)

func testNetConfig() Config {
	return Config{
		Host:  events.HostInfo{Hostname: "test-host", IP: "10.0.0.1"},
		Agent: events.AgentInfo{Name: "test-agent", Version: "0.0.0"},
	}
}

func makeFakeScanner(listeners []listenEntry, total int, err error) listenerScanner {
	return func() ([]listenEntry, int, error) {
		return listeners, total, err
	}
}

// ── Config defaults ──────────────────────────────────────────────────────────

func TestNewCollector_Defaults(t *testing.T) {
	c := NewCollector(Config{})
	if c.cfg.PollInterval != 5*time.Second {
		t.Errorf("PollInterval = %v, want 5s", c.cfg.PollInterval)
	}
	if c.cfg.ScanDeltaThreshold != 50 {
		t.Errorf("ScanDeltaThreshold = %d, want 50", c.cfg.ScanDeltaThreshold)
	}
	if c.cfg.ScanMultiplier != 2.0 {
		t.Errorf("ScanMultiplier = %v, want 2.0", c.cfg.ScanMultiplier)
	}
}

func TestCollector_Name(t *testing.T) {
	c := NewCollector(Config{})
	if c.Name() != "network" {
		t.Errorf("Name() = %q, want \"network\"", c.Name())
	}
}

// ── poll: new listener detection ─────────────────────────────────────────────

func TestPoll_NewListener_EmitsEvent(t *testing.T) {
	port80 := listenEntry{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 80}

	// Start with no listeners, then a new one appears.
	c := newCollectorWithScanner(testNetConfig(), makeFakeScanner(nil, 0, nil))
	c.prevListen = make(map[string]listenEntry) // empty baseline
	c.prevTotal = 0

	c.scanner = makeFakeScanner([]listenEntry{port80}, 1, nil)
	evs := c.poll()

	if len(evs) != 1 {
		t.Fatalf("events count = %d, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Type != events.EventNetworkConnectionOpen {
		t.Errorf("Type = %q, want %q", ev.Type, events.EventNetworkConnectionOpen)
	}
	if ev.Network == nil {
		t.Fatal("Network payload must not be nil")
	}
	if ev.Network.LocalPort != 80 {
		t.Errorf("LocalPort = %d, want 80", ev.Network.LocalPort)
	}
	if ev.Network.Proto != "tcp" {
		t.Errorf("Proto = %q, want tcp", ev.Network.Proto)
	}
	if ev.Category != events.CategorySystemCheck {
		t.Errorf("Category = %q, want system_check", ev.Category)
	}
	if ev.Severity != events.SeverityInfo {
		t.Errorf("Severity = %q, want info", ev.Severity)
	}
	if ev.ID == "" {
		t.Error("ID must not be empty")
	}
}

func TestPoll_ExistingListener_NoEvent(t *testing.T) {
	port80 := listenEntry{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 80}

	c := newCollectorWithScanner(testNetConfig(), makeFakeScanner([]listenEntry{port80}, 1, nil))
	// Populate baseline with port80 already present.
	c.prevListen[port80.key()] = port80
	c.prevTotal = 1

	evs := c.poll()
	for _, ev := range evs {
		if ev.Type == events.EventNetworkConnectionOpen {
			t.Error("unexpected connection_open event for pre-existing listener")
		}
	}
}

func TestPoll_MultipleNewListeners(t *testing.T) {
	listeners := []listenEntry{
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 22},
		{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 80},
		{Proto: "tcp6", LocalIP: "::", LocalPort: 443},
	}

	c := newCollectorWithScanner(testNetConfig(), makeFakeScanner(listeners, 3, nil))
	c.prevListen = make(map[string]listenEntry)
	c.prevTotal = 0

	evs := c.poll()
	openEvents := 0
	for _, ev := range evs {
		if ev.Type == events.EventNetworkConnectionOpen {
			openEvents++
		}
	}
	if openEvents != 3 {
		t.Errorf("connection_open events = %d, want 3", openEvents)
	}
}

// ── poll: scan detection ─────────────────────────────────────────────────────

func TestPoll_ScanDetected(t *testing.T) {
	c := newCollectorWithScanner(testNetConfig(), makeFakeScanner(nil, 200, nil))
	c.cfg.ScanDeltaThreshold = 50
	c.cfg.ScanMultiplier = 2.0
	c.prevListen = make(map[string]listenEntry)
	c.prevTotal = 10 // burst: 200 > 10*2 and delta (190) > 50

	evs := c.poll()
	var found bool
	for _, ev := range evs {
		if ev.Type == events.EventNetworkScanDetected {
			found = true
			if ev.Category != events.CategoryThreatActivity {
				t.Errorf("scan Category = %q, want threat_activity", ev.Category)
			}
			if ev.Severity != events.SeverityCritical {
				t.Errorf("scan Severity = %q, want critical", ev.Severity)
			}
		}
	}
	if !found {
		t.Error("expected network.scan_detected event, got none")
	}
}

func TestPoll_ScanNotDetected_BelowDeltaThreshold(t *testing.T) {
	// 60 connections, prev=10, delta=50 which equals threshold but not exceeds.
	c := newCollectorWithScanner(testNetConfig(), makeFakeScanner(nil, 60, nil))
	c.cfg.ScanDeltaThreshold = 51
	c.cfg.ScanMultiplier = 2.0
	c.prevListen = make(map[string]listenEntry)
	c.prevTotal = 10

	evs := c.poll()
	for _, ev := range evs {
		if ev.Type == events.EventNetworkScanDetected {
			t.Error("unexpected scan_detected event (delta below threshold)")
		}
	}
}

func TestPoll_ScanNotDetected_BelowMultiplier(t *testing.T) {
	// 15 connections, prev=10, delta=5 (below threshold=50 anyway)
	c := newCollectorWithScanner(testNetConfig(), makeFakeScanner(nil, 15, nil))
	c.cfg.ScanDeltaThreshold = 5
	c.cfg.ScanMultiplier = 2.0 // 15 < 10*2 = 20
	c.prevListen = make(map[string]listenEntry)
	c.prevTotal = 10

	evs := c.poll()
	for _, ev := range evs {
		if ev.Type == events.EventNetworkScanDetected {
			t.Error("unexpected scan_detected event (below multiplier threshold)")
		}
	}
}

func TestPoll_ScannerError_ReturnsNoEvents(t *testing.T) {
	c := newCollectorWithScanner(testNetConfig(), makeFakeScanner(nil, 0, context.DeadlineExceeded))
	c.prevListen = make(map[string]listenEntry)
	evs := c.poll()
	if len(evs) != 0 {
		t.Errorf("expected 0 events on scanner error, got %d", len(evs))
	}
}

// ── Run: baseline and lifecycle ──────────────────────────────────────────────

func TestRun_UnavailableScanner_ReturnsNil(t *testing.T) {
	// If the first scanner call fails, Run returns nil (graceful disable).
	c := newCollectorWithScanner(testNetConfig(), makeFakeScanner(nil, 0, context.DeadlineExceeded))
	out := make(chan events.Event, 10)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := c.Run(ctx, out)
	if err != nil {
		t.Errorf("Run returned error = %v, want nil", err)
	}
}

func TestRun_BaselineNoEvents(t *testing.T) {
	// If baseline has listeners and they don't change, no events should be emitted.
	port443 := listenEntry{Proto: "tcp", LocalIP: "0.0.0.0", LocalPort: 443}
	calls := 0
	scanner := func() ([]listenEntry, int, error) {
		calls++
		return []listenEntry{port443}, 1, nil
	}

	c := newCollectorWithScanner(testNetConfig(), scanner)
	c.cfg.PollInterval = 50 * time.Millisecond

	out := make(chan events.Event, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	c.Run(ctx, out) //nolint:errcheck

	if len(out) != 0 {
		t.Errorf("expected 0 events for stable listeners, got %d", len(out))
	}
}
