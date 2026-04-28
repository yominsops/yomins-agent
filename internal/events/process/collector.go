package process

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	gopsprocess "github.com/shirou/gopsutil/v3/process"
	"github.com/yominsops/yomins-agent/internal/events"
)

// DefaultSuspiciousPatterns is the built-in list of suspicious command-line patterns.
// Includes reverse-shell patterns so that isSuspicious() covers all dangerous cmdlines;
// poll() emits the more specific process.reverse_shell type for the reverse-shell subset.
var DefaultSuspiciousPatterns = []string{
	`curl.*\|\s*(ba)?sh`,
	`wget.*\|\s*(ba)?sh`,
	`\bnc\s+-[^-]*e`,
	`base64.*-d.*\|.*sh`,
	`/dev/tcp/`,
	`xmrig|minerd|cpuminer`,
	`bash\s+-i\s+>&\s+/dev/tcp`,
}

// DefaultReverseShellPatterns is the subset of suspicious patterns that indicate
// an active reverse shell. These emit process.reverse_shell instead of process.suspicious.
var DefaultReverseShellPatterns = []string{
	`\bnc\s+-[^-]*e`,
	`/dev/tcp/`,
	`bash\s+-i\s+>&\s+/dev/tcp`,
}

// defaultTmpPaths are the directories considered suspicious for binary execution.
var defaultTmpPaths = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// Config holds configuration for the ProcessCollector.
type Config struct {
	PollInterval       time.Duration // default: 2s
	SuspiciousPatterns []string      // compiled at startup; DefaultSuspiciousPatterns if empty
	CPUAlertThreshold  float64       // absolute CPU % floor for alerts; default: 5.0
	CPUAlertMultiplier float64       // alert when current > multiplier × avg; default: 3.0
	MemAlertThreshold  float32       // absolute memory % floor; default: 10.0
	MemAlertMultiplier float32       // alert when current > multiplier × avg; default: 3.0
	AlertCooldown      time.Duration // suppress repeat alerts per process; default: 60s
	MonitorLifecycle   bool          // emit process.start and process.stop events; default: false
	MonitorTmpPaths    bool          // emit process.exec_tmp events; default: true when enabled via config
	Host               events.HostInfo
	Agent              events.AgentInfo
}

// processLister is a function that returns the current process list.
// Decoupled from gopsutil to allow injection in tests.
type processLister func(ctx context.Context) ([]*gopsprocess.Process, error)

// Collector watches for new/exited processes and detects resource anomalies
// and suspicious command lines.
type Collector struct {
	cfg             Config
	patterns        []*regexp.Regexp // suspicious patterns (process.suspicious)
	reverseShells   []*regexp.Regexp // reverse-shell patterns (process.reverse_shell)
	lister          processLister

	mu    sync.Mutex
	procs map[int32]*ProcessSnapshot // PID → snapshot
}

// NewCollector creates a ProcessCollector with the given config.
func NewCollector(cfg Config) *Collector {
	return newCollectorWithLister(cfg, gopsprocess.ProcessesWithContext)
}

// newCollectorWithLister creates a ProcessCollector with a custom process lister.
// Used in tests to inject a fake process list without OS interaction.
func newCollectorWithLister(cfg Config, lister processLister) *Collector {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.CPUAlertThreshold == 0 {
		cfg.CPUAlertThreshold = 5.0
	}
	if cfg.CPUAlertMultiplier == 0 {
		cfg.CPUAlertMultiplier = 3.0
	}
	if cfg.MemAlertThreshold == 0 {
		cfg.MemAlertThreshold = 10.0
	}
	if cfg.MemAlertMultiplier == 0 {
		cfg.MemAlertMultiplier = 3.0
	}
	if cfg.AlertCooldown == 0 {
		cfg.AlertCooldown = 60 * time.Second
	}

	patterns := cfg.SuspiciousPatterns
	if len(patterns) == 0 {
		patterns = DefaultSuspiciousPatterns
	}
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		} else {
			slog.Warn("process: invalid suspicious pattern, skipping", "pattern", p, "error", err)
		}
	}

	var reverseShells []*regexp.Regexp
	for _, p := range DefaultReverseShellPatterns {
		if re, err := regexp.Compile(p); err == nil {
			reverseShells = append(reverseShells, re)
		}
	}

	return &Collector{
		cfg:           cfg,
		patterns:      compiled,
		reverseShells: reverseShells,
		lister:        lister,
		procs:         make(map[int32]*ProcessSnapshot),
	}
}

func (c *Collector) Name() string { return "process" }

// Run polls gopsutil for process changes and emits events. Blocks until ctx is done.
func (c *Collector) Run(ctx context.Context, out chan<- events.Event) error {
	// First poll: build baseline — no events emitted.
	if err := c.buildBaseline(ctx); err != nil {
		slog.Warn("process: failed to build baseline, proceeding without it", "error", err)
	}

	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			evs := c.poll(ctx)
			for _, ev := range evs {
				select {
				case out <- ev:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}

// buildBaseline captures the current process set as a baseline.
// Processes in the baseline never emit start/stop events.
func (c *Collector) buildBaseline(ctx context.Context) error {
	procs, err := c.lister(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range procs {
		snap := c.snapshotProcess(ctx, p, false)
		if snap != nil {
			c.procs[p.Pid] = snap
		}
	}
	return nil
}

// poll compares the current process set against the known state and returns
// all events that should be emitted.
func (c *Collector) poll(ctx context.Context) []events.Event {
	procs, err := c.lister(ctx)
	if err != nil {
		slog.Warn("process: failed to list processes", "error", err)
		return nil
	}

	currentPIDs := make(map[int32]struct{}, len(procs))
	for _, p := range procs {
		currentPIDs[p.Pid] = struct{}{}
	}

	var evs []events.Event
	now := time.Now().UTC()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Detect new processes.
	for _, p := range procs {
		if _, known := c.procs[p.Pid]; known {
			continue
		}
		snap := c.snapshotProcess(ctx, p, true)
		if snap == nil {
			continue
		}
		c.procs[p.Pid] = snap

		if c.cfg.MonitorLifecycle {
			evs = append(evs, c.makeStartEvent(snap, now))
		}

		// Check for execution from temporary directories.
		if c.cfg.MonitorTmpPaths && isExecFromTmp(snap.Exe, snap.Cmdline) {
			evs = append(evs, c.makeExecTmpEvent(snap, now))
		}

		// Check for reverse shell patterns first (more specific), then other suspicious patterns.
		if c.isReverseShell(snap.Cmdline) {
			evs = append(evs, c.makeReverseShellEvent(snap, now))
		} else if c.isSuspicious(snap.Cmdline) {
			evs = append(evs, c.makeSuspiciousEvent(snap, now))
		}
	}

	// Detect exited and anomalous processes.
	for pid, snap := range c.procs {
		if _, alive := currentPIDs[pid]; !alive {
			if snap.isNew && c.cfg.MonitorLifecycle {
				evs = append(evs, c.makeStopEvent(snap, now))
			}
			delete(c.procs, pid)
			continue
		}

		// Update metrics for surviving processes and check for anomalies.
		// Use the stored proc object: CPUPercentWithContext computes a delta
		// between consecutive calls on the same instance; a fresh object always
		// returns 0 on its first call.
		if snap.proc == nil {
			continue
		}
		cpu, _ := snap.proc.CPUPercentWithContext(ctx)
		mem, _ := snap.proc.MemoryPercentWithContext(ctx)
		cpuAvg, memAvg := snap.pushMetrics(cpu, float32(mem))

		slog.Debug("process: anomaly check",
			"pid", snap.PID, "name", snap.Name,
			"cpu", cpu, "cpu_avg", cpuAvg, "cpu_ready", snap.readyForAnomaly(),
			"mem", mem, "mem_avg", memAvg)

		if !snap.readyForAnomaly() {
			continue
		}

		if cpu > c.cfg.CPUAlertThreshold &&
			(cpuAvg == 0 || cpu > c.cfg.CPUAlertMultiplier*cpuAvg) &&
			now.Sub(snap.lastCPUAlertAt) > c.cfg.AlertCooldown {
			evs = append(evs, c.makeCPUEvent(snap, cpu, cpuAvg, now))
			snap.lastCPUAlertAt = now
		}

		if float64(mem) > float64(c.cfg.MemAlertThreshold) &&
			(memAvg == 0 || mem > c.cfg.MemAlertMultiplier*memAvg) &&
			now.Sub(snap.lastMemAlertAt) > c.cfg.AlertCooldown {
			evs = append(evs, c.makeMemEvent(snap, float32(mem), memAvg, now))
			snap.lastMemAlertAt = now
		}
	}

	return evs
}

// snapshotProcess reads process metadata from gopsutil and returns a snapshot.
// Returns nil if the process has already exited or can't be read.
func (c *Collector) snapshotProcess(ctx context.Context, p *gopsprocess.Process, isNew bool) *ProcessSnapshot {
	name, _ := p.NameWithContext(ctx)
	ppid, _ := p.PpidWithContext(ctx)
	exe, _ := p.ExeWithContext(ctx)
	cmdlineSlice, _ := p.CmdlineSliceWithContext(ctx)
	cmdline := strings.Join(cmdlineSlice, " ")
	if cmdline == "" {
		cmdline, _ = p.CmdlineWithContext(ctx)
	}

	return &ProcessSnapshot{
		PID:     p.Pid,
		PPID:    int32(ppid),
		Name:    name,
		Exe:     exe,
		Cmdline: cmdline,
		isNew:   isNew,
		proc:    p,
	}
}

func (c *Collector) isSuspicious(cmdline string) bool {
	for _, re := range c.patterns {
		if re.MatchString(cmdline) {
			return true
		}
	}
	return false
}

func (c *Collector) isReverseShell(cmdline string) bool {
	for _, re := range c.reverseShells {
		if re.MatchString(cmdline) {
			return true
		}
	}
	return false
}

// isExecFromTmp returns true if the process binary or any cmdline token lives
// under a temporary/world-writable directory.
func isExecFromTmp(exe, cmdline string) bool {
	for _, prefix := range defaultTmpPaths {
		if strings.HasPrefix(exe, prefix) {
			return true
		}
	}
	for _, token := range strings.Fields(cmdline) {
		for _, prefix := range defaultTmpPaths {
			if strings.HasPrefix(token, prefix) {
				return true
			}
		}
	}
	return false
}

// ── event constructors ────────────────────────────────────────────────────────

func (c *Collector) makeStartEvent(s *ProcessSnapshot, now time.Time) events.Event {
	return events.Event{
		ID:        uuid.New().String(),
		Timestamp: now,
		Type:      events.EventProcessStart,
		Category:  events.CategorySystemCheck,
		Severity:  events.SeverityInfo,
		Host:      c.cfg.Host,
		Agent:     c.cfg.Agent,
		Process: &events.ProcessDetail{
			Name:    s.Name,
			PID:     s.PID,
			PPID:    s.PPID,
			Cmdline: s.Cmdline,
			Exe:     s.Exe,
		},
		Tags: []string{"process", "start"},
	}
}

func (c *Collector) makeStopEvent(s *ProcessSnapshot, now time.Time) events.Event {
	return events.Event{
		ID:        uuid.New().String(),
		Timestamp: now,
		Type:      events.EventProcessStop,
		Category:  events.CategorySystemCheck,
		Severity:  events.SeverityInfo,
		Host:      c.cfg.Host,
		Agent:     c.cfg.Agent,
		Process: &events.ProcessDetail{
			Name:    s.Name,
			PID:     s.PID,
			PPID:    s.PPID,
			Cmdline: s.Cmdline,
			Exe:     s.Exe,
		},
		Tags: []string{"process", "stop"},
	}
}

func (c *Collector) makeSuspiciousEvent(s *ProcessSnapshot, now time.Time) events.Event {
	return events.Event{
		ID:        uuid.New().String(),
		Timestamp: now,
		Type:      events.EventProcessSuspicious,
		Category:  events.CategoryThreatActivity,
		Severity:  events.SeverityCritical,
		Host:      c.cfg.Host,
		Agent:     c.cfg.Agent,
		Process: &events.ProcessDetail{
			Name:    s.Name,
			PID:     s.PID,
			PPID:    s.PPID,
			Cmdline: s.Cmdline,
			Exe:     s.Exe,
		},
		Tags: []string{"process", "suspicious"},
	}
}

func (c *Collector) makeCPUEvent(s *ProcessSnapshot, current, avg float64, now time.Time) events.Event {
	return events.Event{
		ID:        uuid.New().String(),
		Timestamp: now,
		Type:      events.EventProcessHighCPU,
		Category:  events.CategorySystemCheck,
		Severity:  events.SeverityWarning,
		Host:      c.cfg.Host,
		Agent:     c.cfg.Agent,
		Process: &events.ProcessDetail{
			Name:       s.Name,
			PID:        s.PID,
			Cmdline:    s.Cmdline,
			CPUPercent: current,
		},
		Context: &events.ContextInfo{
			Reason: "cpu_spike",
		},
		Tags: []string{"process", "high_cpu"},
	}
}

func (c *Collector) makeMemEvent(s *ProcessSnapshot, current, avg float32, now time.Time) events.Event {
	return events.Event{
		ID:        uuid.New().String(),
		Timestamp: now,
		Type:      events.EventProcessHighMemory,
		Category:  events.CategorySystemCheck,
		Severity:  events.SeverityWarning,
		Host:      c.cfg.Host,
		Agent:     c.cfg.Agent,
		Process: &events.ProcessDetail{
			Name:          s.Name,
			PID:           s.PID,
			Cmdline:       s.Cmdline,
			MemoryPercent: current,
		},
		Context: &events.ContextInfo{
			Reason: "memory_spike",
		},
		Tags: []string{"process", "high_memory"},
	}
}

func (c *Collector) makeExecTmpEvent(s *ProcessSnapshot, now time.Time) events.Event {
	return events.Event{
		ID:         uuid.New().String(),
		Timestamp:  now,
		Type:       events.EventProcessExecTmp,
		Category:   events.CategoryThreatActivity,
		Severity:   events.SeverityWarning,
		Confidence: events.ConfidenceMedium,
		Host:       c.cfg.Host,
		Agent:      c.cfg.Agent,
		Process: &events.ProcessDetail{
			Name:    s.Name,
			PID:     s.PID,
			PPID:    s.PPID,
			Cmdline: s.Cmdline,
			Exe:     s.Exe,
		},
		Tags: []string{"process", "exec_tmp"},
	}
}

func (c *Collector) makeReverseShellEvent(s *ProcessSnapshot, now time.Time) events.Event {
	return events.Event{
		ID:         uuid.New().String(),
		Timestamp:  now,
		Type:       events.EventProcessReverseShell,
		Category:   events.CategoryThreatActivity,
		Severity:   events.SeverityCritical,
		Confidence: events.ConfidenceHigh,
		Host:       c.cfg.Host,
		Agent:      c.cfg.Agent,
		Process: &events.ProcessDetail{
			Name:    s.Name,
			PID:     s.PID,
			PPID:    s.PPID,
			Cmdline: s.Cmdline,
			Exe:     s.Exe,
		},
		Tags: []string{"process", "reverse_shell"},
	}
}
