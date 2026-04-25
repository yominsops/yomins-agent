//go:build linux

package system

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	gopshost "github.com/shirou/gopsutil/v3/host"
	"github.com/yominsops/yomins-agent/internal/events"
)

// Config holds configuration for the SystemCollector.
type Config struct {
	StateDir string // for persisting the last known boot time
	Host     events.HostInfo
	Agent    events.AgentInfo
}

// Collector emits system.reboot on startup if a reboot is detected, and
// system.oom_killer whenever the kernel OOM killer fires.
type Collector struct {
	cfg Config
}

// NewCollector creates a SystemCollector.
func NewCollector(cfg Config) *Collector {
	return &Collector{cfg: cfg}
}

func (c *Collector) Name() string { return "system" }

// Run checks for a recent reboot on startup, then monitors /dev/kmsg for OOM events.
func (c *Collector) Run(ctx context.Context, out chan<- events.Event) error {
	// One-shot reboot check.
	if ev, ok := c.checkReboot(ctx); ok {
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}

	// Continuous OOM monitoring.
	c.runOOMWatcher(ctx, out)
	return nil
}

// ── Reboot detection ──────────────────────────────────────────────────────────

func (c *Collector) checkReboot(ctx context.Context) (events.Event, bool) {
	bootTime, err := gopshost.BootTimeWithContext(ctx)
	if err != nil {
		slog.Warn("system: cannot determine boot time", "error", err)
		return events.Event{}, false
	}

	prevBootTime, err := c.loadBootTime()
	c.saveBootTime(bootTime)

	if err != nil {
		// No previous boot time recorded — first run, no reboot event.
		return events.Event{}, false
	}

	if bootTime > prevBootTime {
		return events.Event{
			ID:        uuid.New().String(),
			Timestamp: time.Unix(int64(bootTime), 0).UTC(),
			Type:      events.EventSystemReboot,
			Category:  events.CategorySystemCheck,
			Severity:  events.SeverityWarning,
			Host:      c.cfg.Host,
			Agent:     c.cfg.Agent,
			Tags:      []string{"system", "reboot"},
		}, true
	}
	return events.Event{}, false
}

func (c *Collector) bootTimePath() string {
	return filepath.Join(c.cfg.StateDir, "last_boot_time")
}

func (c *Collector) loadBootTime() (uint64, error) {
	data, err := os.ReadFile(c.bootTimePath())
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return v, err
}

func (c *Collector) saveBootTime(t uint64) {
	_ = os.WriteFile(c.bootTimePath(), []byte(strconv.FormatUint(t, 10)), 0600)
}

// ── OOM watcher ───────────────────────────────────────────────────────────────

func (c *Collector) runOOMWatcher(ctx context.Context, out chan<- events.Event) {
	f, err := openKmsg()
	if err != nil {
		slog.Warn("system: /dev/kmsg unavailable, OOM events disabled", "error", err)
		return
	}
	defer f.Close()

	// Drain records that pre-date the agent start by seeking to the end.
	// /dev/kmsg supports SEEK_END to position at the tail of the ring buffer;
	// this avoids consuming the scanner (a scanner that has returned false is
	// permanently done and cannot be reused to read new messages).
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		// Fallback: drain via scanner. The scanner will be in a terminal state
		// after this, so we reopen the file for the watching phase.
		tmpScanner := bufio.NewScanner(f)
		drainKmsg(tmpScanner)
		f.Close()
		f, err = openKmsg()
		if err != nil {
			slog.Warn("system: /dev/kmsg reopen failed after drain, OOM events disabled", "error", err)
			return
		}
		defer f.Close()
	}

	scanner := bufio.NewScanner(f)

	// Read new kernel messages as they arrive.
	// bufio.Scanner on /dev/kmsg blocks until a new message is available.
	done := ctx.Done()
	lines := make(chan string, 16)

	go func() {
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-done:
				return
			}
		}
		close(lines)
	}()

	for {
		select {
		case <-done:
			return
		case line, ok := <-lines:
			if !ok {
				return
			}
			if ev, matched := c.parseOOM(line); matched {
				select {
				case out <- ev:
				case <-done:
					return
				}
			}
		}
	}
}

func (c *Collector) parseOOM(line string) (events.Event, bool) {
	parsed, ok := parseOOMLine(line)
	if !ok {
		return events.Event{}, false
	}
	return events.Event{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Type:      events.EventSystemOOMKiller,
		Category:  events.CategorySystemCheck,
		Severity:  events.SeverityWarning,
		Host:      c.cfg.Host,
		Agent:     c.cfg.Agent,
		Process: &events.ProcessDetail{
			Name: parsed.ProcessName,
		},
		Context: &events.ContextInfo{
			Reason: "oom_killed",
		},
		Tags: []string{"system", "oom"},
	}, true
}
