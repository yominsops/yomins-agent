//go:build linux

package system

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
	StateDir           string // for persisting the last known boot time and snapshots
	MonitorConfigFiles bool   // watch critical config files for hash changes
	Host               events.HostInfo
	Agent              events.AgentInfo
}

// fileState records the hash and metadata of a monitored file.
type fileState struct {
	Hash    string `json:"hash"`
	ModTime int64  `json:"mod_time"`
	Size    int64  `json:"size"`
}

// defaultMonitoredFiles is the list of security-critical files to watch.
var defaultMonitoredFiles = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
}

// Collector emits system.reboot on startup if a reboot is detected, and
// system.oom_killer whenever the kernel OOM killer fires. It also polls
// /etc/passwd for user changes and monitors critical config files.
type Collector struct {
	cfg Config
}

// NewCollector creates a SystemCollector.
func NewCollector(cfg Config) *Collector {
	return &Collector{cfg: cfg}
}

func (c *Collector) Name() string { return "system" }

// Run checks for a recent reboot on startup, then launches background
// goroutines for OOM monitoring, user change detection, and config file watching.
func (c *Collector) Run(ctx context.Context, out chan<- events.Event) error {
	// One-shot reboot check.
	if ev, ok := c.checkReboot(ctx); ok {
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}

	go c.runOOMWatcher(ctx, out)
	go c.pollPasswd(ctx, out)

	if c.cfg.MonitorConfigFiles {
		go c.pollFileState(ctx, out)
	}

	<-ctx.Done()
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

// ── User change detection ─────────────────────────────────────────────────────

func (c *Collector) pollPasswd(ctx context.Context, out chan<- events.Event) {
	snapshot, err := c.loadPasswdSnapshot()
	if err != nil {
		snapshot = c.currentPasswdUsers()
		_ = c.savePasswdSnapshot(snapshot)
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			current := c.currentPasswdUsers()
			if current == nil {
				continue
			}

			for username, uid := range current {
				if _, exists := snapshot[username]; !exists {
					slog.Warn("system: user created", "user", username, "uid", uid)
					ev := events.Event{
						ID:         uuid.New().String(),
						Timestamp:  now.UTC(),
						Type:       events.EventSystemUserCreated,
						Category:   events.CategoryThreatActivity,
						Severity:   events.SeverityCritical,
						Confidence: events.ConfidenceHigh,
						Host:       c.cfg.Host,
						Agent:      c.cfg.Agent,
						Actor:      &events.ActorInfo{User: username, UID: uid},
						Tags:       []string{"system", "user_created"},
					}
					select {
					case out <- ev:
					case <-ctx.Done():
						return
					}
				}
			}

			for username, uid := range snapshot {
				if _, exists := current[username]; !exists {
					slog.Warn("system: user deleted", "user", username, "uid", uid)
					ev := events.Event{
						ID:         uuid.New().String(),
						Timestamp:  now.UTC(),
						Type:       events.EventSystemUserDeleted,
						Category:   events.CategoryThreatActivity,
						Severity:   events.SeverityWarning,
						Confidence: events.ConfidenceMedium,
						Host:       c.cfg.Host,
						Agent:      c.cfg.Agent,
						Actor:      &events.ActorInfo{User: username, UID: uid},
						Tags:       []string{"system", "user_deleted"},
					}
					select {
					case out <- ev:
					case <-ctx.Done():
						return
					}
				}
			}

			if !passwdEqual(snapshot, current) {
				snapshot = current
				_ = c.savePasswdSnapshot(snapshot)
			}
		}
	}
}

func (c *Collector) currentPasswdUsers() map[string]int {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		slog.Warn("system: cannot read /etc/passwd", "error", err)
		return nil
	}
	users := make(map[string]int)
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 3 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		users[parts[0]] = uid
	}
	return users
}

func passwdEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func (c *Collector) passwdSnapshotPath() string {
	return filepath.Join(c.cfg.StateDir, "passwd_snapshot.json")
}

func (c *Collector) loadPasswdSnapshot() (map[string]int, error) {
	data, err := os.ReadFile(c.passwdSnapshotPath())
	if err != nil {
		return nil, err
	}
	var m map[string]int
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Collector) savePasswdSnapshot(m map[string]int) error {
	if m == nil {
		return nil
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := c.passwdSnapshotPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, c.passwdSnapshotPath())
}

// ── Config file monitoring ────────────────────────────────────────────────────

func (c *Collector) pollFileState(ctx context.Context, out chan<- events.Event) {
	state := c.loadFileState()

	// Build initial baseline for any files not yet tracked.
	for _, path := range defaultMonitoredFiles {
		if _, exists := state[path]; !exists {
			if fs, err := hashFile(path); err == nil {
				state[path] = fs
			}
		}
	}
	_ = c.saveFileState(state)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	warnedUnreadable := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			changed := false
			for _, path := range defaultMonitoredFiles {
				current, err := hashFile(path)
				if err != nil {
					if !warnedUnreadable[path] {
						slog.Debug("system: cannot hash file, skipping", "path", path, "error", err)
						warnedUnreadable[path] = true
					}
					continue
				}
				warnedUnreadable[path] = false

				prev, known := state[path]
				if known && prev.Hash != current.Hash {
					slog.Warn("system: config file modified", "path", path)
					ev := events.Event{
						ID:         uuid.New().String(),
						Timestamp:  now.UTC(),
						Type:       events.EventSystemConfigModified,
						Category:   events.CategoryThreatActivity,
						Severity:   events.SeverityCritical,
						Confidence: events.ConfidenceHigh,
						Host:       c.cfg.Host,
						Agent:      c.cfg.Agent,
						Context:    &events.ContextInfo{Reason: path},
						Tags:       []string{"system", "config_modified"},
					}
					select {
					case out <- ev:
					case <-ctx.Done():
						return
					}
				}
				if !known || prev.Hash != current.Hash {
					state[path] = current
					changed = true
				}
			}
			if changed {
				_ = c.saveFileState(state)
			}
		}
	}
}

func hashFile(path string) (fileState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return fileState{}, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fileState{}, err
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	return fileState{
		Hash:    hash,
		ModTime: fi.ModTime().Unix(),
		Size:    fi.Size(),
	}, nil
}

func (c *Collector) fileStatePath() string {
	return filepath.Join(c.cfg.StateDir, "file_state.json")
}

func (c *Collector) loadFileState() map[string]fileState {
	data, err := os.ReadFile(c.fileStatePath())
	if err != nil {
		return make(map[string]fileState)
	}
	var m map[string]fileState
	if err := json.Unmarshal(data, &m); err != nil {
		return make(map[string]fileState)
	}
	return m
}

func (c *Collector) saveFileState(m map[string]fileState) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := c.fileStatePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, c.fileStatePath())
}
