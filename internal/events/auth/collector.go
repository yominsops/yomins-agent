//go:build linux

package auth

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/yominsops/yomins-agent/internal/events"
)

// fileInode returns the inode number of the file described by fi.
// Used to detect log rotation (inode change = new file at same path).
func fileInode(fi os.FileInfo) uint64 {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}

// Config holds configuration for the AuthCollector.
type Config struct {
	WtmpPath    string // default: /var/log/wtmp
	AuthLogPath string // default: /var/log/auth.log; falls back to /var/log/secure
	StateDir    string // for persisting the wtmp byte cursor and login-IP state

	BruteforceThreshold   int           // default: 5
	BruteforceWindow      time.Duration // default: 30s
	BruteforceSuppression time.Duration // default: 2m
	IgnorePrivateIP       bool          // ignore loopback/private IPs for login_new_ip

	Host  events.HostInfo
	Agent events.AgentInfo
}

// bruteforceKey groups failed attempts by remote IP and username.
type bruteforceKey struct {
	RemoteIP string
	User     string
}

// bruteforceEntry tracks the sliding window of failed attempts for one key.
type bruteforceEntry struct {
	attempts        []time.Time
	suppressedUntil time.Time
}

// Collector watches /var/log/wtmp for login/logout events and
// /var/log/auth.log for failed login and sudo events.
type Collector struct {
	cfg Config

	mu           sync.Mutex
	bfTracker    map[bruteforceKey]*bruteforceEntry
	lastIPByUser map[string]string // user → last seen remote IP
}

// NewCollector creates a new AuthCollector.
func NewCollector(cfg Config) *Collector {
	if cfg.WtmpPath == "" {
		cfg.WtmpPath = "/var/log/wtmp"
	}
	// Debian 13 (trixie) uses wtmp.db instead of wtmp.
	if _, err := os.Stat(cfg.WtmpPath); os.IsNotExist(err) {
		const wtmpDB = "/var/log/wtmp.db"
		if _, err2 := os.Stat(wtmpDB); err2 == nil {
			cfg.WtmpPath = wtmpDB
		}
	}
	if cfg.AuthLogPath == "" {
		cfg.AuthLogPath = "/var/log/auth.log"
	}
	// If the configured auth log does not exist, try /var/log/secure as a
	// secondary file-based fallback (used on RHEL/CentOS/AlmaLinux systems).
	// If that also does not exist, Run will fall back to the systemd journal.
	if _, err := os.Stat(cfg.AuthLogPath); os.IsNotExist(err) {
		const secure = "/var/log/secure"
		if _, err2 := os.Stat(secure); err2 == nil {
			cfg.AuthLogPath = secure
		}
	}
	if cfg.BruteforceThreshold == 0 {
		cfg.BruteforceThreshold = 5
	}
	if cfg.BruteforceWindow == 0 {
		cfg.BruteforceWindow = 30 * time.Second
	}
	if cfg.BruteforceSuppression == 0 {
		cfg.BruteforceSuppression = 2 * time.Minute
	}
	return &Collector{
		cfg:          cfg,
		bfTracker:    make(map[bruteforceKey]*bruteforceEntry),
		lastIPByUser: loadLastIPByUser(cfg.StateDir),
	}
}

func (c *Collector) Name() string { return "auth" }

// Run starts the wtmp and auth log watchers and multiplexes their events onto out.
// The auth log watcher uses a file if one exists (auth.log or secure), otherwise
// it falls back to reading the systemd journal via journalctl.
func (c *Collector) Run(ctx context.Context, out chan<- events.Event) error {
	sub := make(chan events.Event, 64)

	go c.runWtmp(ctx, sub)

	if _, err := os.Stat(c.cfg.AuthLogPath); err == nil {
		go c.runAuthLog(ctx, sub)
	} else {
		go c.runJournalLog(ctx, sub)
	}

	gcTicker := time.NewTicker(time.Minute)
	defer gcTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-sub:
			if !ok {
				return nil
			}
			select {
			case out <- ev:
			case <-ctx.Done():
				return nil
			}
		case <-gcTicker.C:
			c.gcBruteforceTracker()
		}
	}
}

// ── wtmp watcher ──────────────────────────────────────────────────────────────

func (c *Collector) runWtmp(ctx context.Context, out chan<- events.Event) {
	f, err := os.Open(c.cfg.WtmpPath)
	if err != nil {
		slog.Warn("auth: wtmp unavailable, login/logout events disabled", "path", c.cfg.WtmpPath, "error", err)
		return
	}
	defer f.Close()

	// Seek to end — do not replay historical sessions.
	cursor, err := c.loadWtmpCursor()
	if err != nil || cursor == 0 {
		end, _ := f.Seek(0, io.SeekEnd)
		cursor = end
	}
	if _, err := f.Seek(cursor, io.SeekStart); err != nil {
		if _, err = f.Seek(0, io.SeekEnd); err != nil {
			slog.Warn("auth: cannot seek wtmp", "error", err)
			return
		}
	}

	var prevInode uint64
	if fi, err := f.Stat(); err == nil {
		prevInode = fileInode(fi)
	}

	buf := make([]byte, utmpRecordSize)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Detect log rotation: if inode changed, reopen from start.
			if fi, err := os.Stat(c.cfg.WtmpPath); err == nil {
				if fileInode(fi) != prevInode {
					f.Close()
					f, err = os.Open(c.cfg.WtmpPath)
					if err != nil {
						slog.Warn("auth: wtmp reopen failed after rotation", "error", err)
						return
					}
					prevInode = fileInode(fi)
					cursor = 0
				}
			}

			// Read all available complete records.
			for {
				n, err := io.ReadFull(f, buf)
				if n == utmpRecordSize {
					cursor += int64(n)
					rec, ok := parseRecord(buf)
					if ok {
						now := time.Now().UTC()
						switch rec.Type {
						case utUserProcess:
							// Login records always carry a username.
							if rec.User != "" {
								out <- c.makeLoginEvent(rec)
								if nipEv, triggered := c.checkNewIP(rec, now); triggered {
									out <- nipEv
								}
							}
						case utDeadProcess:
							// Logout records have an empty ut_user by kernel convention;
							// use TTY as the presence check instead.
							if rec.TTY != "" {
								out <- c.makeLogoutEvent(rec)
							}
						}
					}
				}
				if err != nil {
					// No more complete records available right now.
					break
				}
			}
			c.saveWtmpCursor(cursor)
		}
	}
}

func (c *Collector) makeLoginEvent(rec parsedRecord) events.Event {
	return events.Event{
		ID:        uuid.New().String(),
		Timestamp: rec.Timestamp,
		Type:      events.EventAuthLoginSuccess,
		Category:  events.CategoryAccessEvent,
		Severity:  events.SeverityInfo,
		Host:      c.cfg.Host,
		Agent:     c.cfg.Agent,
		Actor:     &events.ActorInfo{User: rec.User},
		Context: &events.ContextInfo{
			TTY:      rec.TTY,
			RemoteIP: rec.Host,
		},
		Tags: []string{"auth", "login"},
	}
}

func (c *Collector) makeLogoutEvent(rec parsedRecord) events.Event {
	return events.Event{
		ID:        uuid.New().String(),
		Timestamp: rec.Timestamp,
		Type:      events.EventAuthLogout,
		Category:  events.CategoryAccessEvent,
		Severity:  events.SeverityInfo,
		Host:      c.cfg.Host,
		Agent:     c.cfg.Agent,
		Actor:     &events.ActorInfo{User: rec.User},
		Context: &events.ContextInfo{
			TTY: rec.TTY,
		},
		Tags: []string{"auth", "logout"},
	}
}

// Cursor persistence helpers.

func (c *Collector) cursorPath() string {
	return filepath.Join(c.cfg.StateDir, "wtmp_cursor")
}

func (c *Collector) loadWtmpCursor() (int64, error) {
	data, err := os.ReadFile(c.cursorPath())
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func (c *Collector) saveWtmpCursor(offset int64) {
	_ = os.WriteFile(c.cursorPath(), []byte(strconv.FormatInt(offset, 10)), 0600)
}

// ── auth.log watcher ──────────────────────────────────────────────────────────

// Patterns for lines we care about in auth.log / journal messages.
var (
	// reLoginFailed matches sshd password/pubkey failure lines:
	//   "Failed password for alice from 1.2.3.4 port 22 ssh2"
	//   "Failed password for invalid user alice from 1.2.3.4 port 22 ssh2"
	reLoginFailed = regexp.MustCompile(`Failed (\S+) for (?:invalid user )?(\S+) from ([\d.]+) port \d+`)

	// reInvalidUser matches sshd pre-auth username rejection lines:
	//   "Invalid user admin from 1.2.3.4 port 22"
	// This fires before any password check, so the method is recorded as "preauth".
	reInvalidUser = regexp.MustCompile(`Invalid user (\S+) from ([\d.]+) port \d+`)

	reSudo = regexp.MustCompile(`sudo:\s+(\S+)\s*:.*?COMMAND=(.+)$`)
)

func (c *Collector) runAuthLog(ctx context.Context, out chan<- events.Event) {
	f, err := os.Open(c.cfg.AuthLogPath)
	if err != nil {
		slog.Warn("auth: auth log unavailable, failed-login/sudo events disabled",
			"path", c.cfg.AuthLogPath, "error", err)
		return
	}
	defer f.Close()

	// Seek to end — no history replay.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		slog.Warn("auth: cannot seek auth log", "error", err)
		return
	}

	var prevInode uint64
	if fi, err := f.Stat(); err == nil {
		prevInode = fileInode(fi)
	}

	reader := bufio.NewReader(f)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Detect log rotation.
			if fi, err := os.Stat(c.cfg.AuthLogPath); err == nil {
				if fileInode(fi) != prevInode {
					f.Close()
					f, err = os.Open(c.cfg.AuthLogPath)
					if err != nil {
						slog.Warn("auth: auth log reopen failed after rotation", "error", err)
						return
					}
					reader = bufio.NewReader(f)
					prevInode = fileInode(fi)
				}
			}
			// Read all available new lines. bufio.Reader (unlike bufio.Scanner)
			// does not permanently mark itself done on EOF, so subsequent ticks
			// correctly pick up lines written after the previous read.
			for {
				line, err := reader.ReadString('\n')
				if len(line) > 0 {
					line = strings.TrimRight(line, "\r\n")
					now := time.Now().UTC()
					if ev, ok := c.parseAuthLogLine(line); ok {
						select {
						case out <- ev:
						case <-ctx.Done():
							return
						}
						if ev.Type == events.EventAuthLoginFailed && ev.Actor != nil {
							if bfEv, triggered := c.checkBruteforce(ev.Actor.User, ev.Actor.IP, now); triggered {
								select {
								case out <- bfEv:
								case <-ctx.Done():
									return
								}
							}
						}
					}
				}
				if err != nil {
					// io.EOF means no more data right now; try again next tick.
					break
				}
			}
		}
	}
}

func (c *Collector) parseAuthLogLine(line string) (events.Event, bool) {
	now := time.Now().UTC()

	if m := reLoginFailed.FindStringSubmatch(line); m != nil {
		method, user, ip := m[1], m[2], m[3]
		return events.Event{
			ID:        uuid.New().String(),
			Timestamp: now,
			Type:      events.EventAuthLoginFailed,
			Category:  events.CategoryAccessEvent,
			Severity:  events.SeverityWarning,
			Host:      c.cfg.Host,
			Agent:     c.cfg.Agent,
			Actor: &events.ActorInfo{
				User:   user,
				IP:     ip,
				Method: method,
			},
			Context: &events.ContextInfo{
				Reason:  "invalid_password",
				Service: "sshd",
			},
			Tags: []string{"auth", "failed_login"},
		}, true
	}

	if m := reInvalidUser.FindStringSubmatch(line); m != nil {
		user, ip := m[1], m[2]
		return events.Event{
			ID:        uuid.New().String(),
			Timestamp: now,
			Type:      events.EventAuthLoginFailed,
			Category:  events.CategoryAccessEvent,
			Severity:  events.SeverityWarning,
			Host:      c.cfg.Host,
			Agent:     c.cfg.Agent,
			Actor: &events.ActorInfo{
				User:   user,
				IP:     ip,
				Method: "preauth",
			},
			Context: &events.ContextInfo{
				Reason:  "invalid_user",
				Service: "sshd",
			},
			Tags: []string{"auth", "failed_login"},
		}, true
	}

	if m := reSudo.FindStringSubmatch(line); m != nil {
		user, command := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
		return events.Event{
			ID:        uuid.New().String(),
			Timestamp: now,
			Type:      events.EventAuthSudo,
			Category:  events.CategoryAccessEvent,
			Severity:  events.SeverityWarning,
			Host:      c.cfg.Host,
			Agent:     c.cfg.Agent,
			Actor: &events.ActorInfo{
				User:       user,
				TargetUser: "root",
				Command:    command,
			},
			Tags: []string{"auth", "sudo"},
		}, true
	}

	return events.Event{}, false
}

// ── bruteforce detection ──────────────────────────────────────────────────────

// checkBruteforce records a failed login attempt for (user, remoteIP) and
// returns a bruteforce event if the threshold is crossed.
func (c *Collector) checkBruteforce(user, remoteIP string, now time.Time) (events.Event, bool) {
	if remoteIP == "" {
		return events.Event{}, false
	}
	key := bruteforceKey{RemoteIP: remoteIP, User: user}
	cutoff := now.Add(-c.cfg.BruteforceWindow)

	c.mu.Lock()
	defer c.mu.Unlock()

	entry := c.bfTracker[key]
	if entry == nil {
		entry = &bruteforceEntry{}
		c.bfTracker[key] = entry
	}

	// Prune attempts outside the window.
	j := 0
	for _, t := range entry.attempts {
		if t.After(cutoff) {
			entry.attempts[j] = t
			j++
		}
	}
	entry.attempts = append(entry.attempts[:j], now)

	count := len(entry.attempts)
	slog.Debug("auth: bruteforce window", "ip", remoteIP, "user", user, "attempts", count)

	if count >= c.cfg.BruteforceThreshold && now.After(entry.suppressedUntil) {
		entry.suppressedUntil = now.Add(c.cfg.BruteforceSuppression)
		slog.Warn("auth: bruteforce detected", "ip", remoteIP, "user", user, "attempts", count)
		return events.Event{
			ID:         uuid.New().String(),
			Timestamp:  now,
			Type:       events.EventAuthBruteforceDetected,
			Category:   events.CategoryThreatActivity,
			Severity:   events.SeverityCritical,
			Confidence: events.ConfidenceHigh,
			Host:       c.cfg.Host,
			Agent:      c.cfg.Agent,
			Actor: &events.ActorInfo{
				User: user,
				IP:   remoteIP,
			},
			Context: &events.ContextInfo{
				Reason: "bruteforce",
			},
			Tags: []string{"auth", "bruteforce"},
		}, true
	}
	return events.Event{}, false
}

// gcBruteforceTracker removes stale entries from the bruteforce tracker.
func (c *Collector) gcBruteforceTracker() {
	now := time.Now().UTC()
	cutoff := now.Add(-c.cfg.BruteforceWindow)

	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.bfTracker {
		j := 0
		for _, t := range entry.attempts {
			if t.After(cutoff) {
				entry.attempts[j] = t
				j++
			}
		}
		entry.attempts = entry.attempts[:j]
		if len(entry.attempts) == 0 && now.After(entry.suppressedUntil) {
			delete(c.bfTracker, key)
		}
	}
}

// ── login_new_ip detection ────────────────────────────────────────────────────

// checkNewIP returns a login_new_ip event if the user logged in from an IP
// not seen before.
func (c *Collector) checkNewIP(rec parsedRecord, now time.Time) (events.Event, bool) {
	ip := rec.Host
	if ip == "" {
		return events.Event{}, false
	}
	if c.cfg.IgnorePrivateIP && isPrivateIP(ip) {
		return events.Event{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	prev, known := c.lastIPByUser[rec.User]
	c.lastIPByUser[rec.User] = ip
	saveLastIPByUser(c.cfg.StateDir, c.lastIPByUser)

	if !known || prev == ip {
		return events.Event{}, false
	}

	slog.Warn("auth: login from new IP", "user", rec.User, "previous_ip", prev, "current_ip", ip)
	return events.Event{
		ID:         uuid.New().String(),
		Timestamp:  now,
		Type:       events.EventAuthLoginNewIP,
		Category:   events.CategoryThreatActivity,
		Severity:   events.SeverityWarning,
		Confidence: events.ConfidenceMedium,
		Host:       c.cfg.Host,
		Agent:      c.cfg.Agent,
		Actor: &events.ActorInfo{
			User: rec.User,
			IP:   ip,
		},
		Context: &events.ContextInfo{
			RemoteIP: prev,
			Reason:   "new_ip",
		},
		Tags: []string{"auth", "new_ip"},
	}, true
}

// ── login-IP state persistence ────────────────────────────────────────────────

func lastIPPath(stateDir string) string {
	return filepath.Join(stateDir, "auth_last_ip.json")
}

func loadLastIPByUser(stateDir string) map[string]string {
	data, err := os.ReadFile(lastIPPath(stateDir))
	if err != nil {
		return make(map[string]string)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return make(map[string]string)
	}
	return m
}

func saveLastIPByUser(stateDir string, m map[string]string) {
	if stateDir == "" {
		return
	}
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	path := lastIPPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// ── private IP helper ─────────────────────────────────────────────────────────

var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, n, _ := net.ParseCIDR(cidr)
		if n != nil {
			privateNets = append(privateNets, n)
		}
	}
}

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() {
		return true
	}
	for _, n := range privateNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
