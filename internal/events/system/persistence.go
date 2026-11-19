//go:build linux

package system

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yominsops/yomins-agent/internal/events"
)

// watchSpec is a group of files an intruder changes to keep access or to
// raise it: the places a backdoor survives a reboot or a password change.
type watchSpec struct {
	Kind     string // tag and the name in the portal: "authorized_keys", "cron", …
	Type     events.EventType
	Severity events.Severity
	Globs    []string
}

// persistenceSpecs are watched in addition to the five files of
// defaultMonitoredFiles. Paths differ by distribution (user crontabs are in
// /var/spool/cron on RHEL and /var/spool/cron/crontabs on Debian; rc.local
// in /etc/rc.d on RHEL), so both are listed: a glob that matches nothing
// costs nothing.
var persistenceSpecs = []watchSpec{
	// Drop-ins of the files the config watch already covers.
	{Kind: "sudoers", Type: events.EventSystemConfigModified, Severity: events.SeverityCritical,
		Globs: []string{"/etc/sudoers.d/*"}},
	{Kind: "sshd_config", Type: events.EventSystemConfigModified, Severity: events.SeverityCritical,
		Globs: []string{"/etc/ssh/sshd_config.d/*"}},
	{Kind: "pam", Type: events.EventSystemConfigModified, Severity: events.SeverityCritical,
		Globs: []string{"/etc/pam.d/*", "/etc/security/access.conf"}},

	// Persistence.
	{Kind: "authorized_keys", Type: events.EventSystemPersistence, Severity: events.SeverityCritical,
		Globs: []string{"/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2", "/home/*/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys2"}},
	{Kind: "ld_preload", Type: events.EventSystemPersistence, Severity: events.SeverityCritical,
		Globs: []string{"/etc/ld.so.preload"}},
	{Kind: "cron", Type: events.EventSystemPersistence, Severity: events.SeverityWarning,
		Globs: []string{"/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
			"/var/spool/cron/*", "/var/spool/cron/crontabs/*", "/etc/anacrontab"}},
	{Kind: "systemd_unit", Type: events.EventSystemPersistence, Severity: events.SeverityWarning,
		Globs: []string{"/etc/systemd/system/*.service", "/etc/systemd/system/*.timer", "/etc/systemd/system/*.socket", "/etc/systemd/system/*.path",
			"/etc/systemd/system/*.d/*.conf"}},
	{Kind: "rc_local", Type: events.EventSystemPersistence, Severity: events.SeverityWarning,
		Globs: []string{"/etc/rc.local", "/etc/rc.d/rc.local"}},
	{Kind: "shell_profile", Type: events.EventSystemPersistence, Severity: events.SeverityWarning,
		Globs: []string{"/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bashrc", "/etc/environment"}},
}

const (
	maxWatchedFiles = 5000    // shared hosting has thousands of homes
	maxWatchedSize  = 1 << 20 // larger files are tracked by size and time only
)

// watchState is what the persistence watch remembers between runs.
type watchState struct {
	// Baselined are the specs whose files are known: a spec seen for the
	// first time (a new install, or a spec added by an upgrade) reports
	// nothing, it records what is there.
	Baselined map[string]bool        `json:"baselined"`
	Files     map[string]watchedFile `json:"files"`
}

type watchedFile struct {
	Kind    string `json:"kind"`
	Hash    string `json:"hash"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mod_time"`
}

// expand lists the regular files the spec's globs match now, sorted.
func (s watchSpec) expand(root string) []string {
	var out []string
	for _, g := range s.Globs {
		matches, _ := filepath.Glob(filepath.Join(root, g))
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.Mode().IsRegular() {
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

// fileSnapshot reads one file's identity. The hash is computed only when
// the size or the modification time changed since prev.
func fileSnapshot(path, kind string, prev *watchedFile) (watchedFile, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return watchedFile{}, err
	}
	w := watchedFile{Kind: kind, Size: fi.Size(), ModTime: fi.ModTime().UnixNano()}
	if prev != nil && prev.Size == w.Size && prev.ModTime == w.ModTime {
		w.Hash = prev.Hash
		return w, nil
	}
	if fi.Size() > maxWatchedSize {
		w.Hash = fmt.Sprintf("size:%d", fi.Size())
		return w, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return watchedFile{}, err
	}
	defer f.Close() //nolint:errcheck
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return watchedFile{}, err
	}
	w.Hash = fmt.Sprintf("%x", h.Sum(nil))
	return w, nil
}

// fileChange is one difference between two scans.
type fileChange struct {
	spec   watchSpec
	path   string
	change string // added, modified, removed
}

// scanPersistence compares the files of specs now with st, updates st and
// returns the changes. root prefixes every glob (tests).
func scanPersistence(root string, specs []watchSpec, st *watchState) []fileChange {
	if st.Baselined == nil {
		st.Baselined = map[string]bool{}
	}
	if st.Files == nil {
		st.Files = map[string]watchedFile{}
	}
	var changes []fileChange
	budget := maxWatchedFiles
	for _, spec := range specs {
		baselined := st.Baselined[spec.Kind+"|"+strings.Join(spec.Globs, ",")]
		seen := map[string]bool{}
		for _, p := range spec.expand(root) {
			if budget == 0 {
				break
			}
			budget--
			seen[p] = true
			prev, known := st.Files[p]
			var prevp *watchedFile
			if known {
				prevp = &prev
			}
			cur, err := fileSnapshot(p, spec.Kind, prevp)
			if err != nil {
				continue // unreadable now: keep what was known
			}
			switch {
			case !known && baselined:
				changes = append(changes, fileChange{spec, p, "added"})
			case known && cur.Hash != prev.Hash:
				changes = append(changes, fileChange{spec, p, "modified"})
			}
			st.Files[p] = cur
		}
		for p, f := range st.Files {
			if f.Kind == spec.Kind && !seen[p] {
				if _, err := os.Lstat(p); os.IsNotExist(err) {
					changes = append(changes, fileChange{spec, p, "removed"})
					delete(st.Files, p)
				}
			}
		}
		st.Baselined[spec.Kind+"|"+strings.Join(spec.Globs, ",")] = true
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].path < changes[j].path })
	return changes
}

// changeEvent turns a change into an event. The path goes in context.reason,
// as for system.config_modified; the kind and the change are tags; for an
// authorized_keys file the actor is the account it lets in.
func (c *Collector) changeEvent(ch fileChange, now time.Time, root string) events.Event {
	path := strings.TrimPrefix(ch.path, strings.TrimSuffix(root, "/"))
	ev := events.Event{
		ID:         uuid.New().String(),
		Timestamp:  now.UTC(),
		Type:       ch.spec.Type,
		Category:   events.CategoryThreatActivity,
		Severity:   ch.spec.Severity,
		Confidence: events.ConfidenceHigh,
		Host:       c.cfg.Host,
		Agent:      c.cfg.Agent,
		Context:    &events.ContextInfo{Reason: path},
		Tags:       []string{"system", "persistence", ch.spec.Kind, ch.change},
	}
	if ch.spec.Type == events.EventSystemConfigModified {
		ev.Tags[1] = "config_modified"
	}
	// Package upgrades rewrite pam.d, cron.daily and profile.d too. A change
	// made while the package database was being written is still reported,
	// as information rather than a threat.
	if c.packageActivity(root, now) {
		ev.Severity, ev.Confidence = events.SeverityInfo, events.ConfidenceLow
		ev.Tags = append(ev.Tags, "package_manager")
	}
	if ch.spec.Kind == "authorized_keys" {
		user := "root"
		if strings.HasPrefix(path, "/home/") {
			user = strings.SplitN(strings.TrimPrefix(path, "/home/"), "/", 2)[0]
		}
		ev.Actor = &events.ActorInfo{User: user}
	}
	return ev
}

// packageDatabases are where dpkg and rpm record installed packages.
var packageDatabases = []string{
	"/var/lib/dpkg/status",
	"/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages",
	"/usr/lib/sysimage/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/Packages",
}

// packageWindow is how long after the package database changed a file
// change is put down to the package manager.
const packageWindow = 10 * time.Minute

func (c *Collector) packageActivity(root string, now time.Time) bool {
	for _, db := range packageDatabases {
		if fi, err := os.Stat(filepath.Join(root, db)); err == nil && now.Sub(fi.ModTime()) < packageWindow {
			return true
		}
	}
	return false
}

func (c *Collector) persistenceStatePath() string {
	return filepath.Join(c.cfg.StateDir, "persistence_state.json")
}

func (c *Collector) loadWatchState() watchState {
	var st watchState
	if data, err := os.ReadFile(c.persistenceStatePath()); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

func (c *Collector) saveWatchState(st watchState) {
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp := c.persistenceStatePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, c.persistenceStatePath())
}

// pollPersistence scans the persistence specs every 30 s.
func (c *Collector) pollPersistence(ctx context.Context, out chan<- events.Event) {
	st := c.loadWatchState()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	// The first scan runs at once: it reports what changed while the agent
	// was not running (and records what is there for a spec seen first).
	now := time.Now()
	for {
		for _, ch := range scanPersistence("", persistenceSpecs, &st) {
			slog.Warn("system: file changed", "kind", ch.spec.Kind, "change", ch.change, "path", ch.path)
			select {
			case out <- c.changeEvent(ch, now, ""):
			case <-ctx.Done():
				return
			}
		}
		c.saveWatchState(st)
		select {
		case <-ctx.Done():
			return
		case now = <-ticker.C:
		}
	}
}
