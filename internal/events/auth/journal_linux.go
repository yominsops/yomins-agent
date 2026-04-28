//go:build linux

package auth

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"time"

	"github.com/yominsops/yomins-agent/internal/events"
)

// journalEntry holds the fields we need from a journald JSON record.
type journalEntry struct {
	// MESSAGE is the raw log message without any program-name prefix.
	Message string `json:"MESSAGE"`
	// Comm is the process name (_COMM field), e.g. "sshd" or "sudo".
	Comm string `json:"_COMM"`
}

// runJournalLog reads failed-login and sudo events from the systemd journal by
// spawning journalctl as a subprocess. It is used as a fallback when neither
// /var/log/auth.log nor /var/log/secure is present (common on systems without
// rsyslog/syslog-ng).
//
// The service unit must include SupplementaryGroups=systemd-journal so the
// agent user can read the system journal without root.
func (c *Collector) runJournalLog(ctx context.Context, out chan<- events.Event) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		slog.Warn("auth: journalctl not found, failed-login/sudo events disabled")
		return
	}

	// -f         : follow (stream new entries as they arrive)
	// -n 0       : start from now; do not replay historical entries
	// -o json    : one JSON object per line; gives us _COMM for routing
	// _COMM=sshd : sshd log lines (failed logins)
	// +          : logical OR
	// _COMM=sudo : sudo execution lines
	cmd := exec.CommandContext(ctx, "journalctl",
		"-f", "-n", "0",
		"-o", "json",
		"_COMM=sshd", "+", "_COMM=sudo",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		slog.Warn("auth: cannot create journalctl stdout pipe", "error", err)
		return
	}

	if err := cmd.Start(); err != nil {
		slog.Warn("auth: cannot start journalctl, failed-login/sudo events disabled", "error", err)
		return
	}
	defer cmd.Wait() //nolint:errcheck

	slog.Info("auth: using journald for failed-login/sudo events (no auth.log found)")

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		now := time.Now().UTC()
		if ev, ok := c.parseJournalLine(scanner.Text()); ok {
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
}

// parseJournalLine decodes a single journald JSON line and routes it through
// the existing parseAuthLogLine regexes.
//
// Sudo journal MESSAGE fields lack the "sudo: " program-name prefix that
// auth.log lines carry (syslogd adds it, but the journal stores the raw
// message). Prepending "sudo: " makes the existing reSudo regex match without
// any additional changes.
func (c *Collector) parseJournalLine(line string) (events.Event, bool) {
	var entry journalEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return events.Event{}, false
	}

	msg := entry.Message
	if entry.Comm == "sudo" {
		msg = "sudo: " + msg
	}
	return c.parseAuthLogLine(msg)
}
