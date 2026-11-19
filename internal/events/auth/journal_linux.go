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

	// -f    : follow (stream new entries as they arrive)
	// -n 0  : start from now; do not replay historical entries
	// -o json: one JSON object per line; gives us _COMM for routing
	// The matches on one field are OR-ed. OpenSSH 9.8 split sshd: the
	// per-connection process that logs logins is sshd-session (and since
	// 10.0 sshd-auth for authentication), on Debian 13, Ubuntu 25.04+,
	// Fedora 41+, RHEL 9.6+/10 and their rebuilds.
	cmd := exec.CommandContext(ctx, "journalctl",
		"-f", "-n", "0",
		"-o", "json",
		"_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth", "_COMM=sudo",
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

	c.sshFromLog.Store(true)
	slog.Info("auth: reading sshd and sudo messages from the journal")

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		if ev, ok := c.parseJournalLine(scanner.Text()); ok {
			if !c.send(ctx, out, ev, time.Now().UTC()) {
				return
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
