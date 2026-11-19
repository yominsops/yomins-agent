//go:build linux

package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/events"
)

func newTestCollector(t *testing.T) *Collector {
	t.Helper()
	c := NewCollector(Config{StateDir: t.TempDir(), IgnorePrivateIP: true})
	c.journalUsable = func() bool { return false }
	return c
}

// Lines as sshd and sudo write them: through rsyslog on Debian/Ubuntu
// (auth.log) and RHEL (secure), with OpenSSH 9.8+'s sshd-session, and IPv6.
func TestParseAuthLogLine(t *testing.T) {
	cases := []struct {
		line   string
		typ    events.EventType
		user   string
		ip     string
		method string
	}{
		{"2026-11-19T13:34:09.257Z host sshd[812]: Failed password for alice from 203.0.113.5 port 43192 ssh2", events.EventAuthLoginFailed, "alice", "203.0.113.5", "password"},
		{"Nov 19 13:34:09 host sshd-session[812]: Failed password for root from 2001:db8::7 port 22 ssh2", events.EventAuthLoginFailed, "root", "2001:db8::7", "password"},
		{"Nov 19 13:34:09 host sshd-session[812]: Invalid user hacker from 198.51.100.9 port 54888", events.EventAuthLoginFailed, "hacker", "198.51.100.9", "preauth"},
		{"Nov 19 13:34:09 host sshd[812]: Invalid user  from 198.51.100.9 port 54888", events.EventAuthLoginFailed, "", "198.51.100.9", "preauth"},
		{"Nov 19 13:34:10 host sshd-session[900]: Accepted publickey for alice from 2001:db8::7 port 41234 ssh2: ED25519 SHA256:abc", events.EventAuthLoginSuccess, "alice", "2001:db8::7", "publickey"},
		{"Nov 19 13:34:10 host sshd[900]: Accepted password for deploy from 203.0.113.5 port 41234 ssh2", events.EventAuthLoginSuccess, "deploy", "203.0.113.5", "password"},
		{"Nov 19 16:50:51 host sshd-session[900]: Disconnected from user alice 2001:db8::7 port 41919", events.EventAuthLogout, "alice", "2001:db8::7", ""},
		{"Nov 19 16:41:02 host sshd-session[901]: Connection closed by authenticating user root 94.177.195.107 port 30329 [preauth]", events.EventAuthLoginFailed, "root", "94.177.195.107", "publickey"},
		{"Nov 19 16:41:03 host sshd-session[902]: Disconnected from authenticating user root 94.177.195.108 port 30330 [preauth]", events.EventAuthLoginFailed, "root", "94.177.195.108", "publickey"},
		{"Nov 19 13:34:11 host sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id", events.EventAuthSudo, "alice", "", ""},
	}
	c := newTestCollector(t)
	for _, tc := range cases {
		ev, ok := c.parseAuthLogLine(tc.line)
		if !ok {
			t.Errorf("%q: not parsed", tc.line)
			continue
		}
		if ev.Type != tc.typ || ev.Actor == nil || ev.Actor.User != tc.user || ev.Actor.IP != tc.ip || ev.Actor.Method != tc.method {
			t.Errorf("%q: got %s %+v", tc.line, ev.Type, ev.Actor)
		}
	}
}

// A user that does not exist logs "Invalid user" and then "Failed password
// for invalid user" for each password: one connection is one failure, not two.
func TestParseAuthLogLine_InvalidUserCountedOnce(t *testing.T) {
	c := newTestCollector(t)
	n := 0
	for _, line := range []string{
		"sshd[1]: Invalid user hacker from 198.51.100.9 port 54888",
		"sshd[1]: pam_unix(sshd:auth): check pass; user unknown",
		"sshd[1]: Failed password for invalid user hacker from 198.51.100.9 port 54888 ssh2",
		"sshd[1]: Connection closed by invalid user hacker 198.51.100.9 port 54888 [preauth]",
		"sudo: pam_unix(sudo:session): session closed for user root",
	} {
		if _, ok := c.parseAuthLogLine(line); ok {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d events, want 1", n)
	}
}

func TestParseJournalLine(t *testing.T) {
	c := newTestCollector(t)
	ev, ok := c.parseJournalLine(`{"MESSAGE":"Failed password for alice from 203.0.113.5 port 1 ssh2","_COMM":"sshd-session"}`)
	if !ok || ev.Type != events.EventAuthLoginFailed {
		t.Fatalf("sshd-session line: %v %v", ok, ev.Type)
	}
	ev, ok = c.parseJournalLine(`{"MESSAGE":"alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id","_COMM":"sudo"}`)
	if !ok || ev.Type != events.EventAuthSudo || ev.Actor.Command != "/usr/bin/id" {
		t.Fatalf("sudo line: %v %+v", ok, ev.Actor)
	}
}

func TestSend_NewIPAfterAcceptedLogin(t *testing.T) {
	c := newTestCollector(t)
	out := make(chan events.Event, 10)
	ctx := context.Background()
	now := time.Now()
	for _, line := range []string{
		"sshd[1]: Accepted publickey for alice from 203.0.113.5 port 1 ssh2",
		"sshd[2]: Accepted publickey for alice from 2001:db8::7 port 1 ssh2",
	} {
		ev, _ := c.parseAuthLogLine(line)
		c.send(ctx, out, ev, now)
	}
	close(out)
	var types []events.EventType
	for e := range out {
		types = append(types, e.Type)
	}
	want := []events.EventType{events.EventAuthLoginSuccess, events.EventAuthLoginSuccess, events.EventAuthLoginNewIP}
	if len(types) != len(want) {
		t.Fatalf("got %v", types)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("got %v", types)
		}
	}
}

func TestSend_Bruteforce(t *testing.T) {
	c := newTestCollector(t)
	out := make(chan events.Event, 20)
	now := time.Now()
	for i := 0; i < 5; i++ {
		ev, _ := c.parseAuthLogLine("sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2")
		c.send(context.Background(), out, ev, now.Add(time.Duration(i)*time.Second))
	}
	close(out)
	bf := 0
	for e := range out {
		if e.Type == events.EventAuthBruteforceDetected {
			bf++
		}
	}
	if bf != 1 {
		t.Errorf("%d bruteforce events, want 1", bf)
	}
}

func TestIsPrivateIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"10.1.2.3": true, "172.17.0.3": true, "192.168.1.1": true, "127.0.0.1": true,
		"::1": true, "fd00::1": true, "fe80::1": true,
		"203.0.113.5": false, "2001:db8::7": false, "not-an-ip": false,
	} {
		if got := isPrivateIP(ip); got != want {
			t.Errorf("%s: %v", ip, got)
		}
	}
}

func TestAuthSource(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "none.log")
	for _, tc := range []struct {
		path    string
		set     bool
		journal bool
		want    string
	}{
		{file, false, true, "journal"}, // the file exists, the journal is still preferred
		{file, true, true, "file"},     // a configured file wins
		{file, false, false, "file"},   // no readable journal (container)
		{missing, true, true, "journal"},
		{missing, false, false, "journal"},
	} {
		c := NewCollector(Config{StateDir: dir, AuthLogPath: tc.path, AuthLogPathSet: tc.set})
		j := tc.journal
		c.journalUsable = func() bool { return j }
		if got := c.authSource(); got != tc.want {
			t.Errorf("%+v: %s", tc, got)
		}
	}
}

func TestReportedFromLog(t *testing.T) {
	c := newTestCollector(t)
	ssh := parsedRecord{User: "alice", TTY: "pts/0", Host: "203.0.113.5"}
	console := parsedRecord{User: "root", TTY: "tty1"}
	if c.reportedFromLog(ssh) || c.reportedFromLog(console) {
		t.Fatal("wtmp is the only source until sshd's messages are read")
	}
	c.sshFromLog.Store(true)
	if !c.reportedFromLog(ssh) || c.reportedFromLog(console) {
		t.Fatal("with sshd's messages, wtmp reports only console sessions")
	}
}

// A connection whose passwords failed also ends with "Connection closed by
// authenticating user …": it is one failure per password, not one more.
func TestParseAuthLogLine_ClosedAfterFailedPassword(t *testing.T) {
	c := newTestCollector(t)
	n := 0
	for _, line := range []string{
		"sshd[1]: Failed password for alice from 203.0.113.5 port 43192 ssh2",
		"sshd[1]: Failed password for alice from 203.0.113.5 port 43192 ssh2",
		"sshd[1]: Connection closed by authenticating user alice 203.0.113.5 port 43192 [preauth]",
		"sshd[2]: Connection closed by authenticating user alice 203.0.113.5 port 43200 [preauth]", // another connection, keys only
		"sshd[3]: Connection closed by 203.0.113.5 port 43300 [preauth]",                           // no user: not an attempt
	} {
		if _, ok := c.parseAuthLogLine(line); ok {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d failures, want 3", n)
	}
}
