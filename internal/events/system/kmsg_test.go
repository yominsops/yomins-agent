//go:build linux

package system

import (
	"testing"
)

// ── parseOOMLine ─────────────────────────────────────────────────────────────

func TestParseOOMLine_ValidLine(t *testing.T) {
	line := "6,1234,567890,-;Killed process 4567 (stress) total-vm:204800kB, anon-rss:102400kB, file-rss:0kB, shmem-rss:0kB"
	ev, ok := parseOOMLine(line)
	if !ok {
		t.Fatal("parseOOMLine returned ok=false for valid line")
	}
	if ev.PID != "4567" {
		t.Errorf("PID = %q, want 4567", ev.PID)
	}
	if ev.ProcessName != "stress" {
		t.Errorf("ProcessName = %q, want stress", ev.ProcessName)
	}
	if ev.TotalVMKB != "204800" {
		t.Errorf("TotalVMKB = %q, want 204800", ev.TotalVMKB)
	}
	if ev.AnonRSSKB != "102400" {
		t.Errorf("AnonRSSKB = %q, want 102400", ev.AnonRSSKB)
	}
	if ev.RawLine != line {
		t.Errorf("RawLine = %q, want full line", ev.RawLine)
	}
}

func TestParseOOMLine_PlainKernelFormat(t *testing.T) {
	// /dev/kmsg lines often have a prefix stripped by the scanner. Test the
	// bare pattern that appears after prefix removal.
	line := "Killed process 1234 (oom-test) total-vm:8192kB, anon-rss:4096kB"
	ev, ok := parseOOMLine(line)
	if !ok {
		t.Fatal("parseOOMLine returned ok=false")
	}
	if ev.PID != "1234" {
		t.Errorf("PID = %q, want 1234", ev.PID)
	}
	if ev.ProcessName != "oom-test" {
		t.Errorf("ProcessName = %q, want oom-test", ev.ProcessName)
	}
}

func TestParseOOMLine_LargePID(t *testing.T) {
	line := "Killed process 4194304 (bigpid) total-vm:1048576kB, anon-rss:524288kB"
	ev, ok := parseOOMLine(line)
	if !ok {
		t.Fatal("parseOOMLine returned ok=false for large PID")
	}
	if ev.PID != "4194304" {
		t.Errorf("PID = %q, want 4194304", ev.PID)
	}
}

func TestParseOOMLine_LargeMemoryValues(t *testing.T) {
	line := "Killed process 999 (leaker) total-vm:67108864kB, anon-rss:33554432kB"
	ev, ok := parseOOMLine(line)
	if !ok {
		t.Fatal("parseOOMLine returned ok=false for large memory")
	}
	if ev.TotalVMKB != "67108864" {
		t.Errorf("TotalVMKB = %q, want 67108864", ev.TotalVMKB)
	}
	if ev.AnonRSSKB != "33554432" {
		t.Errorf("AnonRSSKB = %q, want 33554432", ev.AnonRSSKB)
	}
}

func TestParseOOMLine_ProcessNameWithHyphen(t *testing.T) {
	line := "Killed process 100 (my-service) total-vm:1024kB, anon-rss:512kB"
	ev, ok := parseOOMLine(line)
	if !ok {
		t.Fatal("parseOOMLine returned ok=false for hyphenated process name")
	}
	if ev.ProcessName != "my-service" {
		t.Errorf("ProcessName = %q, want my-service", ev.ProcessName)
	}
}

func TestParseOOMLine_NonMatchingLines(t *testing.T) {
	nonMatching := []string{
		"",
		"Out of memory: Kill process 1234 stress", // different format
		"Killed 1234 total-vm:0kB",                // missing parens
		"OOM killer invoked",
		"Linux kernel log line",
		"process 1234 (app) killed",   // wrong verb order
		"Killed process (app) total-vm:0kB, anon-rss:0kB", // missing PID
	}

	for _, line := range nonMatching {
		_, ok := parseOOMLine(line)
		if ok {
			t.Errorf("parseOOMLine(%q): expected ok=false, got ok=true", line)
		}
	}
}

func TestParseOOMLine_ZeroMemory(t *testing.T) {
	line := "Killed process 1 (init) total-vm:0kB, anon-rss:0kB"
	ev, ok := parseOOMLine(line)
	if !ok {
		t.Fatal("parseOOMLine returned ok=false for zero memory values")
	}
	if ev.TotalVMKB != "0" {
		t.Errorf("TotalVMKB = %q, want 0", ev.TotalVMKB)
	}
	if ev.AnonRSSKB != "0" {
		t.Errorf("AnonRSSKB = %q, want 0", ev.AnonRSSKB)
	}
}

func TestParseOOMLine_RealKernelLogFormat(t *testing.T) {
	// Real /dev/kmsg line format: "priority,seqnum,timestamp,-;message"
	cases := []struct {
		line      string
		wantMatch bool
		wantPID   string
		wantName  string
	}{
		{
			line:      "3,12345,98765432,-;Killed process 5678 (java) total-vm:4194304kB, anon-rss:2097152kB",
			wantMatch: true,
			wantPID:   "5678",
			wantName:  "java",
		},
		{
			line:      "kernel: oom-killer: gfp_mask=0x14200ca, order=0",
			wantMatch: false,
		},
		{
			line:      "kernel: Out of memory: Kill process 1234 (bash) score 900 or sacrifice child",
			wantMatch: false, // different OOM format, not our pattern
		},
	}

	for _, tc := range cases {
		ev, ok := parseOOMLine(tc.line)
		if ok != tc.wantMatch {
			t.Errorf("parseOOMLine(%q): ok=%v, want %v", tc.line, ok, tc.wantMatch)
			continue
		}
		if tc.wantMatch {
			if ev.PID != tc.wantPID {
				t.Errorf("PID = %q, want %q", ev.PID, tc.wantPID)
			}
			if ev.ProcessName != tc.wantName {
				t.Errorf("ProcessName = %q, want %q", ev.ProcessName, tc.wantName)
			}
		}
	}
}

// ── regex consistency ─────────────────────────────────────────────────────────

func TestOOMRegex_CaptureGroupCount(t *testing.T) {
	// The regex must have exactly 4 capture groups: PID, name, totalVM, anonRSS.
	m := reOOMKiller.FindStringSubmatch("Killed process 1 (foo) total-vm:1kB, anon-rss:1kB")
	if len(m) != 5 { // full match + 4 groups
		t.Errorf("capture groups = %d, want 5 (full match + 4 groups)", len(m))
	}
}
