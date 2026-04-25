//go:build linux

package system

import (
	"bufio"
	"os"
	"regexp"
)

// reOOMKiller matches the standard OOM killer log line format.
// Example: "Killed process 1234 (bash) total-vm:204800kB, anon-rss:8192kB"
var reOOMKiller = regexp.MustCompile(
	`Killed process (\d+) \(([^)]+)\) total-vm:(\d+)kB, anon-rss:(\d+)kB`,
)

// oomKilledEvent holds the parsed fields from an OOM killer log line.
type oomKilledEvent struct {
	PID        string
	ProcessName string
	TotalVMKB  string
	AnonRSSKB  string
	RawLine    string
}

// openKmsg opens /dev/kmsg for reading. Returns an error if unavailable
// (e.g. missing CAP_SYSLOG or running in a restricted container).
func openKmsg() (*os.File, error) {
	return os.Open("/dev/kmsg")
}

// drainKmsg reads and discards all currently available lines from the scanner.
// This is used on startup to skip kernel messages that pre-date the agent.
func drainKmsg(scanner *bufio.Scanner) {
	// /dev/kmsg is non-blocking when opened with O_RDONLY; Read returns 0 bytes
	// at EOF instead of blocking. We drain until there are no more records.
	// bufio.Scanner will return false when it hits EOF.
	for scanner.Scan() {
		// discard
	}
}

// parseOOMLine attempts to extract OOM killer info from a single kmsg line.
// Returns (event, true) if the line matches; (zero, false) otherwise.
func parseOOMLine(line string) (oomKilledEvent, bool) {
	m := reOOMKiller.FindStringSubmatch(line)
	if m == nil {
		return oomKilledEvent{}, false
	}
	return oomKilledEvent{
		PID:         m[1],
		ProcessName: m[2],
		TotalVMKB:   m[3],
		AnonRSSKB:   m[4],
		RawLine:     line,
	}, true
}
