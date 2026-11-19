//go:build linux

package system

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/yominsops/yomins-agent/internal/events"
)

// hwPattern turns a kernel message into a hardware error: kind, the device
// (submatch dev, or a fixed name) and how bad it is.
type hwPattern struct {
	kind     string
	re       *regexp.Regexp
	dev      int    // submatch with the device, 0 for none
	fixedDev string // when dev is 0
	severity events.Severity
}

// hwPatterns are the kernel's own words for failing hardware, as block,
// filesystem, md, nvme, libata, EDAC and MCE code print them (Linux 4.x–6.x).
var hwPatterns = []hwPattern{
	// md first: "md/raid1:md0: Disk failure on sdb1, disabling device."
	{kind: "raid_disk_failed", re: regexp.MustCompile(`md/raid\d*:(md\w+): Disk failure on (\S+?),`), dev: 1, severity: events.SeverityCritical},
	{kind: "disk_io", re: regexp.MustCompile(`(?:I/O|critical medium|critical target|critical nexus) error, dev (\w+), sector`), dev: 1, severity: events.SeverityWarning},
	{kind: "disk_io", re: regexp.MustCompile(`Buffer I/O error on dev (\w+),`), dev: 1, severity: events.SeverityWarning},
	{kind: "filesystem_readonly", re: regexp.MustCompile(`EXT[234]-fs \(([\w.-]+)\): Remounting filesystem read-only`), dev: 1, severity: events.SeverityCritical},
	{kind: "filesystem_error", re: regexp.MustCompile(`EXT[234]-fs error \(device ([\w.-]+)\)`), dev: 1, severity: events.SeverityCritical},
	{kind: "filesystem_error", re: regexp.MustCompile(`XFS \(([\w.-]+)\): (?:.*Corruption|metadata I/O error|.*[Ss]hutting down filesystem|Filesystem has been shut down)`), dev: 1, severity: events.SeverityCritical},
	{kind: "filesystem_error", re: regexp.MustCompile(`BTRFS (?:error|critical) \(device ([\w.-]+)`), dev: 1, severity: events.SeverityCritical},
	{kind: "nvme", re: regexp.MustCompile(`nvme (nvme\d+): (?:controller is down|Removing after probe failure|Device not ready|I/O \d+ (?:\(\w+\) )?QID \d+ timeout)`), dev: 1, severity: events.SeverityWarning},
	{kind: "ata", re: regexp.MustCompile(`(ata\d+)(?:\.\d+)?: failed command:`), dev: 1, severity: events.SeverityWarning},
	{kind: "memory_ecc", re: regexp.MustCompile(`EDAC (MC\d+): \d+ UE`), dev: 1, severity: events.SeverityCritical},
	{kind: "memory_ecc", re: regexp.MustCompile(`EDAC (MC\d+): \d+ CE`), dev: 1, severity: events.SeverityWarning},
	{kind: "mce", re: regexp.MustCompile(`\[Hardware Error\]`), fixedDev: "cpu", severity: events.SeverityCritical},
}

type hwError struct {
	kind, device, message string
	severity              events.Severity
}

// kmsgText is the message of a /dev/kmsg record ("6,1234,5678,-;text").
func kmsgText(line string) string {
	if i := strings.IndexByte(line, ';'); i >= 0 && i < 40 && !strings.ContainsAny(line[:i], " \t") {
		return line[i+1:]
	}
	return line
}

func parseHardwareLine(line string) (hwError, bool) {
	msg := kmsgText(line)
	if msg == "" || msg[0] == ' ' { // continuation lines (KEY=value)
		return hwError{}, false
	}
	for _, p := range hwPatterns {
		m := p.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		dev := p.fixedDev
		if p.dev > 0 {
			dev = m[p.dev]
		}
		if p.kind == "memory_ecc" {
			dev = strings.ToLower(dev)
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return hwError{kind: p.kind, device: dev, message: strings.TrimSpace(msg), severity: p.severity}, true
	}
	return hwError{}, false
}

// hwLimiter lets one event per kind and device through an hour: a failing
// disk logs an I/O error for every read. The next one says how many were
// held back.
type hwLimiter struct {
	mu     sync.Mutex
	window time.Duration
	last   map[string]time.Time
	held   map[string]int
}

func newHWLimiter(window time.Duration) *hwLimiter {
	return &hwLimiter{window: window, last: map[string]time.Time{}, held: map[string]int{}}
}

// allow reports whether to send, and how many were held back before it.
func (l *hwLimiter) allow(key string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[key]; ok && now.Sub(t) < l.window {
		l.held[key]++
		return false, 0
	}
	n := l.held[key]
	l.last[key] = now
	delete(l.held, key)
	return true, n
}

func (c *Collector) hardwareEvent(line string, now time.Time) (events.Event, bool) {
	hw, ok := parseHardwareLine(line)
	if !ok {
		return events.Event{}, false
	}
	if c.hwLimit == nil {
		c.hwLimit = newHWLimiter(time.Hour)
	}
	send, held := c.hwLimit.allow(hw.kind+"/"+hw.device, now)
	if !send {
		return events.Event{}, false
	}
	reason := hw.message
	if held > 0 {
		reason = fmt.Sprintf("%s (and %d more like it since the previous report)", reason, held)
	}
	return events.Event{
		ID:         uuid.New().String(),
		Timestamp:  now.UTC(),
		Type:       events.EventSystemHardwareError,
		Category:   events.CategorySystemCheck,
		Severity:   hw.severity,
		Confidence: events.ConfidenceHigh,
		Host:       c.cfg.Host,
		Agent:      c.cfg.Agent,
		Context:    &events.ContextInfo{Reason: reason, Service: hw.device},
		Tags:       []string{"system", "hardware", hw.kind, hw.device},
	}, true
}
