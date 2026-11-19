package collector

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// UpdatesCollector reports pending package updates (security ones apart)
// and whether a reboot is needed: a patched kernel or library is not in use
// until then. Package managers are slow, so wrap it with Every.
//
// apt (Debian, Ubuntu), dnf 4 and dnf 5 (RHEL and its rebuilds, Fedora,
// Amazon Linux) and zypper (SUSE) are read from their caches; refreshing
// them needs root and is left to unattended-upgrades, dnf-automatic or the
// distribution's own timer.
type UpdatesCollector struct {
	paths   HostPaths
	run     cmdRunner
	lookup  func(string) (string, error)
	release func() string
	// workDir is where dnf 5 may keep its per-user state: the agent's
	// user has no home and the service unit allows writes only under its
	// state directory, and dnf 5 fails outright when it cannot create one.
	workDir string
}

// cmdResult is the outcome of an external command: its standard output,
// its exit code, and err when it could not be run at all.
type cmdResult struct {
	out  []byte
	code int
	err  error
}

// cmdRunner runs a command with extra environment variables; tests replace it.
type cmdRunner func(ctx context.Context, env []string, name string, args ...string) cmdResult

func execCmd(ctx context.Context, env []string, name string, args ...string) cmdResult {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return cmdResult{out: out, code: exit.ExitCode()}
	}
	return cmdResult{out: out, err: err}
}

// NewUpdatesCollector creates the collector. stateDir is the agent's state
// directory (package managers keep their per-user files under it).
func NewUpdatesCollector(paths HostPaths, stateDir string) *UpdatesCollector {
	return &UpdatesCollector{paths: paths, run: execCmd, lookup: exec.LookPath, release: kernelRelease,
		workDir: filepath.Join(stateDir, "pkg")}
}

func (c *UpdatesCollector) Name() string { return "updates" }

func (c *UpdatesCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	p := c.pending(ctx)
	if p.ok {
		pts = append(pts, gauge("system_updates_pending", "Packages with an update available", float64(p.all), map[string]string{"kind": "all"}))
		if p.securityKnown {
			pts = append(pts, gauge("system_updates_pending", "Packages with an update available", float64(p.security), map[string]string{"kind": "security"}))
		}
	}
	reboot := 0.0
	if c.rebootRequired(ctx) {
		reboot = 1
	}
	pts = append(pts, gauge("system_reboot_required", "1 when installed updates (a kernel, core libraries) need a reboot to take effect", reboot, nil))
	return pts, nil
}

type pendingUpdates struct {
	all, security int
	ok            bool // the package manager answered
	securityKnown bool // it also told which updates fix security issues
}

func (c *UpdatesCollector) has(name string) bool {
	_, err := c.lookup(name)
	return err == nil
}

// env is the environment dnf runs with: XDG_STATE_HOME and HOME point to a
// directory the agent may write.
func (c *UpdatesCollector) env() []string {
	_ = os.MkdirAll(c.workDir, 0o700)
	return []string{"XDG_STATE_HOME=" + c.workDir, "HOME=" + c.workDir}
}

func (c *UpdatesCollector) pending(ctx context.Context) pendingUpdates {
	switch {
	case c.has("apt-get"):
		r := c.run(ctx, nil, "apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
		if r.err != nil || r.code != 0 {
			return pendingUpdates{}
		}
		all, security := countApt(r.out)
		return pendingUpdates{all: all, security: security, ok: true, securityKnown: true}
	case c.has("dnf"):
		env := c.env()
		// check-update exits 100 when updates exist, 0 when none, 1 on error.
		r := c.run(ctx, env, "dnf", "-q", "--cacheonly", "check-update")
		if r.err != nil || (r.code != 0 && r.code != 100) {
			return pendingUpdates{}
		}
		p := pendingUpdates{all: countDNFUpdates(r.out), ok: true}
		if s := c.run(ctx, env, "dnf", "-q", "--cacheonly", "updateinfo", "list", "--security"); s.err == nil && s.code == 0 {
			p.security, p.securityKnown = countDNFAdvisoryPackages(s.out), true
		}
		return p
	case c.has("zypper"):
		r := c.run(ctx, nil, "zypper", "--non-interactive", "--no-refresh", "--xmlout", "list-updates")
		if r.err != nil || r.code != 0 {
			return pendingUpdates{}
		}
		p := pendingUpdates{all: countZypper(r.out, "package", ""), ok: true}
		if s := c.run(ctx, nil, "zypper", "--non-interactive", "--no-refresh", "--xmlout", "list-patches", "--category", "security"); s.err == nil && s.code == 0 {
			p.security, p.securityKnown = countZypper(s.out, "patch", "security"), true
		}
		return p
	case c.has("yum"):
		// yum 3 (CentOS 7, CloudLinux 7): same exit codes as dnf.
		r := c.run(ctx, nil, "yum", "-q", "-C", "check-update")
		if r.err != nil || (r.code != 0 && r.code != 100) {
			return pendingUpdates{}
		}
		return pendingUpdates{all: countDNFUpdates(r.out), ok: true}
	}
	return pendingUpdates{}
}

func countApt(out []byte) (all, security int) {
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		all++
		if strings.Contains(line, "-security") || strings.Contains(line, "Debian-Security") {
			security++
		}
	}
	return all, security
}

var reRPMArch = regexp.MustCompile(`\.(noarch|x86_64|aarch64|i686|i386|ppc64le|s390x|armv7hl)$`)

// countDNFUpdates counts the packages `dnf check-update` lists
// ("name.arch  version  repo"). The "Obsoleting Packages" section and its
// indented lines, and notes such as "Security: kernel-… is an installed
// security update", are not updates.
func countDNFUpdates(out []byte) int {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 3 && reRPMArch.MatchString(f[0]) {
			seen[f[0]] = true
		}
	}
	return len(seen)
}

var reNEVRA = regexp.MustCompile(`^\S+-[^-\s]+-[^-\s]+` + reRPMArch.String())

// countDNFAdvisoryPackages counts the packages `dnf updateinfo list
// --security` names. dnf 4 prints "ADVISORY SEVERITY/Sec. PACKAGE" and dnf 5
// a table with a header; a package fixed by two advisories is listed twice
// and counted once.
func countDNFAdvisoryPackages(out []byte) int {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		for _, f := range strings.Fields(line) {
			if reNEVRA.MatchString(f) {
				seen[f] = true
			}
		}
	}
	return len(seen)
}

// countZypper counts the <update kind="…"> entries of zypper's XML output,
// of one category when it is given.
func countZypper(out []byte, kind, category string) int {
	dec := xml.NewDecoder(bytes.NewReader(out))
	n := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return n
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "update" {
			continue
		}
		attr := map[string]string{}
		for _, a := range se.Attr {
			attr[a.Name.Local] = a.Value
		}
		if attr["kind"] == kind && (category == "" || attr["category"] == category) && attr["status"] != "applied" {
			n++
		}
	}
}

// rebootRequired is true when Debian and Ubuntu have flagged it, when a
// newer kernel than the running one is installed, or when the RPM-based
// package managers say a core library or the kernel was updated since boot.
func (c *UpdatesCollector) rebootRequired(ctx context.Context) bool {
	if _, err := os.Stat(c.paths.root("run", "reboot-required")); err == nil {
		return true
	}
	if newest := newestKernel(c.paths.root("boot")); newest != "" && c.release() != "" && newest != c.release() {
		return true
	}
	switch {
	case c.has("dnf"):
		// Exit 1 and "Reboot is required": a reboot is needed. An older dnf
		// without the command also exits 1, so the text is checked too.
		// --cacheonly: otherwise it downloads the repositories' metadata
		// into the agent's own cache first.
		r := c.run(ctx, c.env(), "dnf", "-q", "--cacheonly", "needs-restarting", "-r")
		return r.code == 1 && bytes.Contains(r.out, []byte("Reboot is required"))
	case c.has("zypper"):
		return c.run(ctx, nil, "zypper", "--non-interactive", "needs-rebooting").code == 102
	}
	return false
}

// newestKernel returns the release of the most recently installed kernel
// image in /boot ("6.1.0-26-arm64" from vmlinuz-6.1.0-26-arm64).
func newestKernel(boot string) string {
	matches, _ := filepath.Glob(filepath.Join(boot, "vmlinuz-*"))
	type k struct {
		rel string
		mod int64
	}
	var ks []k
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil || strings.Contains(m, "rescue") {
			continue
		}
		ks = append(ks, k{strings.TrimPrefix(filepath.Base(m), "vmlinuz-"), fi.ModTime().UnixNano()})
	}
	if len(ks) == 0 {
		return ""
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].mod > ks[j].mod })
	return ks[0].rel
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
