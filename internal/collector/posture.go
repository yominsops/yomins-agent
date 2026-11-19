package collector

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// PostureCollector reports how the host is protected: mandatory access
// control (SELinux on the RHEL family, AppArmor on Debian, Ubuntu, SUSE),
// the firewall and auditd, automatic updates, kernel live patches, the
// effective SSH server settings, accounts that are root in all but name or
// have no password, and two signs of tampering (ld.so.preload, a tainted
// kernel). Each metric is left out where its subject does not exist on the
// host, so "0" always means "present and off".
type PostureCollector struct {
	paths HostPaths
	run   runner
}

// NewPostureCollector creates the collector.
func NewPostureCollector(paths HostPaths) *PostureCollector {
	return &PostureCollector{paths: paths, run: execRunner}
}

func (c *PostureCollector) Name() string { return "posture" }

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (c *PostureCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	pts = append(pts, c.mac()...)
	pts = append(pts, c.services(ctx)...)
	pts = append(pts, c.livepatch()...)
	pts = append(pts, c.ssh()...)
	pts = append(pts, c.accounts()...)
	if fi, err := os.Stat(c.paths.root("etc", "ld.so.preload")); err == nil {
		pts = append(pts, gauge("security_ld_preload", "1 when /etc/ld.so.preload names libraries: every program loads them — a common rootkit trick", b2f(fi.Size() > 0), nil))
	} else {
		pts = append(pts, gauge("security_ld_preload", "1 when /etc/ld.so.preload names libraries: every program loads them — a common rootkit trick", 0, nil))
	}
	if v, ok := readUint(c.paths.proc("sys", "kernel", "tainted")); ok {
		pts = append(pts, gauge("security_kernel_tainted", "The kernel's taint flags: non-zero after an unsigned or out-of-tree module, a crash, a forced load", float64(v), nil))
	}
	return pts, nil
}

// ── SELinux, AppArmor ────────────────────────────────────────────────────────

func (c *PostureCollector) mac() []metrics.MetricPoint {
	var pts []metrics.MetricPoint
	const selinuxHelp = "SELinux mode (1 for the current one): enforcing, permissive or disabled"
	if b, err := os.ReadFile(c.paths.sys("fs", "selinux", "enforce")); err == nil {
		mode := "permissive"
		if strings.TrimSpace(string(b)) == "1" {
			mode = "enforcing"
		}
		pts = append(pts, gauge("security_selinux_mode", selinuxHelp, 1, map[string]string{"mode": mode}))
	} else if _, err := os.Stat(c.paths.root("etc", "selinux", "config")); err == nil {
		pts = append(pts, gauge("security_selinux_mode", selinuxHelp, 1, map[string]string{"mode": "disabled"}))
	}
	if b, err := os.ReadFile(c.paths.sys("module", "apparmor", "parameters", "enabled")); err == nil {
		pts = append(pts, gauge("security_apparmor_enabled", "1 when AppArmor is enabled in the kernel", b2f(strings.TrimSpace(string(b)) == "Y"), nil))
		if lines, err := readLines(c.paths.sys("kernel", "security", "apparmor", "profiles")); err == nil {
			counts := map[string]int{"enforce": 0, "complain": 0}
			for _, l := range lines {
				if i := strings.LastIndex(l, "("); i >= 0 && strings.HasSuffix(l, ")") {
					counts[l[i+1:len(l)-1]]++
				}
			}
			for mode, n := range counts {
				pts = append(pts, gauge("security_apparmor_profiles", "Loaded AppArmor profiles by mode", float64(n), map[string]string{"mode": mode}))
			}
		}
	}
	return pts
}

// ── Firewall, auditd, automatic updates ──────────────────────────────────────

var unitDirs = []string{"etc/systemd/system", "usr/lib/systemd/system", "lib/systemd/system"}

func (c *PostureCollector) unitInstalled(unit string) bool {
	for _, d := range unitDirs {
		if _, err := os.Stat(c.paths.root(d, unit)); err == nil {
			return true
		}
	}
	return false
}

// unitStates asks systemctl about units in one call: is-active or
// is-enabled print one line per unit, in order.
func (c *PostureCollector) unitStates(ctx context.Context, verb string, units []string) map[string]string {
	out := map[string]string{}
	if len(units) == 0 {
		return out
	}
	b, _ := c.run(ctx, "systemctl", append([]string{verb}, units...)...) // non-zero when one is not active
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i, u := range units {
		if i < len(lines) {
			out[u] = strings.TrimSpace(lines[i])
		}
	}
	return out
}

func (c *PostureCollector) services(ctx context.Context) []metrics.MetricPoint {
	var pts []metrics.MetricPoint
	const fwHelp = "1 when this firewall is active (each tool found on the host)"

	var active []string
	for _, u := range []string{"firewalld.service", "nftables.service", "iptables.service", "netfilter-persistent.service", "lfd.service", "auditd.service"} {
		if c.unitInstalled(u) {
			active = append(active, u)
		}
	}
	state := c.unitStates(ctx, "is-active", active)
	tools := map[string]string{"firewalld.service": "firewalld", "nftables.service": "nftables", "iptables.service": "iptables", "netfilter-persistent.service": "iptables-persistent"}
	anyOn := false
	for unit, tool := range tools {
		if s, ok := state[unit]; ok {
			on := s == "active"
			anyOn = anyOn || on
			pts = append(pts, gauge("security_firewall_active", fwHelp, b2f(on), map[string]string{"tool": tool}))
		}
	}
	// ufw keeps its switch in its configuration; its unit only loads the rules.
	if lines, err := readLines(c.paths.root("etc", "ufw", "ufw.conf")); err == nil {
		on := false
		for _, l := range lines {
			if strings.TrimSpace(l) == "ENABLED=yes" {
				on = true
			}
		}
		anyOn = anyOn || on
		pts = append(pts, gauge("security_firewall_active", fwHelp, b2f(on), map[string]string{"tool": "ufw"}))
	}
	// CSF (cPanel, DirectAdmin hosts): its daemon lfd runs while it is on.
	if _, err := os.Stat(c.paths.root("etc", "csf", "csf.conf")); err == nil {
		on := state["lfd.service"] == "active"
		anyOn = anyOn || on
		pts = append(pts, gauge("security_firewall_active", fwHelp, b2f(on), map[string]string{"tool": "csf"}))
	}
	pts = append(pts, gauge("security_firewall_enabled", "1 when any firewall found on the host is active", b2f(anyOn), nil))

	if s, ok := state["auditd.service"]; ok {
		pts = append(pts, gauge("security_auditd_active", "1 when the audit daemon runs (logins, privilege use and SELinux denials in /var/log/audit/audit.log)", b2f(s == "active"), nil))
	}

	const auHelp = "1 when security updates install by themselves"
	if _, err := os.Stat(c.paths.root("usr", "bin", "unattended-upgrade")); err == nil {
		pts = append(pts, gauge("security_auto_updates_enabled", auHelp, b2f(c.aptPeriodicUnattended()), map[string]string{"method": "unattended-upgrades"}))
	}
	var timers []string
	for _, u := range []string{"dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic.timer"} {
		if c.unitInstalled(u) {
			timers = append(timers, u)
		}
	}
	if len(timers) > 0 {
		on := false
		for u, s := range c.unitStates(ctx, "is-enabled", timers) {
			// dnf-automatic.timer installs only when automatic.conf says
			// apply_updates; the -install timer always does.
			if s == "enabled" && (u == "dnf-automatic-install.timer" || c.dnfAutomaticApplies()) {
				on = true
			}
		}
		pts = append(pts, gauge("security_auto_updates_enabled", auHelp, b2f(on), map[string]string{"method": "dnf-automatic"}))
	}
	return pts
}

// aptPeriodicUnattended reads APT::Periodic::Unattended-Upgrade from
// /etc/apt/apt.conf.d, the last setting winning as apt reads the files in order.
func (c *PostureCollector) aptPeriodicUnattended() bool {
	files, _ := filepath.Glob(c.paths.root("etc", "apt", "apt.conf.d", "*"))
	on := false
	for _, f := range files {
		lines, _ := readLines(f)
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "//") || !strings.HasPrefix(l, "APT::Periodic::Unattended-Upgrade ") {
				continue
			}
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(l, "APT::Periodic::Unattended-Upgrade")), `";`)
			on = v != "0" && v != ""
		}
	}
	return on
}

func (c *PostureCollector) dnfAutomaticApplies() bool {
	for _, f := range []string{c.paths.root("etc", "dnf", "automatic.conf"), c.paths.root("etc", "dnf", "dnf5-plugins", "automatic.conf")} {
		lines, err := readLines(f)
		if err != nil {
			continue
		}
		for _, l := range lines {
			k, v, ok := strings.Cut(strings.ReplaceAll(l, " ", ""), "=")
			if ok && k == "apply_updates" {
				return v == "yes" || v == "true" || v == "1"
			}
		}
	}
	return false
}

// ── Kernel live patches ──────────────────────────────────────────────────────

func (c *PostureCollector) livepatch() []metrics.MetricPoint {
	entries, err := os.ReadDir(c.paths.sys("kernel", "livepatch"))
	if err != nil {
		return nil
	}
	return []metrics.MetricPoint{gauge("security_kernel_livepatches", "Kernel live patches loaded (kpatch, Canonical Livepatch, SUSE kGraft)", float64(len(entries)), nil)}
}

// ── SSH server settings ──────────────────────────────────────────────────────

// sshOptions are reported with their effective value; sshDefaults are
// OpenSSH's own when a setting is absent.
var sshOptions = []string{"permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication", "permitemptypasswords", "x11forwarding"}

var sshDefaults = map[string]string{
	"permitrootlogin": "prohibit-password", "passwordauthentication": "yes", "kbdinteractiveauthentication": "yes",
	"pubkeyauthentication": "yes", "permitemptypasswords": "no", "x11forwarding": "no",
}

func (c *PostureCollector) ssh() []metrics.MetricPoint {
	main := c.paths.root("etc", "ssh", "sshd_config")
	if _, err := os.Stat(main); err != nil {
		return nil
	}
	got := map[string]string{}
	c.readSSHConfig(main, got, 0)
	var pts []metrics.MetricPoint
	for _, o := range sshOptions {
		v, ok := got[o]
		if !ok {
			v = sshDefaults[o]
		}
		pts = append(pts, gauge("security_ssh_option", "Effective sshd setting outside Match blocks (1 for its value)", 1, map[string]string{"option": o, "value": v}))
	}
	return pts
}

// readSSHConfig applies sshd's rules: the first value of a keyword wins,
// Include is read in place (globs, relative to /etc/ssh), and what follows
// a Match line applies only to some connections, so it is not read.
// It returns false once a Match line is reached.
func (c *PostureCollector) readSSHConfig(path string, got map[string]string, depth int) bool {
	f, err := os.Open(path)
	if err != nil || depth > 8 {
		return true
	}
	defer f.Close() //nolint:errcheck
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(strings.Replace(line, "=", " ", 1))
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		switch key {
		case "match":
			return false
		case "include":
			for _, g := range fields[1:] {
				if !filepath.IsAbs(g) {
					g = filepath.Join("/etc/ssh", g)
				}
				matches, _ := filepath.Glob(c.paths.root(g))
				for _, m := range matches {
					if !c.readSSHConfig(m, got, depth+1) {
						return false
					}
				}
			}
		default:
			if _, seen := got[key]; !seen {
				got[key] = strings.ToLower(fields[1])
			}
		}
	}
	return true
}

// ── Accounts ─────────────────────────────────────────────────────────────────

func (c *PostureCollector) accounts() []metrics.MetricPoint {
	var pts []metrics.MetricPoint
	passwd, err := readLines(c.paths.root("etc", "passwd"))
	if err != nil {
		return nil
	}
	uid0 := 0
	primary := map[string][]string{} // gid → users whose primary group it is
	for _, l := range passwd {
		f := strings.Split(l, ":")
		if len(f) < 4 || strings.HasPrefix(l, "#") {
			continue
		}
		if f[2] == "0" && f[0] != "root" {
			uid0++
		}
		primary[f[3]] = append(primary[f[3]], f[0])
	}
	pts = append(pts, gauge("security_accounts", "Accounts that need a look: uid0_extra — besides root, with UID 0; empty_password — that log in without a password", float64(uid0), map[string]string{"kind": "uid0_extra"}))

	if shadow, err := readLines(c.paths.root("etc", "shadow")); err == nil {
		empty := 0
		for _, l := range shadow {
			f := strings.Split(l, ":")
			if len(f) >= 2 && f[1] == "" {
				empty++
			}
		}
		pts = append(pts, gauge("security_accounts", "Accounts that need a look: uid0_extra — besides root, with UID 0; empty_password — that log in without a password", float64(empty), map[string]string{"kind": "empty_password"}))
	}

	if groups, err := readLines(c.paths.root("etc", "group")); err == nil {
		for _, l := range groups {
			f := strings.Split(l, ":")
			if len(f) < 4 || (f[0] != "sudo" && f[0] != "wheel" && f[0] != "admin") {
				continue
			}
			members := map[string]bool{}
			for _, u := range strings.Split(f[3], ",") {
				if u != "" {
					members[u] = true
				}
			}
			for _, u := range primary[f[2]] {
				members[u] = true
			}
			pts = append(pts, gauge("security_privileged_users", "Members of the groups that may use sudo", float64(len(members)), map[string]string{"group": f[0]}))
		}
	}
	return pts
}
