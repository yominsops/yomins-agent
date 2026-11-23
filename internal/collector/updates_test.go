package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeCmd answers commands by their joined name and arguments.
type fakeCmd map[string]cmdResult

func (f fakeCmd) run(_ context.Context, _ []string, name string, args ...string) cmdResult {
	if r, ok := f[strings.Join(append([]string{name}, args...), " ")]; ok {
		return r
	}
	return cmdResult{err: errors.New("not found")}
}

func updatesWith(t *testing.T, h HostPaths, tools string, cmds fakeCmd) *UpdatesCollector {
	t.Helper()
	c := NewUpdatesCollector(h, t.TempDir())
	c.lookup = func(n string) (string, error) {
		if strings.Contains(" "+tools+" ", " "+n+" ") {
			return "/usr/bin/" + n, nil
		}
		return "", errors.New("no")
	}
	c.run = cmds.run
	c.release = func() string { return "" }
	return c
}

func TestUpdates_Apt(t *testing.T) {
	h := fixture(t, map[string]string{"run/reboot-required": ""})
	c := updatesWith(t, h, "apt-get", fakeCmd{
		"apt-get -s -o Debug::NoLocking=1 dist-upgrade": {out: []byte("Inst libc6 [2.36-9] (2.36-9+deb12u9 Debian-Security:12/stable-security [arm64])\nInst vim [1] (2 Debian:12.8/stable [arm64])\nConf vim (2)\n" +
			"Inst libc-bin [2.39-0ubuntu8.9] (2.39-0ubuntu8.12 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [arm64])\n")},
	})
	pts, _ := c.Collect(context.Background())
	if find(t, pts, "system_updates_pending", "kind", "all") != 3 || find(t, pts, "system_updates_pending", "kind", "security") != 2 || find(t, pts, "system_reboot_required") != 1 {
		t.Errorf("%v", pts)
	}
}

// Output shaped like a Debian 12 host with packages.sury.org, Docker CE and
// exim4 held back. sury names no origin, only its suite.
func TestUpdates_AptHeldAndThirdParty(t *testing.T) {
	plain := "Inst php-common [2:101] (2:102+debsuryorg12.1+3 bookworm [all])\n" +
		"Inst docker-buildx-plugin [0.39.0-1~debian.12~bookworm] (0.39.1-1~debian.12~bookworm Docker CE:bookworm [arm64])\n" +
		"Inst libruby3.1 [3.1.2-7+deb12u1] (3.1.2-7+deb12u2 Debian:12.15/oldstable, Debian-Security:12/oldstable-security [arm64])\n" +
		"Inst libc-bin [2.39-0ubuntu8.9] (2.39-0ubuntu8.12 Ubuntu:24.04/noble-updates [amd64])\n" +
		"Inst libpq5 [16.1] (16.2 UbuntuESMApps:24.04/noble-apps-security [amd64])\n"
	held := plain +
		"Inst exim4 [4.92-8+deb10u9~bk11] (4.96-15+deb12u10 Debian:12.15/oldstable, Debian-Security:12/oldstable-security [all]) []\n" +
		"Inst exim4-daemon-heavy [4.92-8+deb10u9~bk11] (4.96-15+deb12u10 Debian:12.15/oldstable, Debian-Security:12/oldstable-security [arm64]) []\n" +
		"Inst vim [1] (2 Debian:12.15/oldstable [arm64])\n"
	c := updatesWith(t, fixture(t, nil), "apt-get", fakeCmd{
		"apt-get -s -o Debug::NoLocking=1 dist-upgrade":               {out: []byte(plain)},
		"apt-get -s -o Debug::NoLocking=1 --ignore-hold dist-upgrade": {out: []byte(held)},
	})
	pts, _ := c.Collect(context.Background())
	for _, w := range []struct {
		name, kind string
		v          float64
	}{
		{"system_updates_pending", "all", 5},
		{"system_updates_pending", "security", 2},
		{"system_updates_pending", "third_party", 2},
		{"system_updates_held", "all", 3},
		{"system_updates_held", "security", 2},
	} {
		if got := find(t, pts, w.name, "kind", w.kind); got != w.v {
			t.Errorf("%s{kind=%s} = %v, want %v", w.name, w.kind, got, w.v)
		}
	}
}

// When the simulation without holds fails, held updates are not reported
// (rather than reported as 0).
func TestUpdates_AptHeldUnknown(t *testing.T) {
	c := updatesWith(t, fixture(t, nil), "apt-get", fakeCmd{
		"apt-get -s -o Debug::NoLocking=1 dist-upgrade": {out: []byte("Inst vim [1] (2 Debian:12.8/stable [arm64])\n")},
	})
	pts, _ := c.Collect(context.Background())
	if has(pts, "system_updates_held") || find(t, pts, "system_updates_pending", "kind", "third_party") != 0 {
		t.Errorf("%v", pts)
	}
}

func TestDistroOrigin(t *testing.T) {
	for line, want := range map[string]bool{
		"Inst a [1] (2 Debian:12/stable [all])":                   true,
		"Inst a [1] (2 Debian-Security:12/stable-security [all])": true,
		"Inst a (2 Ubuntu:24.04/noble-updates [amd64])":           true,
		"Inst a [1] (2 bookworm [all])":                           false,
		"Inst a [1] (2 Docker CE:bookworm [arm64])":               false,
		"Inst a [1] (2 nginx:bookworm, Debian:12/stable [amd64])": true,
		"Inst a [1] (2 packages.sury.org:bookworm [amd64]) []":    false,
		"Inst a": true,
	} {
		if got := distroOrigin(line); got != want {
			t.Errorf("distroOrigin(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestUpdates_AptFails(t *testing.T) {
	c := updatesWith(t, fixture(t, nil), "apt-get", fakeCmd{"apt-get -s -o Debug::NoLocking=1 dist-upgrade": {code: 100}})
	pts, _ := c.Collect(context.Background())
	if has(pts, "system_updates_pending") {
		t.Errorf("a failed apt-get must not report 0 updates: %v", pts)
	}
}

// Output captured on Rocky Linux 8 (dnf 4): bzip2-libs is fixed by two
// advisories, and the Obsoleting section is not a list of updates.
func TestUpdates_DNF4(t *testing.T) {
	c := updatesWith(t, fixture(t, nil), "dnf", fakeCmd{
		"dnf -q --cacheonly check-update": {code: 100, out: []byte(`
binutils.aarch64                      2.30-125.el8_10                     baseos
bzip2-libs.aarch64                    1.0.6-28.el8_10                     baseos
kernel-core.aarch64                   4.18.0-553.el8_10                   baseos
Security: kernel-core-4.18.0-553.el8_10.aarch64 is an installed security update
Obsoleting Packages
grub2-tools.aarch64                   1:2.02-150.el8                      baseos
    grub2-tools.aarch64               1:2.02-148.el8                      @anaconda
`)},
		"dnf -q --cacheonly updateinfo list --security": {out: []byte(`RLSA-2024:9689  Low/Sec.       binutils-2.30-125.el8_10.aarch64
RLSA-2024:8922  Low/Sec.       bzip2-libs-1.0.6-27.el8_10.aarch64
RLSA-2025:0733  Moderate/Sec.  bzip2-libs-1.0.6-28.el8_10.aarch64
RLSA-2025:0734  Moderate/Sec.  bzip2-libs-1.0.6-28.el8_10.aarch64
`)},
		"dnf -q --cacheonly needs-restarting -r": {code: 1, out: []byte("Core libraries or services have been updated since boot-up:\n  * glibc\n\nReboot is required to fully utilize these updates.\n")},
	})
	pts, _ := c.Collect(context.Background())
	if find(t, pts, "system_updates_pending", "kind", "all") != 3 || find(t, pts, "system_updates_pending", "kind", "security") != 3 || find(t, pts, "system_reboot_required") != 1 {
		t.Errorf("%v", pts)
	}
}

// Output captured on Fedora 43 (dnf 5): updateinfo prints a header.
func TestUpdates_DNF5(t *testing.T) {
	c := updatesWith(t, fixture(t, nil), "dnf", fakeCmd{
		"dnf -q --cacheonly check-update": {code: 100, out: []byte("dnf5.aarch64                       5.2.18.0-7.fc43   updates\ndnf5-plugins.aarch64               5.2.18.0-7.fc43   updates\n")},
		"dnf -q --cacheonly updateinfo list --security": {out: []byte(`Name                   Type     Severity                               Package              Issued
FEDORA-2026-3941b8db92 security Moderate         tpm2-tss-4.1.5-1.fc43.aarch64 2026-11-12 03:14:26
FEDORA-2026-5b05307c5f security Important         dnf5-5.2.18.0-7.fc43.aarch64 2026-11-16 00:51:31
FEDORA-2026-11d7d4d8f3 security Moderate      vim-data-2:9.2.390-1.fc42.noarch 2026-05-07 01:26:58
`)},
		"dnf -q --cacheonly needs-restarting -r": {code: 0, out: []byte("No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n")},
	})
	pts, _ := c.Collect(context.Background())
	if find(t, pts, "system_updates_pending", "kind", "all") != 2 || find(t, pts, "system_updates_pending", "kind", "security") != 3 || find(t, pts, "system_reboot_required") != 0 {
		t.Errorf("%v", pts)
	}
}

// dnf 5 run as a user without a writable home exits 1 ("cannot create
// directories … .local/state"): that is no answer, not "no updates".
func TestUpdates_DNFFails(t *testing.T) {
	c := updatesWith(t, fixture(t, nil), "dnf", fakeCmd{
		"dnf -q --cacheonly check-update":        {code: 1},
		"dnf -q --cacheonly needs-restarting -r": {code: 1, out: []byte("No such command: needs-restarting.")},
	})
	pts, _ := c.Collect(context.Background())
	if has(pts, "system_updates_pending") || find(t, pts, "system_reboot_required") != 0 {
		t.Errorf("%v", pts)
	}
}

func TestUpdates_DNFGetsWritableState(t *testing.T) {
	dir := t.TempDir()
	var env []string
	c := NewUpdatesCollector(fixture(t, nil), dir)
	c.lookup = func(n string) (string, error) {
		if n == "dnf" {
			return "/usr/bin/dnf", nil
		}
		return "", errors.New("no")
	}
	c.release = func() string { return "" }
	c.run = func(_ context.Context, e []string, _ string, _ ...string) cmdResult { env = e; return cmdResult{} }
	_, _ = c.Collect(context.Background())
	want := "XDG_STATE_HOME=" + filepath.Join(dir, "pkg")
	if len(env) == 0 || env[0] != want {
		t.Fatalf("env = %v, want %s", env, want)
	}
	if fi, err := os.Stat(filepath.Join(dir, "pkg")); err != nil || !fi.IsDir() {
		t.Fatalf("state dir not created: %v", err)
	}
}

func TestUpdates_Zypper(t *testing.T) {
	c := updatesWith(t, fixture(t, nil), "zypper", fakeCmd{
		"zypper --non-interactive --no-refresh --xmlout list-updates": {out: []byte(`<?xml version='1.0'?>
<stream><update-status version="0.6"><update-list>
<update kind="package" name="libopenssl3" edition="3.1.4-150600.5.21.1" arch="x86_64"/>
<update kind="package" name="vim" edition="9.1.0836-150500.20.15.1" arch="x86_64"/>
</update-list></update-status></stream>`)},
		"zypper --non-interactive --no-refresh --xmlout list-patches --category security": {out: []byte(`<?xml version='1.0'?>
<stream><update-status version="0.6"><update-list>
<update kind="patch" name="openSUSE-SLE-15.6-2026-101" category="security" severity="important" status="needed"/>
<update kind="patch" name="openSUSE-SLE-15.6-2026-099" category="security" severity="low" status="applied"/>
</update-list></update-status></stream>`)},
		"zypper --non-interactive needs-rebooting": {code: 102},
	})
	pts, _ := c.Collect(context.Background())
	if find(t, pts, "system_updates_pending", "kind", "all") != 2 || find(t, pts, "system_updates_pending", "kind", "security") != 1 || find(t, pts, "system_reboot_required") != 1 {
		t.Errorf("%v", pts)
	}
}

func TestUpdates_Yum(t *testing.T) {
	c := updatesWith(t, fixture(t, nil), "yum", fakeCmd{
		"yum -q -C check-update": {code: 100, out: []byte("\nbash.x86_64    4.2.46-35.el7_9   updates\nopenssl.x86_64 1:1.0.2k-26.el7_9 updates\n")},
	})
	pts, _ := c.Collect(context.Background())
	if find(t, pts, "system_updates_pending", "kind", "all") != 2 || has(pts, "system_updates_pending", "kind", "security") {
		t.Errorf("%v", pts)
	}
}

func TestUpdates_NewerKernelInstalled(t *testing.T) {
	h := fixture(t, map[string]string{"boot/vmlinuz-6.1.0-25-arm64": ""})
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(h.Root, "boot/vmlinuz-6.1.0-26-arm64"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	c := updatesWith(t, h, "", nil)
	c.release = func() string { return "6.1.0-25-arm64" }
	pts, _ := c.Collect(context.Background())
	if find(t, pts, "system_reboot_required") != 1 || has(pts, "system_updates_pending") {
		t.Errorf("%v", pts)
	}
}
