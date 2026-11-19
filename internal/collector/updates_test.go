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
