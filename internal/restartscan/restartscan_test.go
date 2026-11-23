package restartscan

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func proc(t *testing.T, procs map[string][2]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, f := range procs {
		dir := filepath.Join(root, pid)
		must(t, os.MkdirAll(dir, 0o755))
		if f[0] != "" {
			must(t, os.WriteFile(filepath.Join(dir, "maps"), []byte(f[0]), 0o644))
		}
		must(t, os.WriteFile(filepath.Join(dir, "cgroup"), []byte(f[1]), 0o644))
	}
	// Entries that are not processes.
	must(t, os.MkdirAll(filepath.Join(root, "self"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "uptime"), []byte("1 1"), 0o644))
	return root
}

const (
	stale  = "7f00-7f10 r-xp 00000000 08:01 123 /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)\n"
	fresh  = "7f00-7f10 r-xp 00000000 08:01 123 /usr/lib/x86_64-linux-gnu/libssl.so.3\n"
	shm    = "7f00-7f10 rw-s 00000000 00:01 9 /dev/shm/pulse-shm-1 (deleted)\n7f20-7f30 rw-p 0 00:01 8 /memfd:x (deleted)\n"
	tmpBin = "5500-5510 r-xp 0 08:01 7 /tmp/build/a.out (deleted)\n"
)

func TestScan(t *testing.T) {
	root := proc(t, map[string][2]string{
		"1":    {stale, "0::/init.scope\n"},
		"101":  {fresh + stale, "0::/system.slice/nginx.service\n"},
		"102":  {stale, "0::/system.slice/nginx.service\n"},
		"103":  {stale, "0::/system.slice/php8.3-fpm.service\n"},
		"104":  {fresh, "0::/system.slice/ssh.service\n"},
		"105":  {shm + tmpBin, "0::/system.slice/pulse.service\n"},
		"106":  {stale, "0::/system.slice/docker-0123abcd.scope\n"},
		"107":  {stale, "0::/user.slice/user-1000.slice/session-3.scope\n"},
		"108":  {stale, "0::/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service\n"},
		"109":  {stale, "12:pids:/system.slice/cron.service\n1:name=systemd:/system.slice/cron.service\n"},
		"110":  {"", "0::/\n"}, // kernel thread: empty maps
		"2000": {stale, "0::/kubepods.slice/kubepods-besteffort.slice/cri-containerd-1.scope\n"},
	})
	r := Scan(root)
	if r.Error != "" || r.Version != ReportVersion || time.Since(r.Time) > time.Minute {
		t.Fatalf("%+v", r)
	}
	want := []string{"cron.service", "nginx.service", "php8.3-fpm.service"}
	if !reflect.DeepEqual(r.Units, want) {
		t.Errorf("units = %v, want %v", r.Units, want)
	}
	// init (no service), the login session and the user manager's service.
	if r.Other != 3 {
		t.Errorf("other = %d, want 3", r.Other)
	}
}

func TestScan_NoProc(t *testing.T) {
	r := Scan(filepath.Join(t.TempDir(), "missing"))
	if r.Error == "" || r.Units == nil {
		t.Errorf("%+v", r)
	}
}

func TestServiceUnit(t *testing.T) {
	for in, want := range map[string]string{
		"0::/system.slice/nginx.service":                   "nginx.service",
		"0::/system.slice/containerd.service":              "containerd.service",
		"0::/system.slice/docker-abc.scope":                "-",
		"0::/machine.slice/libpod-abc.scope/container":     "-",
		"0::/user.slice/user-0.slice/session-1.scope":      "",
		"0::/init.scope":                                   "",
		"4:memory:/docker/abc\n1:name=systemd:/docker/abc": "-",
		"3:cpu:/\n2:pids:/system.slice/exim4.service":      "exim4.service",
		"": "",
	} {
		if got := serviceUnit(in); got != want {
			t.Errorf("serviceUnit(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.json")
	r := Report{Version: ReportVersion, Time: time.Now().UTC().Truncate(time.Second), Units: []string{"nginx.service"}, Other: 2}
	if err := Write(path, r); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Fatalf("%+v %v", got, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode())
	}
	must(t, os.WriteFile(path, []byte(`{"version":99}`), 0o644))
	if _, err := Read(path); err == nil {
		t.Error("a report of another version must be refused")
	}
	must(t, os.WriteFile(path, []byte(`{`), 0o644))
	if _, err := Read(path); err == nil {
		t.Error("broken json must fail")
	}
	if _, err := Read(filepath.Join(t.TempDir(), "none")); !os.IsNotExist(err) {
		t.Errorf("missing: %v", err)
	}
	if err := Write(filepath.Join(t.TempDir(), "no", "dir", "r.json"), r); err == nil {
		t.Error("write into a missing dir must fail")
	}
}
