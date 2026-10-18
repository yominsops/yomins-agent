package process

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseStat(t *testing.T) {
	// The command name holds a space and a ')' to check the split after the last ')'.
	line := "1234 (php-fpm: pool (www)) S 1 1234 1234 0 -1 4194624 100 0 0 0 250 50 0 0 20 0 1 0 98765 300000000 2048 18446744073709551615"
	s, err := parseStat([]byte(line), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "php-fpm: pool (www)" {
		t.Errorf("Name = %q", s.Name)
	}
	if s.PPID != 1 || s.CPU != 300 || s.Start != 98765 || s.RSS != 2048*4096 {
		t.Errorf("got %+v", s)
	}
}

func TestParseStat_Malformed(t *testing.T) {
	for _, line := range []string{"", "1234 no-parens S 1", "1 (x) S 1 2 3"} {
		if _, err := parseStat([]byte(line), 4096); err == nil {
			t.Errorf("parseStat(%q) should fail", line)
		}
	}
}

func TestProcfs_ReadsFakeRoot(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "77")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := "77 (nginx) S 1 77 77 0 -1 0 0 0 0 0 10 5 0 0 20 0 1 0 500 1000 3 0"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644))
	must(os.WriteFile(filepath.Join(dir, "cmdline"), []byte("nginx\x00-g\x00daemon off;\x00"), 0o644))
	must(os.Symlink("/usr/sbin/nginx", filepath.Join(dir, "exe")))
	must(os.WriteFile(filepath.Join(root, "meminfo"), []byte("MemTotal:       16384 kB\nMemFree: 1 kB\n"), 0o644))
	must(os.MkdirAll(filepath.Join(root, "self"), 0o755)) // not a PID: skipped

	p := &procfs{root: root, pageSize: 4096, clkTck: 100}
	procs, err := p.List(context.Background())
	must(err)
	if len(procs) != 1 || procs[0].PID != 77 || procs[0].Name != "nginx" || procs[0].CPU != 15 {
		t.Fatalf("List = %+v", procs)
	}
	exe, cmdline := p.Details(77)
	if exe != "/usr/sbin/nginx" || cmdline != "nginx -g daemon off;" {
		t.Errorf("Details = %q, %q", exe, cmdline)
	}
	if got := p.MemTotal(); got != 16384*1024 {
		t.Errorf("MemTotal = %d", got)
	}
}

func TestProcfs_RealProc(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc")
	}
	procs, err := newProcfs().List(context.Background())
	if err != nil || len(procs) == 0 {
		t.Fatalf("List: %v, %d processes", err, len(procs))
	}
	self := int32(os.Getpid())
	for _, p := range procs {
		if p.PID == self {
			return
		}
	}
	t.Errorf("own PID %d not listed", self)
}
