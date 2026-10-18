package process

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tklauser/go-sysconf"
)

// procSample is what one poll learns about a process from /proc/<pid>/stat.
// Reading only that file keeps a poll at one open+read per process: the
// collector runs every 2s, and gopsutil re-read /proc/stat and /proc/meminfo
// for every process, which cost the agent ~6% of a core on a 300-process host.
type procSample struct {
	PID   int32
	PPID  int32
	Name  string
	Start uint64 // starttime in clock ticks since boot; tells a reused PID apart
	CPU   uint64 // utime + stime in clock ticks
	RSS   uint64 // resident set size in bytes
}

// procSource lists processes. Swapped for a fake in tests.
type procSource interface {
	// List returns every process readable at this moment.
	List(ctx context.Context) ([]procSample, error)
	// Details returns the binary path and command line; called once per new process.
	Details(pid int32) (exe, cmdline string)
	// MemTotal returns the physical memory in bytes (0 if unknown).
	MemTotal() uint64
	// ClockTicks returns the kernel clock ticks per second (USER_HZ).
	ClockTicks() float64
}

// procfs reads processes straight from /proc (or $HOST_PROC, like gopsutil).
type procfs struct {
	root     string
	pageSize uint64
	clkTck   float64
}

func newProcfs() *procfs {
	root := os.Getenv("HOST_PROC")
	if root == "" {
		root = "/proc"
	}
	clk := 100.0
	if v, err := sysconf.Sysconf(sysconf.SC_CLK_TCK); err == nil && v > 0 {
		clk = float64(v)
	}
	return &procfs{root: root, pageSize: uint64(os.Getpagesize()), clkTck: clk}
}

func (p *procfs) ClockTicks() float64 { return p.clkTck }

func (p *procfs) List(ctx context.Context) ([]procSample, error) {
	d, err := os.Open(p.root)
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	out := make([]procSample, 0, len(names))
	for _, n := range names {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		pid, err := strconv.ParseInt(n, 10, 32)
		if err != nil {
			continue
		}
		buf, err := os.ReadFile(filepath.Join(p.root, n, "stat"))
		if err != nil {
			continue // exited between readdir and read
		}
		s, err := parseStat(buf, p.pageSize)
		if err != nil {
			continue
		}
		s.PID = int32(pid)
		out = append(out, s)
	}
	return out, nil
}

func (p *procfs) Details(pid int32) (string, string) {
	dir := filepath.Join(p.root, strconv.Itoa(int(pid)))
	exe, _ := os.Readlink(filepath.Join(dir, "exe"))
	raw, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
	cmdline := strings.TrimSpace(string(bytes.ReplaceAll(raw, []byte{0}, []byte{' '})))
	return exe, cmdline
}

func (p *procfs) MemTotal() uint64 {
	f, err := os.Open(filepath.Join(p.root, "meminfo"))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, _ := strconv.ParseUint(fields[1], 10, 64)
		return kb * 1024
	}
	return 0 // also on a read error: memory percentages are then skipped
}

// parseStat parses /proc/<pid>/stat. The command name sits in parentheses and
// may itself contain spaces and parentheses, so the fields are split after the
// last ')'.
func parseStat(b []byte, pageSize uint64) (procSample, error) {
	open := bytes.IndexByte(b, '(')
	end := bytes.LastIndexByte(b, ')')
	if open < 0 || end < open {
		return procSample{}, fmt.Errorf("malformed stat")
	}
	s := procSample{Name: string(b[open+1 : end])}
	// fields[0] is field 3 of proc(5) (state), so field N is fields[N-3].
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 22 {
		return procSample{}, fmt.Errorf("short stat: %d fields", len(fields))
	}
	num := func(i int) uint64 { v, _ := strconv.ParseUint(fields[i], 10, 64); return v }
	s.PPID = int32(num(4 - 3))
	s.CPU = num(14-3) + num(15-3)
	s.Start = num(22 - 3)
	s.RSS = num(24-3) * pageSize
	return s, nil
}
