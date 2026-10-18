package collector

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// HostPaths are the roots the /proc- and /sys-reading collectors read from.
// Tests point them at fixtures; in Docker they may be bind mounts.
type HostPaths struct {
	Proc string // default /proc, or $HOST_PROC
	Sys  string // default /sys, or $HOST_SYS
	Root string // default /, or $HOST_ROOT
}

// DefaultHostPaths honours the HOST_PROC / HOST_SYS / HOST_ROOT variables gopsutil uses.
func DefaultHostPaths() HostPaths {
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	return HostPaths{Proc: env("HOST_PROC", "/proc"), Sys: env("HOST_SYS", "/sys"), Root: env("HOST_ROOT", "/")}
}

func (h HostPaths) proc(p ...string) string { return filepath.Join(append([]string{h.Proc}, p...)...) }
func (h HostPaths) sys(p ...string) string  { return filepath.Join(append([]string{h.Sys}, p...)...) }
func (h HostPaths) root(p ...string) string { return filepath.Join(append([]string{h.Root}, p...)...) }

// readLines returns the lines of a small file.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

// readUint reads a file holding one number.
func readUint(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v, err == nil
}

func gauge(name, help string, v float64, labels map[string]string) metrics.MetricPoint {
	return metrics.MetricPoint{Name: name, Help: help, Type: metrics.Gauge, Value: v, Labels: labels}
}

func counter(name, help string, v float64, labels map[string]string) metrics.MetricPoint {
	return metrics.MetricPoint{Name: name, Help: help, Type: metrics.Counter, Value: v, Labels: labels}
}
