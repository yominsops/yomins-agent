// Package restartscan finds services that still run code an update has
// replaced: after apt or dnf upgrades a library or a binary, the processes
// started before keep the old, deleted file mapped until they restart, so the
// fix is not in effect. Reading other processes' /proc/<pid>/maps needs root
// (ptrace access, not file permissions), which the agent does not have, so
// `yomins-agent restart-scan` runs from its own root timer
// (yomins-agent-restart.timer), writes a report next to the agent's state,
// and the unprivileged agent turns the report into metrics.
package restartscan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ReportVersion changes when the report format does.
const ReportVersion = 1

// DefaultReportPath is where the timer writes the report.
const DefaultReportPath = "/var/lib/yomins/agent/restart.json"

// Report is one scan of all processes.
type Report struct {
	Version int       `json:"version"`
	Time    time.Time `json:"time"`
	Error   string    `json:"error,omitempty"`
	// Units are the systemd services with at least one such process, sorted.
	Units []string `json:"units"`
	// Other counts such processes outside a service: login sessions, user
	// managers. They pick the update up at the next login.
	Other int `json:"other"`
}

// codeDirs are where the files a process runs live; a deleted file mapped
// from anywhere else (a temp file, shared memory) is not stale code.
var codeDirs = []string{"/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/"}

// Scan reads every process under procRoot ("/proc").
func Scan(procRoot string) Report {
	r := Report{Version: ReportVersion, Time: time.Now().UTC(), Units: []string{}}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	units := map[string]bool{}
	for _, e := range entries {
		// Kernel threads have empty maps and are skipped by staleCode.
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		if !staleCode(filepath.Join(dir, "maps")) {
			continue
		}
		cg, _ := os.ReadFile(filepath.Join(dir, "cgroup"))
		switch unit := serviceUnit(string(cg)); {
		case unit == "-":
			// A container's process: its files come from the image, not
			// from the host's packages.
		case unit != "":
			units[unit] = true
		default:
			r.Other++
		}
	}
	for u := range units {
		r.Units = append(r.Units, u)
	}
	sort.Strings(r.Units)
	return r
}

// staleCode is true when the process maps a deleted file from a code
// directory. A kernel thread or a process gone meanwhile has no readable maps.
func staleCode(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasSuffix(line, " (deleted)") {
			continue
		}
		i := strings.IndexByte(line, '/')
		if i < 0 {
			continue
		}
		file := strings.TrimSuffix(line[i:], " (deleted)")
		for _, d := range codeDirs {
			if strings.HasPrefix(file, d) {
				return true
			}
		}
	}
	// A read error (the process exited) leaves what was read so far.
	_ = sc.Err()
	return false
}

// serviceUnit returns the systemd service of a process from its
// /proc/<pid>/cgroup ("0::/system.slice/nginx.service"; with cgroup v1, the
// name=systemd or the first hierarchy that has a path), "" outside a
// service, and "-" for a container's process.
func serviceUnit(cgroup string) string {
	var path string
	for line := range strings.SplitSeq(cgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" || strings.Contains(parts[1], "name=systemd") {
			path = parts[2]
			break
		}
		if path == "" && parts[2] != "/" {
			path = parts[2]
		}
	}
	unit := ""
	for seg := range strings.SplitSeq(path, "/") {
		switch {
		case strings.HasPrefix(seg, "docker-"), strings.HasPrefix(seg, "libpod-"),
			strings.HasPrefix(seg, "cri-containerd-"), strings.HasPrefix(seg, "crio-"),
			seg == "docker", seg == "kubepods", strings.HasPrefix(seg, "kubepods-"):
			return "-"
		case strings.HasSuffix(seg, ".service") && !strings.HasPrefix(seg, "user@"):
			// The innermost service wins; one inside a user manager is
			// "other" (below).
			unit = seg
		}
	}
	if strings.Contains(path, "/user.slice/") || strings.HasPrefix(path, "/user.slice") {
		return ""
	}
	return unit
}

// Write saves the report atomically, readable by the agent.
func Write(path string, r Report) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".restart-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Read loads a report.
func Read(path string) (Report, error) {
	var r Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.Version != ReportVersion {
		return r, fmt.Errorf("restart report version %d, want %d", r.Version, ReportVersion)
	}
	return r, nil
}
