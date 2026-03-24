//go:build linux

package collector

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
)

type realInfoReader struct {
	virtOverride string
}

func newRealInfoReader(virtOverride string) InfoReader {
	return &realInfoReader{virtOverride: virtOverride}
}

func (r *realInfoReader) SystemInfoWithContext(ctx context.Context) (*SystemInfoStat, error) {
	s := &SystemInfoStat{}

	dist, ver := parseOSRelease()
	s.Distribution = dist
	s.DistributionVersion = ver

	if kv, err := host.KernelVersionWithContext(ctx); err == nil {
		s.KernelVersion = kv
	}

	if r.virtOverride != "" {
		s.Virtualization = r.virtOverride
	} else {
		s.Virtualization = detectVirtualization(ctx)
	}

	return s, nil
}

func (r *realInfoReader) CPUInfoWithContext(ctx context.Context) (*CPUInfoStat, error) {
	infos, err := cpu.InfoWithContext(ctx)
	if err != nil {
		return nil, err
	}
	model := ""
	if len(infos) > 0 {
		model = infos[0].ModelName
	}
	physCores, _ := cpu.CountsWithContext(ctx, false)
	logThreads, _ := cpu.CountsWithContext(ctx, true)
	return &CPUInfoStat{
		Model:   model,
		Cores:   physCores,
		Threads: logThreads,
	}, nil
}

func (r *realInfoReader) PackageUpdateTimesWithContext(ctx context.Context) (*PackageUpdateTimes, error) {
	put := &PackageUpdateTimes{}

	// Try dpkg logs first (Debian/Ubuntu).
	kernelTS, softwareTS := parseDpkgLogs()
	if kernelTS > 0 || softwareTS > 0 {
		put.LastKernelUpdate = kernelTS
		put.LastSoftwareUpdate = softwareTS
		return put, nil
	}

	// Fallback: rpm (RHEL/CentOS/AlmaLinux/Rocky).
	put.LastKernelUpdate = rpmLastUpdate(ctx, true)
	put.LastSoftwareUpdate = rpmLastUpdate(ctx, false)
	return put, nil
}

func (r *realInfoReader) KernelCareInfoWithContext(ctx context.Context) (*KernelCareInfoStat, error) {
	if _, err := exec.LookPath("kcarectl"); err != nil {
		return &KernelCareInfoStat{Installed: false}, nil
	}
	out, err := exec.CommandContext(ctx, "kcarectl", "--version").Output()
	if err != nil {
		return &KernelCareInfoStat{Installed: true, Version: "unknown"}, nil
	}
	ver := strings.TrimSpace(string(out))
	ver = strings.TrimPrefix(ver, "kcarectl v")
	ver = strings.TrimPrefix(ver, "v")
	return &KernelCareInfoStat{Installed: true, Version: ver}, nil
}

// parseOSRelease reads /etc/os-release and returns the distro ID and version.
func parseOSRelease() (id, version string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "", ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	return id, version
}

// detectVirtualization tries systemd-detect-virt first, then falls back to DMI.
func detectVirtualization(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "systemd-detect-virt", "--vm").Output()
	if err == nil {
		v := strings.TrimSpace(string(out))
		if v != "" && v != "none" {
			return v
		}
		if v == "none" {
			return "none"
		}
	}

	// Fallback: read DMI sys_vendor.
	data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil {
		return "unknown"
	}
	vendor := strings.TrimSpace(string(data))
	for _, m := range []struct {
		substr, virt string
	}{
		{"QEMU", "kvm"},
		{"KVM", "kvm"},
		{"VMware", "vmware"},
		{"Xen", "xen"},
		{"Microsoft", "hyperv"},
		{"VirtualBox", "oracle"},
	} {
		if strings.Contains(vendor, m.substr) {
			return m.virt
		}
	}
	return "none"
}

// parseDpkgLogs scans /var/log/dpkg.log.1 then /var/log/dpkg.log.
// Returns Unix timestamps of the last kernel and general software updates.
func parseDpkgLogs() (kernelTS, softwareTS int64) {
	for _, path := range []string{"/var/log/dpkg.log.1", "/var/log/dpkg.log"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			action := fields[2]
			if action != "install" && action != "upgrade" {
				continue
			}
			t, err := time.ParseInLocation("2006-01-02 15:04:05", fields[0]+" "+fields[1], time.Local)
			if err != nil {
				continue
			}
			ts := t.Unix()
			if ts > softwareTS {
				softwareTS = ts
			}
			// Check for kernel package (linux-image).
			if len(fields) > 3 && strings.Contains(fields[3], "linux-image") {
				if ts > kernelTS {
					kernelTS = ts
				}
			}
		}
		f.Close()
	}
	return kernelTS, softwareTS
}

// rpmLastUpdate returns the Unix timestamp of the most recent rpm package update.
// If kernelOnly is true, only the kernel package is queried.
func rpmLastUpdate(ctx context.Context, kernelOnly bool) int64 {
	args := []string{"-qa", "--last"}
	if kernelOnly {
		args = append(args, "kernel")
	}
	out, err := exec.CommandContext(ctx, "rpm", args...).Output()
	if err != nil {
		return 0
	}
	// First non-empty line; format: "kernel-5.14.0-362.el9.x86_64  Wed Mar 10 05:32:11 2024"
	line := firstLine(out)
	if line == "" {
		return 0
	}
	// Find the date portion after the package name (separated by whitespace).
	// The date is the last 4 fields: "Wed Mar 10 05:32:11 2024"
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return 0
	}
	dateStr := strings.Join(fields[len(fields)-5:], " ")
	t, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", dateStr, time.Local)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func firstLine(b []byte) string {
	idx := bytes.IndexByte(b, '\n')
	if idx < 0 {
		return strings.TrimSpace(string(b))
	}
	return strings.TrimSpace(string(b[:idx]))
}
