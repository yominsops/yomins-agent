//go:build linux

package collector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
)

type realInfoReader struct {
	virtOverride string

	pkgMu    sync.Mutex
	pkgTimes *PackageUpdateTimes
	pkgAt    time.Time
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
	r.pkgMu.Lock()
	defer r.pkgMu.Unlock()
	// The package database changes rarely and rpm -qa reads all of it, so
	// the answer is kept for a while instead of being rebuilt on every push.
	if r.pkgTimes != nil && time.Since(r.pkgAt) < packageTimesTTL {
		return r.pkgTimes, nil
	}
	put := &PackageUpdateTimes{}
	if _, err := exec.LookPath("dpkg"); err == nil {
		// Debian/Ubuntu: dpkg.log names each install and upgrade; once it
		// has been rotated away, the package lists' times say the same.
		put.LastKernelUpdate, put.LastSoftwareUpdate = parseDpkgLogs()
		if put.LastSoftwareUpdate == 0 {
			put.LastKernelUpdate, put.LastSoftwareUpdate = dpkgInfoTimes("/var/lib/dpkg/info")
		}
	} else if _, err := exec.LookPath("rpm"); err == nil {
		// RHEL and its rebuilds, Fedora, Amazon Linux, SUSE, CloudLinux.
		out, err := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{INSTALLTIME} %{NAME}\\n").Output()
		if err != nil {
			return put, nil // not kept: the next push asks again
		}
		put.LastKernelUpdate, put.LastSoftwareUpdate = rpmInstallTimes(out)
	}
	r.pkgTimes, r.pkgAt = put, time.Now()
	return put, nil
}

// packageTimesTTL is how long the last package update times are reused.
const packageTimesTTL = 10 * time.Minute

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

func (r *realInfoReader) MemoryInfoWithContext(ctx context.Context) (*MemoryInfo, error) {
	info := &MemoryInfo{TotalMB: readMemTotalMB()}

	// Per-DIMM details from dmidecode (optional, requires root).
	if _, err := exec.LookPath("dmidecode"); err == nil {
		if out, err := exec.CommandContext(ctx, "dmidecode", "--type", "17").Output(); err == nil {
			info.Modules = parseDmidecodeMemory(out)
		}
	}

	return info, nil
}

// readMemTotalMB reads the total physical memory from /proc/meminfo.
func readMemTotalMB() int {
	f, err := os.Open("/proc/meminfo")
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
		// Format: "MemTotal:       32768000 kB"
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if kb, err := strconv.Atoi(fields[1]); err == nil {
				return kb / 1024
			}
		}
	}
	return 0
}

func (r *realInfoReader) DiskHardwareWithContext(_ context.Context) ([]DiskHardwareStat, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	var disks []DiskHardwareStat
	for _, e := range entries {
		dev := e.Name()
		if isVirtualBlockDevice(dev) {
			continue
		}
		d := DiskHardwareStat{Device: dev}

		// Size: sectors × 512 → decimal GB
		if data, err := os.ReadFile(fmt.Sprintf("/sys/block/%s/size", dev)); err == nil {
			if sectors, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
				d.SizeGB = int(sectors * 512 / 1_000_000_000)
			}
		}

		// Type + Transport
		if strings.HasPrefix(dev, "nvme") {
			d.Type = "nvme"
			d.Transport = "nvme"
		} else {
			rotPath := fmt.Sprintf("/sys/block/%s/queue/rotational", dev)
			if data, err := os.ReadFile(rotPath); err == nil {
				switch strings.TrimSpace(string(data)) {
				case "0":
					d.Type = "ssd"
				case "1":
					d.Type = "hdd"
				}
			}
			d.Transport = diskTransport(dev)
		}

		// Model
		if model, err := readTrimmed(fmt.Sprintf("/sys/block/%s/device/model", dev)); err == nil {
			d.Model = model
		}

		disks = append(disks, d)
	}
	return disks, nil
}

func (r *realInfoReader) NetworkHardwareWithContext(_ context.Context) ([]NetworkHardwareStat, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var nics []NetworkHardwareStat
	for _, e := range entries {
		iface := e.Name()
		// Only physical NICs have a "device" entry.
		if _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/device", iface)); err != nil {
			continue
		}

		n := NetworkHardwareStat{Interface: iface}

		if data, err := readTrimmed(fmt.Sprintf("/sys/class/net/%s/speed", iface)); err == nil {
			if v, err := strconv.Atoi(data); err == nil && v > 0 {
				n.SpeedMbps = v
			}
		}
		if data, err := readTrimmed(fmt.Sprintf("/sys/class/net/%s/operstate", iface)); err == nil {
			n.State = data
		} else {
			n.State = "unknown"
		}
		if data, err := readTrimmed(fmt.Sprintf("/sys/class/net/%s/duplex", iface)); err == nil {
			n.Duplex = data
		} else {
			n.Duplex = "unknown"
		}

		nics = append(nics, n)
	}
	return nics, nil
}

func (r *realInfoReader) SystemHardwareWithContext(_ context.Context) (*SystemHardwareStat, error) {
	vendor, _ := readTrimmed("/sys/class/dmi/id/sys_vendor")
	product, _ := readTrimmed("/sys/class/dmi/id/product_name")
	return &SystemHardwareStat{Vendor: vendor, Product: product}, nil
}

// parseDmidecodeMemory parses `dmidecode --type 17` output into module stats.
func parseDmidecodeMemory(out []byte) []MemoryModuleStat {
	var result []MemoryModuleStat
	// Records are separated by blank lines; each memory device starts with "Memory Device"
	records := bytes.Split(out, []byte("\n\n"))
	for _, rec := range records {
		lines := strings.Split(string(rec), "\n")
		// Check this is a Memory Device record.
		isMemDevice := false
		for _, l := range lines {
			if strings.TrimSpace(l) == "Memory Device" {
				isMemDevice = true
				break
			}
		}
		if !isMemDevice {
			continue
		}

		var m MemoryModuleStat
		locatorSet := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			k, v, ok := strings.Cut(line, ": ")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch k {
			case "Size":
				if v == "No Module Installed" || v == "Unknown" {
					m.SizeMB = 0
				} else if strings.HasSuffix(v, " GB") {
					if n, err := strconv.Atoi(strings.TrimSuffix(v, " GB")); err == nil {
						m.SizeMB = n * 1024
					}
				} else if strings.HasSuffix(v, " MB") {
					if n, err := strconv.Atoi(strings.TrimSuffix(v, " MB")); err == nil {
						m.SizeMB = n
					}
				}
			case "Type":
				if v != "Unknown" {
					m.Type = v
				}
			case "Speed":
				// "2666 MT/s" or "Unknown"
				if v != "Unknown" {
					fields := strings.Fields(v)
					if len(fields) > 0 {
						if n, err := strconv.Atoi(fields[0]); err == nil {
							m.SpeedMhz = n
						}
					}
				}
			case "Manufacturer":
				if v != "Not Specified" && v != "Unknown" {
					m.Manufacturer = v
				}
			case "Locator":
				// Take the first "Locator:" (not "Bank Locator:").
				if !locatorSet {
					m.Locator = v
					locatorSet = true
				}
			}
		}
		if m.SizeMB > 0 {
			result = append(result, m)
		}
	}
	return result
}

// isVirtualBlockDevice returns true for device names that are not physical disks.
func isVirtualBlockDevice(dev string) bool {
	for _, prefix := range []string{"loop", "ram", "zram", "dm-", "md", "sr", "nbd"} {
		if strings.HasPrefix(dev, prefix) {
			return true
		}
	}
	return false
}

// diskTransport attempts to determine the transport type for a non-NVMe block device.
func diskTransport(dev string) string {
	subsysPath := fmt.Sprintf("/sys/block/%s/device/subsystem", dev)
	target, err := os.Readlink(subsysPath)
	if err != nil {
		return "unknown"
	}
	target = strings.ToLower(target)
	if strings.Contains(target, "scsi") {
		return "sata"
	}
	if strings.Contains(target, "nvme") {
		return "nvme"
	}
	return "unknown"
}

// readTrimmed reads a file and returns its content with leading/trailing whitespace removed.
func readTrimmed(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
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

// reKernelRPM matches the kernel packages of the RPM distributions: kernel
// (RHEL 7, CloudLinux), kernel-core (RHEL 8+, Fedora), kernel-default (SUSE),
// kernel-uek (Oracle), kernel-lt/ml (ELRepo), kernel-rt.
var reKernelRPM = regexp.MustCompile(`^kernel(-(core|default|uek|lt|ml|rt))?$`)

// rpmInstallTimes reads `rpm -qa --qf '%{INSTALLTIME} %{NAME}\n'`. A number
// is used rather than `rpm --last`, whose date follows the locale
// ("Thu 19 Nov 2026 01:22:25 PM UTC" with en_US.UTF-8).
func rpmInstallTimes(out []byte) (kernelTS, softwareTS int64) {
	for _, line := range strings.Split(string(out), "\n") {
		ts, name, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		t, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			continue
		}
		if t > softwareTS {
			softwareTS = t
		}
		if reKernelRPM.MatchString(name) && t > kernelTS {
			kernelTS = t
		}
	}
	return kernelTS, softwareTS
}

// dpkgInfoTimes returns the newest modification times of the package file
// lists in /var/lib/dpkg/info: dpkg rewrites a package's list when it
// installs or upgrades it.
func dpkgInfoTimes(dir string) (kernelTS, softwareTS int64) {
	lists, _ := filepath.Glob(filepath.Join(dir, "*.list"))
	for _, l := range lists {
		fi, err := os.Stat(l)
		if err != nil {
			continue
		}
		t := fi.ModTime().Unix()
		if t > softwareTS {
			softwareTS = t
		}
		if strings.HasPrefix(filepath.Base(l), "linux-image-") && t > kernelTS {
			kernelTS = t
		}
	}
	return kernelTS, softwareTS
}
