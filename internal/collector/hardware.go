package collector

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// HardwareCollector reports the health of the hardware under the OS, all
// from files any user can read: software RAID (md) arrays, ZFS pools, memory
// ECC errors (EDAC), temperature and fan sensors (hwmon) and CPU thermal
// throttling. On a virtual machine most of it is absent, and so are the
// metrics. Disk SMART data needs root and comes from the SMART collector.
type HardwareCollector struct {
	paths HostPaths
}

// NewHardwareCollector creates the collector.
func NewHardwareCollector(paths HostPaths) *HardwareCollector {
	return &HardwareCollector{paths: paths}
}

func (c *HardwareCollector) Name() string { return "hardware" }

func (c *HardwareCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	pts = append(pts, c.mdArrays()...)
	pts = append(pts, c.zfsPools()...)
	pts = append(pts, c.edac()...)
	pts = append(pts, c.hwmon()...)
	pts = append(pts, c.throttle()...)
	return pts, nil
}

func readTrim(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// ── Software RAID ────────────────────────────────────────────────────────────

// mdActiveStates are the array_state values of an array serving I/O.
var mdActiveStates = map[string]bool{
	"clean": true, "active": true, "active-idle": true, "write-pending": true, "read-auto": true,
}

var mdSyncActions = []string{"idle", "resync", "recover", "check", "repair", "reshape", "frozen"}

func (c *HardwareCollector) mdArrays() []metrics.MetricPoint {
	var pts []metrics.MetricPoint
	dirs, _ := filepath.Glob(c.paths.sys("block", "md*", "md"))
	sort.Strings(dirs)
	for _, dir := range dirs {
		level, ok := readTrim(filepath.Join(dir, "level"))
		if !ok || level == "" { // an inactive or half-assembled array
			continue
		}
		dev := filepath.Base(filepath.Dir(dir))
		l := map[string]string{"device": dev, "level": level}
		state, _ := readTrim(filepath.Join(dir, "array_state"))
		pts = append(pts, gauge("raid_array_active", "1 when the md array serves I/O (array_state clean, active, read-auto ...)", b2f(mdActiveStates[state]), l))
		if n, ok := readUint(filepath.Join(dir, "raid_disks")); ok {
			pts = append(pts, gauge("raid_array_disks", "Member disks the md array is built for", float64(n), l))
		}
		if n, ok := readUint(filepath.Join(dir, "degraded")); ok { // raid0 and linear have none
			pts = append(pts, gauge("raid_array_degraded_disks", "Member disks the md array is missing: above 0 it runs without full redundancy", float64(n), l))
		}
		failed := 0
		members, _ := filepath.Glob(filepath.Join(dir, "dev-*", "state"))
		for _, m := range members {
			if s, ok := readTrim(m); ok && strings.Contains(s, "faulty") {
				failed++
			}
		}
		pts = append(pts, gauge("raid_array_failed_disks", "Member disks of the md array marked faulty", float64(failed), l))
		if action, ok := readTrim(filepath.Join(dir, "sync_action")); ok {
			for _, a := range mdSyncActions {
				pts = append(pts, gauge("raid_array_sync_action", "What the md array is doing (1 for the current one): idle, resync, recover (rebuild), check, repair, reshape", b2f(a == action), map[string]string{"device": dev, "action": a}))
			}
			if done, ok := readTrim(filepath.Join(dir, "sync_completed")); ok && action != "idle" {
				if a, b, ok := strings.Cut(done, "/"); ok {
					x, err1 := strconv.ParseFloat(strings.TrimSpace(a), 64)
					y, err2 := strconv.ParseFloat(strings.TrimSpace(b), 64)
					if err1 == nil && err2 == nil && y > 0 {
						pts = append(pts, gauge("raid_array_sync_ratio", "How far the running resync, rebuild or check is (0–1)", x/y, map[string]string{"device": dev}))
					}
				}
			}
		}
	}
	return pts
}

// ── ZFS ──────────────────────────────────────────────────────────────────────

var zfsStates = []string{"ONLINE", "DEGRADED", "FAULTED", "OFFLINE", "UNAVAIL", "REMOVED", "SUSPENDED"}

func (c *HardwareCollector) zfsPools() []metrics.MetricPoint {
	var pts []metrics.MetricPoint
	files, _ := filepath.Glob(c.paths.proc("spl", "kstat", "zfs", "*", "state"))
	sort.Strings(files)
	for _, f := range files {
		state, ok := readTrim(f)
		if !ok {
			continue
		}
		pool := filepath.Base(filepath.Dir(f))
		for _, s := range zfsStates {
			pts = append(pts, gauge("zfs_pool_state", "ZFS pool health (1 for the current one): ONLINE is healthy, DEGRADED runs without full redundancy", b2f(strings.EqualFold(s, state)), map[string]string{"pool": pool, "state": strings.ToLower(s)}))
		}
	}
	return pts
}

// ── Memory ECC (EDAC) ────────────────────────────────────────────────────────

func (c *HardwareCollector) edac() []metrics.MetricPoint {
	var pts []metrics.MetricPoint
	mcs, _ := filepath.Glob(c.paths.sys("devices", "system", "edac", "mc", "mc[0-9]*"))
	sort.Strings(mcs)
	for _, mc := range mcs {
		name := filepath.Base(mc)
		if n, ok := readUint(filepath.Join(mc, "ce_count")); ok {
			pts = append(pts, counter("memory_ecc_errors_total", "Memory errors the ECC caught, by memory controller: corrected ones are a warning that a module is failing, uncorrected ones crash or corrupt", float64(n), map[string]string{"controller": name, "type": "corrected"}))
		}
		if n, ok := readUint(filepath.Join(mc, "ue_count")); ok {
			pts = append(pts, counter("memory_ecc_errors_total", "Memory errors the ECC caught, by memory controller: corrected ones are a warning that a module is failing, uncorrected ones crash or corrupt", float64(n), map[string]string{"controller": name, "type": "uncorrected"}))
		}
	}
	return pts
}

// ── Sensors (hwmon) ──────────────────────────────────────────────────────────

func (c *HardwareCollector) hwmon() []metrics.MetricPoint {
	var pts []metrics.MetricPoint
	chips, _ := filepath.Glob(c.paths.sys("class", "hwmon", "hwmon*"))
	sort.Strings(chips)
	seen := map[string]int{}
	for _, chip := range chips {
		name, ok := readTrim(filepath.Join(chip, "name"))
		if !ok {
			continue
		}
		// The device the chip belongs to (coretemp.0, nvme0, 0000:00:18.3)
		// tells two chips with the same name apart; hwmonN numbers change
		// between boots.
		dev := ""
		if target, err := filepath.EvalSymlinks(filepath.Join(chip, "device")); err == nil {
			dev = filepath.Base(target)
		}
		if dev == "" {
			seen[name]++
			dev = name + "." + strconv.Itoa(seen[name]-1)
		}
		temps, _ := filepath.Glob(filepath.Join(chip, "temp*_input"))
		sort.Strings(temps)
		for _, t := range temps {
			v, ok := readInt(t)
			if !ok {
				continue
			}
			base := strings.TrimSuffix(t, "_input")
			sensor := filepath.Base(base)
			if lbl, ok := readTrim(base + "_label"); ok && lbl != "" {
				sensor = lbl
			}
			l := map[string]string{"chip": name, "device": dev, "sensor": sensor}
			pts = append(pts, gauge("hardware_temperature_celsius", "Temperature reported by a hardware sensor (CPU, board, disk, NVMe)", float64(v)/1000, l))
			if crit, ok := readInt(base + "_crit"); ok && crit > 0 {
				pts = append(pts, gauge("hardware_temperature_critical_celsius", "The sensor's critical temperature: the hardware throttles or shuts down there", float64(crit)/1000, l))
			} else if max, ok := readInt(base + "_max"); ok && max > 0 {
				pts = append(pts, gauge("hardware_temperature_critical_celsius", "The sensor's critical temperature: the hardware throttles or shuts down there", float64(max)/1000, l))
			}
		}
		fans, _ := filepath.Glob(filepath.Join(chip, "fan*_input"))
		sort.Strings(fans)
		for _, f := range fans {
			v, ok := readUint(f)
			if !ok {
				continue
			}
			base := strings.TrimSuffix(f, "_input")
			sensor := filepath.Base(base)
			if lbl, ok := readTrim(base + "_label"); ok && lbl != "" {
				sensor = lbl
			}
			pts = append(pts, gauge("hardware_fan_rpm", "Fan speed: 0 on a fan that should spin means it has stopped", float64(v), map[string]string{"chip": name, "device": dev, "sensor": sensor}))
		}
	}
	return pts
}

func readInt(path string) (int64, bool) {
	s, ok := readTrim(path)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

// ── CPU thermal throttling ───────────────────────────────────────────────────

func (c *HardwareCollector) throttle() []metrics.MetricPoint {
	files, _ := filepath.Glob(c.paths.sys("devices", "system", "cpu", "cpu[0-9]*", "thermal_throttle", "core_throttle_count"))
	if len(files) == 0 {
		return nil
	}
	var total uint64
	for _, f := range files {
		if n, ok := readUint(f); ok {
			total += n
		}
	}
	return []metrics.MetricPoint{counter("cpu_thermal_throttle_events_total", "Times a CPU core slowed itself down because it was too hot, all cores together", float64(total), nil)}
}
