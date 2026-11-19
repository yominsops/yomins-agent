package collector

import (
	"context"
	"testing"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

func hardwareWith(t *testing.T, files map[string]string) []metrics.MetricPoint {
	t.Helper()
	pts, err := NewHardwareCollector(fixture(t, files)).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return pts
}

// md0 is a RAID1 that lost a disk and is rebuilding onto a spare; md1 is a
// healthy RAID0; md127 is an inactive leftover with no level.
func TestHardware_MD(t *testing.T) {
	pts := hardwareWith(t, map[string]string{
		"sys/block/md0/md/level":                  "raid1\n",
		"sys/block/md0/md/array_state":            "clean\n",
		"sys/block/md0/md/raid_disks":             "2\n",
		"sys/block/md0/md/degraded":               "1\n",
		"sys/block/md0/md/sync_action":            "recover\n",
		"sys/block/md0/md/sync_completed":         "250 / 1000\n",
		"sys/block/md0/md/dev-sda1/state":         "in_sync\n",
		"sys/block/md0/md/dev-sdb1/state":         "faulty\n",
		"sys/block/md0/md/dev-sdc1/state":         "spare\n",
		"sys/block/md1/md/level":                  "raid0\n",
		"sys/block/md1/md/array_state":            "clean\n",
		"sys/block/md1/md/raid_disks":             "2\n",
		"sys/block/md1/md/dev-sdd1/state":         "in_sync\n",
		"sys/block/md127/md/level":                "\n",
		"sys/block/md127/md/array_state":          "inactive\n",
		"sys/devices/system/edac/mc/mc0/ce_count": "3\n",
		"sys/devices/system/edac/mc/mc0/ue_count": "0\n",
	})
	if v := find(t, pts, "raid_array_degraded_disks", "device", "md0", "level", "raid1"); v != 1 {
		t.Errorf("md0 degraded = %v", v)
	}
	if v := find(t, pts, "raid_array_failed_disks", "device", "md0"); v != 1 {
		t.Errorf("md0 failed = %v", v)
	}
	if v := find(t, pts, "raid_array_sync_action", "device", "md0", "action", "recover"); v != 1 {
		t.Errorf("md0 recover = %v", v)
	}
	if v := find(t, pts, "raid_array_sync_ratio", "device", "md0"); v != 0.25 {
		t.Errorf("md0 sync ratio = %v", v)
	}
	if v := find(t, pts, "raid_array_active", "device", "md1"); v != 1 {
		t.Errorf("md1 active = %v", v)
	}
	if has(pts, "raid_array_degraded_disks", "device", "md1") {
		t.Error("raid0 has no degraded count")
	}
	if has(pts, "raid_array_active", "device", "md127") {
		t.Error("inactive md127 reported")
	}
	if v := find(t, pts, "memory_ecc_errors_total", "controller", "mc0", "type", "corrected"); v != 3 {
		t.Errorf("ecc corrected = %v", v)
	}
}

func TestHardware_ZFSSensors(t *testing.T) {
	pts := hardwareWith(t, map[string]string{
		"proc/spl/kstat/zfs/tank/state":                                    "DEGRADED\n",
		"sys/class/hwmon/hwmon0/name":                                      "coretemp\n",
		"sys/class/hwmon/hwmon0/temp1_input":                               "54000\n",
		"sys/class/hwmon/hwmon0/temp1_label":                               "Package id 0\n",
		"sys/class/hwmon/hwmon0/temp1_crit":                                "100000\n",
		"sys/class/hwmon/hwmon1/name":                                      "coretemp\n",
		"sys/class/hwmon/hwmon1/temp2_input":                               "61500\n",
		"sys/class/hwmon/hwmon2/name":                                      "nct6775\n",
		"sys/class/hwmon/hwmon2/fan1_input":                                "0\n",
		"sys/devices/system/cpu/cpu0/thermal_throttle/core_throttle_count": "4\n",
		"sys/devices/system/cpu/cpu1/thermal_throttle/core_throttle_count": "1\n",
	})
	if v := find(t, pts, "zfs_pool_state", "pool", "tank", "state", "degraded"); v != 1 {
		t.Errorf("tank degraded = %v", v)
	}
	if v := find(t, pts, "zfs_pool_state", "pool", "tank", "state", "online"); v != 0 {
		t.Errorf("tank online = %v", v)
	}
	if v := find(t, pts, "hardware_temperature_celsius", "chip", "coretemp", "device", "coretemp.0", "sensor", "Package id 0"); v != 54 {
		t.Errorf("package temp = %v", v)
	}
	if v := find(t, pts, "hardware_temperature_critical_celsius", "sensor", "Package id 0"); v != 100 {
		t.Errorf("crit = %v", v)
	}
	// Two chips of the same name without a device link stay apart.
	if v := find(t, pts, "hardware_temperature_celsius", "device", "coretemp.1", "sensor", "temp2"); v != 61.5 {
		t.Errorf("second chip temp = %v", v)
	}
	if v := find(t, pts, "hardware_fan_rpm", "chip", "nct6775", "sensor", "fan1"); v != 0 {
		t.Errorf("fan = %v", v)
	}
	if v := find(t, pts, "cpu_thermal_throttle_events_total"); v != 5 {
		t.Errorf("throttle = %v", v)
	}
}

// A virtual machine: none of it exists, nothing is reported.
func TestHardware_VM(t *testing.T) {
	if pts := hardwareWith(t, map[string]string{"proc/meminfo": ""}); len(pts) != 0 {
		t.Errorf("got %d points on a bare VM", len(pts))
	}
}
