//go:build linux

package system

import (
	"strings"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/events"
)

func TestParseHardwareLine(t *testing.T) {
	cases := []struct {
		line, kind, dev string
		sev             events.Severity
	}{
		{"3,1201,889123,-;blk_update_request: I/O error, dev sda, sector 123456 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0", "disk_io", "sda", events.SeverityWarning},
		{"3,1202,889124,-;critical medium error, dev sdb, sector 9876 op 0x0:(READ) flags 0x80700", "disk_io", "sdb", events.SeverityWarning},
		{"3,1203,889125,-;I/O error, dev nvme0n1, sector 2048 op 0x1:(WRITE) flags 0x0", "disk_io", "nvme0n1", events.SeverityWarning},
		{"3,1204,889126,-;Buffer I/O error on dev sda1, logical block 0, async page read", "disk_io", "sda1", events.SeverityWarning},
		{"2,1205,889127,-;md/raid1:md0: Disk failure on sdb1, disabling device.", "raid_disk_failed", "md0", events.SeverityCritical},
		{"2,1206,889128,-;EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2: comm ls: reading directory lblock 0", "filesystem_error", "sda1", events.SeverityCritical},
		{"2,1207,889129,-;EXT4-fs (dm-0): Remounting filesystem read-only", "filesystem_readonly", "dm-0", events.SeverityCritical},
		{"1,1208,889130,-;XFS (sdc1): Corruption of in-memory data detected.  Shutting down filesystem", "filesystem_error", "sdc1", events.SeverityCritical},
		{"3,1209,889131,-;BTRFS error (device nvme0n1p2): bdev /dev/nvme0n1p2 errs: wr 0, rd 1, flush 0, corrupt 0, gen 0", "filesystem_error", "nvme0n1p2", events.SeverityCritical},
		{"4,1210,889132,-;nvme nvme0: I/O 512 QID 3 timeout, aborting", "nvme", "nvme0", events.SeverityWarning},
		{"4,1211,889133,-;nvme nvme1: controller is down; will reset: CSTS=0xffffffff", "nvme", "nvme1", events.SeverityWarning},
		{"3,1212,889134,-;ata3.00: failed command: READ FPDMA QUEUED", "ata", "ata3", events.SeverityWarning},
		{"4,1213,889135,-;EDAC MC0: 1 CE memory read error on CPU_SrcID#0_MC#0_Chan#1_DIMM#0 (channel:1 slot:0 page:0x12345)", "memory_ecc", "mc0", events.SeverityWarning},
		{"0,1214,889136,-;EDAC MC1: 1 UE memory read error on CPU_SrcID#1_Ha#0_Chan#0_DIMM#0", "memory_ecc", "mc1", events.SeverityCritical},
		{"2,1215,889137,-;mce: [Hardware Error]: Machine check events logged", "mce", "cpu", events.SeverityCritical},
	}
	for _, c := range cases {
		hw, ok := parseHardwareLine(c.line)
		if !ok || hw.kind != c.kind || hw.device != c.dev || hw.severity != c.sev {
			t.Errorf("%q → %+v %v, want %s %s %s", c.line, hw, ok, c.kind, c.dev, c.sev)
		}
		if strings.Contains(hw.message, ";") && strings.HasPrefix(hw.message, "3,") {
			t.Errorf("kmsg prefix kept: %q", hw.message)
		}
	}
	for _, l := range []string{
		"6,1,2,-;EXT4-fs (sda1): mounted filesystem with ordered data mode",
		"6,1,2,-;nvme nvme0: 8/0/0 default/read/poll queues",
		"6,1,2,-;EDAC MC0: Giving out device to module skx_edac controller Skylake Socket#0 IMC#0",
		" SUBSYSTEM=block",
		"6,1,2,-;md/raid1:md0: active with 2 out of 2 mirrors",
	} {
		if hw, ok := parseHardwareLine(l); ok {
			t.Errorf("%q matched as %+v", l, hw)
		}
	}
}

func TestHardwareEvent_RateLimit(t *testing.T) {
	c := NewCollector(Config{})
	t0 := time.Now()
	line := "3,1,2,-;I/O error, dev sda, sector 1 op 0x0:(READ)"
	ev, ok := c.hardwareEvent(line, t0)
	if !ok || ev.Type != events.EventSystemHardwareError || ev.Context.Service != "sda" {
		t.Fatalf("first: %+v %v", ev, ok)
	}
	for i := 1; i <= 5; i++ {
		if _, ok := c.hardwareEvent(line, t0.Add(time.Duration(i)*time.Minute)); ok {
			t.Fatal("not held back")
		}
	}
	// Another disk is reported at once.
	if _, ok := c.hardwareEvent("3,1,2,-;I/O error, dev sdb, sector 1 op", t0.Add(time.Minute)); !ok {
		t.Error("sdb held back by sda")
	}
	ev, ok = c.hardwareEvent(line, t0.Add(61*time.Minute))
	if !ok || !strings.Contains(ev.Context.Reason, "and 5 more") {
		t.Fatalf("after the hour: %+v %v", ev.Context, ok)
	}
}
