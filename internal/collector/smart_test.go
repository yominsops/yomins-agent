package collector

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/smart"
)

func TestSMART(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smart.json")
	c := NewSMARTCollector(path)

	// No report: an install without the timer, nothing reported.
	if pts, err := c.Collect(context.Background()); err != nil || len(pts) != 0 {
		t.Fatalf("no report: %v %v", pts, err)
	}

	now := time.Now().UTC()
	healthy, failing := true, false
	temp, hours := 36.0, 1200.0
	r := smart.Report{Version: smart.ReportVersion, Time: now.Add(-10 * time.Minute), Smartctl: true, Devices: []smart.Device{
		{Name: "/dev/sda", Type: "sat", Protocol: "ATA", Model: "ST4000", Serial: "Z1", Healthy: &healthy, TemperatureC: &temp, PowerOnHours: &hours,
			Attributes: map[string]float64{"pending_sectors": 2}},
		{Name: "/dev/sdb", Type: "sat", Protocol: "ATA", Model: "WD", Serial: "W1", Healthy: &failing},
	}}
	if err := smart.Write(path, r); err != nil {
		t.Fatal(err)
	}
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v := find(t, pts, "smart_device_healthy", "device", "/dev/sdb"); v != 0 {
		t.Errorf("sdb healthy = %v", v)
	}
	if v := find(t, pts, "smart_attribute", "device", "/dev/sda", "attribute", "pending_sectors"); v != 2 {
		t.Errorf("pending = %v", v)
	}
	if v := find(t, pts, "smart_temperature_celsius", "device", "/dev/sda"); v != 36 {
		t.Errorf("temp = %v", v)
	}
	if v := find(t, pts, "smart_scan_ok"); v != 1 {
		t.Errorf("scan ok = %v", v)
	}

	// The timer stopped: old readings are dropped, the timestamp stays.
	c.now = func() time.Time { return now.Add(4 * time.Hour) }
	pts, _ = c.Collect(context.Background())
	if has(pts, "smart_device_healthy") {
		t.Error("stale readings reported")
	}
	find(t, pts, "smart_scan_timestamp_seconds")

	// smartmontools missing.
	if err := smart.Write(path, smart.Report{Version: smart.ReportVersion, Time: now}); err != nil {
		t.Fatal(err)
	}
	c.now = time.Now
	pts, _ = c.Collect(context.Background())
	if v := find(t, pts, "smart_smartctl_installed"); v != 0 {
		t.Errorf("installed = %v", v)
	}
}
