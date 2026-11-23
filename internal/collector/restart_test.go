package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/restartscan"
)

func TestRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.json")
	c := NewRestartCollector(path)

	if pts, err := c.Collect(context.Background()); err != nil || len(pts) != 0 {
		t.Fatalf("no report: %v %v", pts, err)
	}

	now := time.Now().UTC()
	r := restartscan.Report{Version: restartscan.ReportVersion, Time: now.Add(-10 * time.Minute), Units: []string{"nginx.service", "php8.3-fpm.service"}, Other: 1}
	if err := restartscan.Write(path, r); err != nil {
		t.Fatal(err)
	}
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v := find(t, pts, "system_services_restart_required"); v != 2 {
		t.Errorf("services = %v", v)
	}
	if v := find(t, pts, "system_service_restart_required", "unit", "php8.3-fpm.service"); v != 1 {
		t.Errorf("php = %v", v)
	}
	if v := find(t, pts, "system_processes_restart_required_other"); v != 1 {
		t.Errorf("other = %v", v)
	}
	if v := find(t, pts, "restart_scan_ok"); v != 1 {
		t.Errorf("ok = %v", v)
	}

	// A stale report: the timer stopped, the readings are dropped.
	c.now = func() time.Time { return now.Add(4 * time.Hour) }
	pts, _ = c.Collect(context.Background())
	if has(pts, "system_services_restart_required") || !has(pts, "restart_scan_timestamp_seconds") {
		t.Errorf("stale: %v", pts)
	}

	// A failed scan.
	c.now = time.Now
	r.Error = "open /proc: permission denied"
	if err := restartscan.Write(path, r); err != nil {
		t.Fatal(err)
	}
	pts, _ = c.Collect(context.Background())
	if find(t, pts, "restart_scan_ok") != 0 || has(pts, "system_services_restart_required") {
		t.Errorf("failed scan: %v", pts)
	}

	// A broken report is an error.
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Collect(context.Background()); err == nil {
		t.Error("broken report must fail")
	}
}
