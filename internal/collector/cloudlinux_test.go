package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The /proc/lve/list sample of the CloudLinux documentation (limits).
const lveListDoc = `4:LVE EP lCPU lIO CPU MEM IO lMEM lEP nCPU fMEM fEP
0 0 75 25 0 0 0 262144 20 2 0 0
500 0 75 25 0 0 0 4294967 20 3 2 1
700 1 75 25 1403247 202 0 262144 20 2 0 0
`

func TestCloudLinux(t *testing.T) {
	h := fixture(t, map[string]string{
		"etc/sysconfig/lve":                  "LVE_ENABLE=\"yes\"\nLVE_PMEM=\"1G\"\n",
		"proc/lve/list":                      lveListDoc,
		"usr/share/cagefs-skeleton/bin/sh":   "",
		"etc/cagefs/users.disabled/01/bob":   "",
		"etc/cagefs/users.disabled/02/carol": "",
		"etc/cagefs/cagefs.mp":               "/var/lib/mysql\n",
	})
	if err := os.MkdirAll(filepath.Join(h.Root, "etc/cagefs/users.enabled"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := NewCloudLinuxCollector(h)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v := find(t, pts, "cloudlinux_lve_enabled"); v != 1 {
		t.Errorf("enabled = %v", v)
	}
	if v := find(t, pts, "cloudlinux_lve_accounts"); v != 2 {
		t.Errorf("accounts = %v", v)
	}
	if v := find(t, pts, "cloudlinux_lve_faults_total", "limit", "mem"); v != 2 {
		t.Errorf("fMEM = %v", v)
	}
	if v := find(t, pts, "cloudlinux_lve_faults_total", "limit", "ep"); v != 1 {
		t.Errorf("fEP = %v", v)
	}
	if v := find(t, pts, "cloudlinux_lve_entry_processes"); v != 1 {
		t.Errorf("EP = %v", v)
	}
	if has(pts, "cloudlinux_lve_accounts_at_limit") {
		t.Error("accounts at limit needs a previous collection")
	}
	if v := find(t, pts, "cloudlinux_cagefs_listed_users", "list", "disabled"); v != 2 {
		t.Errorf("cagefs disabled = %v", v)
	}
	if v := find(t, pts, "cloudlinux_cagefs_listed_users", "list", "enabled"); v != 0 {
		t.Errorf("cagefs enabled = %v", v)
	}

	// Account 700 hits its entry process limit twice.
	next := `4:LVE EP lCPU lIO CPU MEM IO lMEM lEP nCPU fMEM fEP
0 0 75 25 0 0 0 262144 20 2 0 0
500 0 75 25 0 0 0 4294967 20 3 2 1
700 20 75 25 1403247 202 0 262144 20 2 0 2
`
	if err := os.WriteFile(filepath.Join(h.Proc, "lve/list"), []byte(next), 0o644); err != nil {
		t.Fatal(err)
	}
	pts, _ = c.Collect(context.Background())
	if v := find(t, pts, "cloudlinux_lve_accounts_at_limit", "limit", "ep"); v != 1 {
		t.Errorf("at ep limit = %v", v)
	}
	if v := find(t, pts, "cloudlinux_lve_accounts_at_limit", "limit", "mem"); v != 0 {
		t.Errorf("at mem limit = %v", v)
	}
}

// A newer layout with more columns, read by its header.
func TestCloudLinux_NewerHeader(t *testing.T) {
	h := fixture(t, map[string]string{
		"proc/lve/list": "8:LVE EP lCPU lIO CPU MEM IO lMEM lEP nCPU fMEM fEP MEMPHY lMEMPHY fMEMPHY NPROC lNPROC fNPROC\n" +
			"1001 3 100 1024 5 100 0 262144 20 1 0 4 2000 262144 7 12 100 0\n",
	})
	pts, _ := NewCloudLinuxCollector(h).Collect(context.Background())
	if v := find(t, pts, "cloudlinux_lve_faults_total", "limit", "memphy"); v != 7 {
		t.Errorf("fMEMPHY = %v", v)
	}
	if v := find(t, pts, "cloudlinux_lve_processes"); v != 12 {
		t.Errorf("NPROC = %v", v)
	}
	if has(pts, "cloudlinux_lve_enabled") || has(pts, "cloudlinux_cagefs_initialized") {
		t.Error("no sysconfig, no cagefs: nothing to say")
	}
}

func TestCloudLinux_NotCloudLinux(t *testing.T) {
	pts, _ := NewCloudLinuxCollector(fixture(t, map[string]string{"etc/os-release": "ID=debian\n"})).Collect(context.Background())
	if len(pts) != 0 {
		t.Errorf("got %v", pts)
	}
}
