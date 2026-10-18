package collector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
	"github.com/yominsops/yomins-agent/internal/procfs"
)

// fixture writes files under a temp root laid out like /proc, /sys and /.
func fixture(t *testing.T, files map[string]string) HostPaths {
	t.Helper()
	dir := t.TempDir()
	for p, body := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return HostPaths{Proc: filepath.Join(dir, "proc"), Sys: filepath.Join(dir, "sys"), Root: dir}
}

// find returns the value of the point with this name and these labels.
func find(t *testing.T, pts []metrics.MetricPoint, name string, labels ...string) float64 {
	t.Helper()
	for _, p := range pts {
		if p.Name != name {
			continue
		}
		ok := true
		for i := 0; i+1 < len(labels); i += 2 {
			if p.Labels[labels[i]] != labels[i+1] {
				ok = false
			}
		}
		if ok {
			return p.Value
		}
	}
	t.Fatalf("no %s%v in %d points", name, labels, len(pts))
	return 0
}

func has(pts []metrics.MetricPoint, name string, labels ...string) bool {
	for _, p := range pts {
		if p.Name == name && (len(labels) < 2 || p.Labels[labels[0]] == labels[1]) {
			return true
		}
	}
	return false
}

func TestDiskIO(t *testing.T) {
	h := fixture(t, map[string]string{
		"proc/diskstats": `   8       0 sda 100 0 2000 50 300 0 4000 150 2 1200 1300 0 0 0 0
   8       1 sda1 90 0 1800 40 290 0 3900 140 0 1100 1200 0 0 0 0
   7       0 loop0 5 0 10 0 0 0 0 0 0 0 0 0 0 0 0
 253       0 dm-0 7 0 70 7 7 0 70 7 0 14 14 0 0 0 0
`,
		"sys/block/sda/size":  "1",
		"sys/block/dm-0/size": "1",
	})
	pts, err := NewDiskIOCollector(h).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v := find(t, pts, "disk_read_bytes_total", "device", "sda"); v != 2000*512 {
		t.Errorf("read bytes = %v", v)
	}
	if v := find(t, pts, "disk_io_time_seconds_total", "device", "sda"); v != 1.2 {
		t.Errorf("io time = %v", v)
	}
	if find(t, pts, "disk_io_now", "device", "sda") != 2 {
		t.Error("in progress")
	}
	if has(pts, "disk_reads_completed_total", "device", "sda1") || has(pts, "disk_reads_completed_total", "device", "loop0") {
		t.Error("partitions and loop devices are not reported")
	}
	if !has(pts, "disk_reads_completed_total", "device", "dm-0") {
		t.Error("device-mapper volumes are reported")
	}
}

func TestPressure(t *testing.T) {
	h := fixture(t, map[string]string{
		"proc/pressure/io": "some avg10=1.00 avg60=2.50 avg300=0.00 total=3000000\nfull avg10=0.00 avg60=1.25 avg300=0.00 total=1000000\n",
	})
	pts, _ := NewPressureCollector(h).Collect(context.Background())
	if v := find(t, pts, "pressure_stalled_seconds_total", "resource", "io", "kind", "some"); v != 3 {
		t.Errorf("some total = %v", v)
	}
	if v := find(t, pts, "pressure_stalled_percent", "resource", "io", "kind", "full"); v != 1.25 {
		t.Errorf("full avg60 = %v", v)
	}
	if has(pts, "pressure_stalled_seconds_total", "resource", "cpu") {
		t.Error("no cpu file, no cpu points")
	}
}

type fakeProcs struct{ samples []procfs.Sample }

func (f *fakeProcs) List(context.Context) ([]procfs.Sample, error) { return f.samples, nil }
func (f *fakeProcs) Details(int32) (string, string)                { return "", "" }
func (f *fakeProcs) MemTotal() uint64                              { return 0 }
func (f *fakeProcs) ClockTicks() float64                           { return 100 }

func TestKernel(t *testing.T) {
	h := fixture(t, map[string]string{
		"proc/meminfo":        "MemTotal: 100 kB\nCached:  2048 kB\nDirty: 4 kB\n",
		"proc/vmstat":         "pgmajfault 12\noom_kill 3\nnr_free_pages 1\n",
		"proc/stat":           "cpu 1 2 3\nctxt 999\nprocesses 77\n",
		"proc/sys/fs/file-nr": "1024\t0\t65536\n",
		"proc/sys/net/netfilter/nf_conntrack_count": "300\n",
		"proc/sys/net/netfilter/nf_conntrack_max":   "262144\n",
	})
	c := NewKernelCollector(h)
	c.procs = &fakeProcs{samples: []procfs.Sample{{State: 'R'}, {State: 'S'}, {State: 'D'}, {State: 'Z'}, {State: 'Z'}}}
	pts, _ := c.Collect(context.Background())
	checks := map[string]float64{
		"memory_cached_bytes": 2048 * 1024, "memory_dirty_bytes": 4096, "memory_major_page_faults_total": 12,
		"memory_oom_kills_total": 3, "system_context_switches_total": 999, "system_forks_total": 77,
		"system_open_files": 1024, "system_open_files_limit": 65536, "network_conntrack_entries": 300, "network_conntrack_limit": 262144,
	}
	for name, want := range checks {
		if v := find(t, pts, name); v != want {
			t.Errorf("%s = %v, want %v", name, v, want)
		}
	}
	if find(t, pts, "system_processes", "state", "zombie") != 2 || find(t, pts, "system_processes", "state", "blocked") != 1 {
		t.Error("process states")
	}
}

func TestNetstat(t *testing.T) {
	h := fixture(t, map[string]string{
		"proc/net/snmp": `Tcp: RtoAlgorithm ActiveOpens PassiveOpens RetransSegs
Tcp: 1 10 20 5
Udp: InDatagrams RcvbufErrors
Udp: 100 7
`,
		"proc/net/netstat": "TcpExt: SyncookiesSent ListenOverflows\nTcpExt: 0 42\n",
		"proc/net/tcp": `  sl  local_address rem_address   st
   0: 00000000:0050 00000000:0000 0A 00000000:00000000
   1: 0100007F:0050 0100007F:9C40 01 00000000:00000000
   2: 0100007F:0050 0100007F:9C41 06 00000000:00000000
`,
	})
	pts, err := NewNetstatCollector(h).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if find(t, pts, "tcp_retransmitted_segments_total") != 5 || find(t, pts, "tcp_listen_overflows_total") != 42 || find(t, pts, "udp_receive_buffer_errors_total") != 7 {
		t.Error("counters")
	}
	if find(t, pts, "tcp_connections", "state", "listen") != 1 || find(t, pts, "tcp_connections", "state", "time_wait") != 1 || find(t, pts, "tcp_connections", "state", "close_wait") != 0 {
		t.Error("states")
	}
}

func TestMounts(t *testing.T) {
	h := fixture(t, map[string]string{
		"proc/1/mounts": `/dev/sda1 / ext4 rw,relatime 0 0
proc /proc proc rw 0 0
/dev/sdb1 /data xfs ro,relatime 0 0
/dev/sda1 / ext4 rw 0 0
`,
	})
	pts, _ := NewMountsCollector(h).Collect(context.Background())
	if len(pts) != 2 || find(t, pts, "filesystem_readonly", "mountpoint", "/data") != 1 || find(t, pts, "filesystem_readonly", "mountpoint", "/") != 0 {
		t.Errorf("%v", pts)
	}
}

func TestSystemd(t *testing.T) {
	c := NewSystemdCollector()
	c.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch args[0] {
		case "list-units":
			return []byte("nginx.service loaded active running nginx\nphp8.3-fpm.service loaded active running PHP\napache2.service loaded inactive dead Apache\nbackup.service loaded failed failed Backup\nfoo.mount loaded active mounted x\n"), nil
		case "is-system-running":
			return []byte("degraded\n"), errors.New("exit status 1")
		case "show":
			if strings.Join(args[len(args)-2:], " ") != "nginx.service php8.3-fpm.service" {
				t.Errorf("show args %v", args)
			}
			return []byte("Id=nginx.service\nActiveState=active\nSubState=running\nNRestarts=0\n\nId=php8.3-fpm.service\nActiveState=activating\nSubState=auto-restart\nNRestarts=14\n"), nil
		}
		return nil, errors.New("unexpected")
	}
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if find(t, pts, "systemd_units_failed") != 1 || find(t, pts, "systemd_unit_failed", "unit", "backup.service") != 1 {
		t.Error("failed units")
	}
	if find(t, pts, "systemd_system_degraded") != 1 {
		t.Error("degraded")
	}
	if find(t, pts, "systemd_service_restarts_total", "unit", "php8.3-fpm.service") != 14 || find(t, pts, "systemd_service_active", "unit", "php8.3-fpm.service") != 0 {
		t.Error("tracked service")
	}
}

func TestUpdates(t *testing.T) {
	h := fixture(t, map[string]string{"run/reboot-required": ""})
	c := NewUpdatesCollector(h)
	c.lookup = func(n string) (string, error) {
		if n == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", errors.New("no")
	}
	c.run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("Inst libc6 [2.36-9] (2.36-9+deb12u9 Debian-Security:12/stable-security [arm64])\nInst vim [1] (2 Debian:12.8/stable [arm64])\nConf vim (2)\n"), nil
	}
	pts, _ := c.Collect(context.Background())
	if find(t, pts, "system_updates_pending", "kind", "all") != 2 || find(t, pts, "system_updates_pending", "kind", "security") != 1 || find(t, pts, "system_reboot_required") != 1 {
		t.Errorf("%v", pts)
	}
}

func TestUpdates_NewerKernelInstalled(t *testing.T) {
	h := fixture(t, map[string]string{"boot/vmlinuz-6.1.0-25-arm64": ""})
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(filepath.Join(h.Root, "boot/vmlinuz-6.1.0-26-arm64"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewUpdatesCollector(h)
	c.lookup = func(string) (string, error) { return "", errors.New("none") }
	c.release = func() string { return "6.1.0-25-arm64" }
	pts, _ := c.Collect(context.Background())
	if find(t, pts, "system_reboot_required") != 1 || has(pts, "system_updates_pending") {
		t.Errorf("%v", pts)
	}
}

func selfSigned(t *testing.T, cn string, notAfter time.Time) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: notAfter.Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCerts(t *testing.T) {
	exp := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	h := fixture(t, map[string]string{
		"etc/letsencrypt/live/metro.dp.ua/cert.pem": selfSigned(t, "metro.dp.ua", exp),
		"etc/nginx/conf.d/mail.conf":                "server {\n  ssl_certificate /etc/ssl/mail/fullchain.pem;\n  ssl_certificate_key /etc/ssl/mail/key.pem;\n}\n",
		"etc/ssl/mail/fullchain.pem":                selfSigned(t, "mail.example", exp.Add(24*time.Hour)),
	})
	pts, _ := NewCertsCollector(h, nil).Collect(context.Background())
	if len(pts) != 2 {
		t.Fatalf("%v", pts)
	}
	if v := find(t, pts, "tls_certificate_expiry_timestamp_seconds", "subject", "metro.dp.ua"); v != float64(exp.Unix()) {
		t.Errorf("expiry = %v", v)
	}
	if !has(pts, "tls_certificate_expiry_timestamp_seconds", "path", "/etc/ssl/mail/fullchain.pem") {
		t.Error("certificate named in nginx config")
	}
}

func TestProcessGroups(t *testing.T) {
	fp := &fakeProcs{samples: []procfs.Sample{
		{PID: 1, Name: "php-fpm", Start: 1, CPU: 100, RSS: 100},
		{PID: 2, Name: "php-fpm", Start: 1, CPU: 100, RSS: 100},
		{PID: 3, Name: "mysqld", Start: 1, CPU: 0, RSS: 1000},
		{PID: 4, Name: "tiny", Start: 1, CPU: 0, RSS: 1},
		{PID: 5, Name: "zomb", State: 'Z'},
	}}
	c := NewProcessGroupsCollector(2)
	c.procs = fp
	at := time.Unix(1000, 0)
	c.now = func() time.Time { return at }
	pts, _ := c.Collect(context.Background())
	if has(pts, "process_group_cpu_percent") {
		t.Error("no CPU on the first pass")
	}
	if find(t, pts, "process_group_count", "process", "php-fpm") != 2 || has(pts, "process_group_count", "process", "tiny") {
		t.Errorf("top by memory: %v", pts)
	}
	fp.samples[0].CPU, fp.samples[1].CPU = 150, 200 // 1.5 s of CPU in 10 s
	at = at.Add(10 * time.Second)
	pts, _ = c.Collect(context.Background())
	if v := find(t, pts, "process_group_cpu_percent", "process", "php-fpm"); v != 15 {
		t.Errorf("cpu = %v, want 15", v)
	}
}

type countingCollector struct{ n int }

func (c *countingCollector) Name() string { return "counting" }
func (c *countingCollector) Collect(context.Context) ([]metrics.MetricPoint, error) {
	c.n++
	return []metrics.MetricPoint{{Name: "x", Value: float64(c.n)}}, nil
}

func TestEvery(t *testing.T) {
	inner := &countingCollector{}
	at := time.Unix(0, 0)
	e := Every(time.Hour, inner).(*everyCollector)
	e.now = func() time.Time { return at }
	_, _ = e.Collect(context.Background())
	at = at.Add(30 * time.Minute)
	pts, _ := e.Collect(context.Background())
	if inner.n != 1 || pts[0].Value != 1 {
		t.Error("cached within the ttl")
	}
	at = at.Add(31 * time.Minute)
	_, _ = e.Collect(context.Background())
	if inner.n != 2 {
		t.Error("run again after the ttl")
	}
}
