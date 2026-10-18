package integrations

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

func val(t *testing.T, pts []metrics.MetricPoint, name string, kv ...string) float64 {
	t.Helper()
	for _, p := range pts {
		if p.Name != name {
			continue
		}
		ok := true
		for i := 0; i+1 < len(kv); i += 2 {
			if p.Labels[kv[i]] != kv[i+1] {
				ok = false
			}
		}
		if ok {
			return p.Value
		}
	}
	t.Fatalf("no %s%v", name, kv)
	return 0
}

func statusOf(pts []metrics.MetricPoint, integration string) string {
	for _, p := range pts {
		if p.Name == "agent_integration_status" && p.Labels["integration"] == integration {
			return p.Labels["status"]
		}
	}
	return ""
}

func TestNginx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nginx_status" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "Active connections: 291 \nserver accepts handled requests\n 16630948 16630948 31070465 \nReading: 6 Writing: 179 Waiting: 106 \n")
	}))
	defer srv.Close()

	n := NewNginx("")
	n.urls = []string{srv.URL + "/stub_status", srv.URL + "/nginx_status"}
	n.installed = func() bool { return true }
	pts, _ := n.Collect(context.Background())
	if statusOf(pts, "nginx") != StatusOK || val(t, pts, "nginx_connections_active") != 291 || val(t, pts, "nginx_requests_total") != 31070465 ||
		val(t, pts, "nginx_connections", "state", "waiting") != 106 {
		t.Errorf("%v", pts)
	}
	if n.found != srv.URL+"/nginx_status" {
		t.Error("the working URL is remembered")
	}

	none := NewNginx(srv.URL + "/nope")
	none.installed = func() bool { return true }
	if pts, _ := none.Collect(context.Background()); statusOf(pts, "nginx") != StatusUnconfigured {
		t.Errorf("no status page: %v", pts)
	}
	absent := NewNginx("")
	absent.installed = func() bool { return false }
	if pts, _ := absent.Collect(context.Background()); len(pts) != 0 {
		t.Error("nothing when nginx is not installed")
	}
}

// fakeFPM answers FastCGI requests with body after a CGI header.
func fakeFPM(t *testing.T, sock string, head, body string) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for { // read records until the empty STDIN
					var h [8]byte
					if _, err := io.ReadFull(c, h[:]); err != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(h[4:6])) + int(h[6])
					if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
						return
					}
					if h[1] == fcgiStdin && binary.BigEndian.Uint16(h[4:6]) == 0 {
						break
					}
				}
				var out bytes.Buffer
				fcgiRecord(&out, fcgiStdout, []byte(head+"\r\n\r\n"+body))
				fcgiRecord(&out, fcgiEndRequest, make([]byte, 8))
				c.Write(out.Bytes())
			}(conn)
		}
	}()
}

func TestPHPFPM(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "fpm.sock")
	fakeFPM(t, sock, "Content-type: application/json", `{"pool":"www","accepted conn":120,"listen queue":3,"max listen queue":9,"idle processes":4,"active processes":6,"max active processes":10,"max children reached":2,"slow requests":5}`)
	conf := filepath.Join(dir, "php", "8.3", "fpm", "pool.d", "www.conf")
	os.MkdirAll(filepath.Dir(conf), 0o755)
	os.WriteFile(conf, []byte("[www]\nlisten = "+sock+"\n;pm.status_path = /old\npm.status_path = /fpm-status\n\n[other]\nlisten = 127.0.0.1:9001\n"), 0o644)

	p := NewPHPFPM()
	p.globs = []string{filepath.Join(dir, "php", "*", "fpm", "pool.d", "*.conf")}
	pts, _ := p.Collect(context.Background())
	if val(t, pts, "phpfpm_processes", "pool", "8.3/www", "state", "active") != 6 || val(t, pts, "phpfpm_max_children_reached_total", "pool", "8.3/www") != 2 ||
		val(t, pts, "phpfpm_listen_queue", "pool", "8.3/www") != 3 {
		t.Errorf("%v", pts)
	}
	unconfigured := false
	for _, pt := range pts {
		if pt.Name == "agent_integration_status" && pt.Labels["instance"] == "8.3/other" && pt.Labels["status"] == StatusUnconfigured {
			unconfigured = true
		}
	}
	if !unconfigured {
		t.Error("a pool without pm.status_path is reported unconfigured")
	}
}

func TestFastCGI_StatusPageDisabled(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s")
	fakeFPM(t, sock, "Status: 404 Not Found\r\nContent-type: text/html", "File not found.")
	if _, err := fcgiGet(context.Background(), "unix", sock, "/status", "json"); err == nil {
		t.Error("a 404 is an error")
	}
}

func TestMailQueue(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{"var/spool/exim4/input/A/1abc-000001-H", "var/spool/exim4/input/A/1abc-000001-D", "var/spool/exim4/input/1xyz-000002-H",
		"var/spool/postfix/deferred/4/ABC123", "var/spool/postfix/active/DEF"} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(f)), 0o755)
		os.WriteFile(filepath.Join(root, f), nil, 0o600)
	}
	os.MkdirAll(filepath.Join(root, "var/spool/postfix/incoming"), 0o755)
	os.MkdirAll(filepath.Join(root, "var/spool/postfix/hold"), 0o755)
	pts, _ := NewMailQueue(root).Collect(context.Background())
	if val(t, pts, "mail_queue_messages", "mta", "exim") != 2 || val(t, pts, "mail_queue_messages", "mta", "postfix", "queue", "deferred") != 1 {
		t.Errorf("%v", pts)
	}
}

func TestScrape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `# TYPE app_requests_total counter
app_requests_total{code="200",hostname="x"} 10
# TYPE app_latency histogram
app_latency_bucket{le="0.1"} 3
app_latency_bucket{le="+Inf"} 5
app_latency_sum 1.5
app_latency_count 5
# TYPE app_temp gauge
app_temp 21.5
`)
	}))
	defer srv.Close()
	pts, _ := NewScrape([]string{srv.URL + "/metrics", "http://127.0.0.1:1/metrics"}).Collect(context.Background())
	target := strings.TrimPrefix(srv.URL, "http://")
	if val(t, pts, "app_requests_total", "code", "200", "exported_hostname", "x", "scrape_target", target) != 10 {
		t.Error("counter with a reserved label renamed")
	}
	infs := 0
	for _, p := range pts {
		if p.Name == "app_latency_bucket" && p.Labels["le"] == "+Inf" {
			infs++
		}
	}
	if infs != 1 || val(t, pts, "app_latency_count") != 5 || val(t, pts, "app_temp") != 21.5 {
		t.Errorf("histogram/gauge: %d +Inf buckets", infs)
	}
	if val(t, pts, "scrape_up", "scrape_target", target) != 1 || val(t, pts, "scrape_up", "scrape_target", "127.0.0.1:1") != 0 {
		t.Error("scrape_up")
	}
}

func TestMySQL_NotInstalled(t *testing.T) {
	m := NewMySQL("", "yomins-agent")
	m.sockets = []string{filepath.Join(t.TempDir(), "none.sock")}
	if pts, err := m.Collect(context.Background()); err != nil || len(pts) != 0 {
		t.Errorf("no socket, no points: %v %v", pts, err)
	}
}

func TestMySQL_UnreachableIsError(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "mysqld.sock")
	os.WriteFile(sock, nil, 0o600) // exists but nobody listens
	m := NewMySQL("", "yomins-agent")
	m.sockets = []string{sock}
	pts, _ := m.Collect(context.Background())
	if statusOf(pts, "mysql") != StatusError || val(t, pts, "mysql_up") != 0 {
		t.Errorf("%v", pts)
	}
}

func TestMySQLDirSizes(t *testing.T) {
	dir := t.TempDir()
	write := func(p string, n int) {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), make([]byte, n), 0o600)
	}
	write("shop/orders.ibd", 3000)
	write("shop/users.ibd", 1000)
	write("blog@002dold/posts.ibd", 500)
	write("mysql/user.MAD", 9999)
	write("#innodb_temp/t.ibt", 9999)
	write("ibdata1", 9999)
	pts := dirSizes(dir, 20)
	if len(pts) != 2 || val(t, pts, "mysql_database_size_bytes", "database", "shop") != 4000 || val(t, pts, "mysql_database_size_bytes", "database", "blog-old") != 500 {
		t.Errorf("%v", pts)
	}
	if pts[0].Labels["database"] != "shop" {
		t.Error("largest first")
	}
}
