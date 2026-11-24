package inventory

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseNetFile(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   106        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0CEA 0100007F:D2F0 01 00000000:00000000 00:00000000 00000000   106        0 1003 1 0000000000000000 100 0 0 10 0
`
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1 0000000000000000 100 0 0 10 0
`
	udp := `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3001 2 0000000000000000 0
  2: 0100007F:A1B2 0100007F:0035 01 00000000:00000000 00:00000000 00000000     0        0 3002 2 0000000000000000 0
`
	out := map[uint64]Port{}
	parseNetFile([]byte(tcp), "tcp", out)
	parseNetFile([]byte(tcp6), "tcp", out)
	parseNetFile([]byte(udp), "udp", out)
	want := map[uint64]Port{
		1001: {Proto: "tcp", Addr: "0.0.0.0", Port: 80},
		1002: {Proto: "tcp", Addr: "127.0.0.1", Port: 3306},
		2001: {Proto: "tcp", Addr: "::", Port: 443},
		2002: {Proto: "tcp", Addr: "127.0.0.1", Port: 8080},
		3001: {Proto: "udp", Addr: "0.0.0.0", Port: 53},
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("got %+v\nwant %+v", out, want)
	}
}

func TestProcessesStateAndPorts(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/proc/stat", "cpu  1 2 3\nbtime 1700000000\n", 0o644)
	stat := func(pid, ppid string, ticks int) string {
		// pid (comm) state ppid … field 22 is the start time.
		f := []string{pid, "(nginx)", "S", ppid}
		for i := 5; i <= 21; i++ {
			f = append(f, "0")
		}
		f = append(f, strconv.Itoa(ticks), "0")
		return strings.Join(f, " ")
	}
	proc := func(pid, ppid string, ticks int, sockets ...string) {
		put(t, root, "/proc/"+pid+"/cgroup", "0::/system.slice/nginx.service\n", 0o644)
		put(t, root, "/proc/"+pid+"/stat", stat(pid, ppid, ticks), 0o644)
		if err := os.Symlink("/usr/sbin/nginx", filepath.Join(root, "proc", pid, "exe")); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, "proc", pid, "fd"), 0o755); err != nil {
			t.Fatal(err)
		}
		for i, s := range sockets {
			if err := os.Symlink("socket:["+s+"]", filepath.Join(root, "proc", pid, "fd", strconv.Itoa(i+3))); err != nil {
				t.Fatal(err)
			}
		}
	}
	proc("100", "1", 500, "1001")
	proc("101", "100", 900, "1001", "2001") // a worker holds the sockets too
	// docker-proxy in the same unit holds a container's port: not nginx's.
	put(t, root, "/proc/102/cgroup", "0::/system.slice/nginx.service\n", 0o644)
	put(t, root, "/proc/102/stat", stat("102", "100", 900), 0o644)
	if err := os.Symlink("/usr/bin/docker-proxy", filepath.Join(root, "proc", "102", "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "proc", "102", "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[3001]", filepath.Join(root, "proc", "102", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	put(t, root, "/proc/net/tcp", `  sl  local_address rem_address   st
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3001 1
`, 0o644)
	put(t, root, "/proc/net/tcp6", `  sl  local_address rem_address   st
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1
`, 0o644)
	r := Report{}
	e := &Env{Root: root, Run: func(context.Context, bool, string, ...string) ([]byte, error) { return nil, os.ErrNotExist }}
	if err := (&processes{}).Detect(context.Background(), e, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Components) != 1 {
		t.Fatalf("got %+v", r.Components)
	}
	c := r.Components[0]
	if c.State != StateRunning || c.StartedAt == nil || !c.StartedAt.Equal(time.Unix(1700000005, 0)) {
		t.Errorf("state/start = %q %v", c.State, c.StartedAt)
	}
	want := []Port{{Proto: "tcp", Addr: "0.0.0.0", Port: 80}, {Proto: "tcp", Addr: "::", Port: 443}}
	if !reflect.DeepEqual(c.Ports, want) {
		t.Errorf("ports = %+v, want %+v", c.Ports, want)
	}
}

func TestStoppedServices(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/run/systemd/system/.keep", "", 0o644)
	put(t, root, "/var/lib/dpkg/status", dpkgStatus, 0o644)
	put(t, root, "/var/lib/dpkg/info/nginx-core.list", "/usr/sbin/nginx\n", 0o644)
	var calls [][]string
	e := &Env{Root: root, Run: func(_ context.Context, _ bool, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if args[0] == "list-units" {
			return []byte("nginx.service loaded inactive dead A high performance web server\n" +
				"● redis-server.service loaded failed failed Advanced key-value store\n" +
				"e2scrub_reap.service loaded inactive dead Remove Stale Metadata\n" +
				"apache2.service loaded inactive dead The Apache HTTP Server\n" +
				"php8.3-fpm.service loaded inactive dead PHP FPM\n"), nil
		}
		return []byte(`Type=forking
ExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
ActiveState=inactive
UnitFileState=enabled
Id=nginx.service

Type=notify
ExecStart={ path=/usr/bin/redis-server ; argv[]=/usr/bin/redis-server /etc/redis/redis.conf ; }
ActiveState=failed
UnitFileState=enabled
Id=redis-server.service

Type=oneshot
ExecStart={ path=/sbin/e2scrub_all ; argv[]=/sbin/e2scrub_all -A -r ; }
ActiveState=inactive
UnitFileState=enabled
Id=e2scrub_reap.service

Type=forking
ExecStart={ path=/usr/sbin/apachectl ; argv[]=/usr/sbin/apachectl start ; }
ActiveState=inactive
UnitFileState=disabled
Id=apache2.service

Type=notify
ExecStart={ path=/usr/sbin/php-fpm8.3 ; argv[]=/usr/sbin/php-fpm8.3 --nodaemonize ; }
ActiveState=inactive
UnitFileState=enabled
Id=php8.3-fpm.service
`), nil
	}}
	r := Report{Packages: parseDpkgStatus([]byte(dpkgStatus)),
		Components: []Component{{Kind: KindService, Name: "php-fpm", Unit: "php8.3-fpm.service", State: StateRunning}}}
	if err := (stoppedServices{}).Detect(context.Background(), e, &r); err != nil {
		t.Fatal(err)
	}
	got := r.Components[1:]
	if len(got) != 2 {
		t.Fatalf("got %+v, want nginx stopped and redis failed", got)
	}
	if n := got[0]; n.Name != "nginx" || n.State != StateStopped || n.Version != "1.22.1" || n.Unit != "nginx.service" {
		t.Errorf("nginx = %+v", n)
	}
	if n := got[1]; n.Name != "redis" || n.State != StateFailed || n.Path != "/usr/bin/redis-server" {
		t.Errorf("redis = %+v", n)
	}
	if show := calls[1]; show[len(show)-6] != "--" {
		t.Errorf("systemctl show args = %v", show)
	}
}

func TestParseUpdates(t *testing.T) {
	apt := `NOTE: This is only a simulation!
Inst libc6 [2.36-9] (2.36-9+deb12u9 Debian-Security:12/stable-security [arm64])
Inst php8.3-cli [8.3.36-1] (8.3.37-1+0~20261121.62+debian12~1.gbp deb.sury.org:bookworm/main [arm64]) []
Inst tzdata [2024a-0+deb12u1] (2025b-0+deb12u1 Debian:12.12/stable, Debian-Security:12/stable-security [all])
Inst nginx-core [1.22.1-9] (1.22.1-9+deb12u1 Debian:12.12/stable [amd64])
Conf libc6 (2.36-9+deb12u9 Debian-Security:12/stable-security [arm64])
`
	got := parseAptSimulation([]byte(apt))
	want := []Update{
		{Name: "libc6", Version: "2.36-9+deb12u9", Security: true, Origin: "Debian-Security"},
		{Name: "nginx-core", Version: "1.22.1-9+deb12u1", Origin: "Debian"},
		{Name: "php8.3-cli", Version: "8.3.37-1+0~20261121.62+debian12~1.gbp", Origin: "deb.sury.org"},
		{Name: "tzdata", Version: "2025b-0+deb12u1", Security: true, Origin: "Debian"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("apt:\n got %+v\nwant %+v", got, want)
	}

	dnf := `
openssl.x86_64                     1:3.0.7-28.el9_4          baseos
kernel.x86_64                      5.14.0-427.el9            baseos
Obsoleting Packages
grub2-tools.x86_64                 1:2.06-80.el9             baseos
`
	ups := parseCheckUpdate([]byte(dnf))
	sec := securityPackages([]byte("ALSA-2024:1234 Important/Sec. openssl-1:3.0.7-28.el9_4.x86_64\n"))
	if len(ups) != 2 || ups[0].Name != "kernel" || ups[1].Name != "openssl" || ups[1].Version != "1:3.0.7-28.el9_4" || !sec["openssl"] || sec["kernel"] {
		t.Errorf("dnf: %+v %v", ups, sec)
	}
}

func TestSiteDomains(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/etc/nginx/sites-enabled/shop", `
# server { root /nope; server_name commented.example; }
server {
    listen 443 ssl;
    server_name shop.example.com www.shop.example.com _;
    root /var/www/shop;
    location /api/ { proxy_pass http://127.0.0.1:8080; }
}
server {
    server_name app.example.org;
    location / {
        root /srv/app/public;
    }
}
server {
    server_name ~^(?<sub>.+)\.example\.net$;
    root /var/www/$sub;
}
`, 0o644)
	put(t, root, "/etc/apache2/sites-enabled/blog.conf", `<VirtualHost *:80>
  ServerName blog.example.com
  ServerAlias www.blog.example.com
  DocumentRoot /var/www/blog
</VirtualHost>
`, 0o644)
	put(t, root, "/var/www/shop/wp-includes/version.php", "$wp_version = '6.8.3';", 0o644)
	put(t, root, "/var/www/shop/wp-config.php", "define( 'WP_HOME', 'https://Shop.Example.com/' );", 0o644)
	put(t, root, "/var/www/blog/wp-includes/version.php", "$wp_version = '6.7.1';", 0o644)
	put(t, root, "/srv/app/public/index.php", "<?php", 0o644)
	put(t, root, "/srv/app/composer.lock", `{"packages":[{"name":"laravel/framework","version":"v11.9.2"}]}`, 0o644)
	put(t, root, "/var/www/vhosts/plesk.example.com/httpdocs/wp-includes/version.php", "$wp_version = '6.8.3';", 0o644)

	r := Report{}
	if err := (webApps{}).Detect(context.Background(), &Env{Root: root}, &r); err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, c := range r.Components {
		got[c.Path] = c.Domains
	}
	want := map[string][]string{
		"/var/www/shop": {"shop.example.com", "www.shop.example.com"},
		"/var/www/blog": {"blog.example.com", "www.blog.example.com"},
		"/srv/app":      {"app.example.org"},
		"/var/www/vhosts/plesk.example.com/httpdocs": {"plesk.example.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("domains:\n got %v\nwant %v", got, want)
	}
}

func TestContainerPorts(t *testing.T) {
	var s dockerSummary
	s.Ports = append(s.Ports,
		struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		}{IP: "0.0.0.0", PrivatePort: 80, PublicPort: 8080, Type: "tcp"},
		struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		}{PrivatePort: 9000, Type: "tcp"}, // not published
	)
	got := containerPorts(s)
	if len(got) != 1 || got[0] != (Port{Proto: "tcp", Addr: "0.0.0.0", Port: 8080, Target: 80}) {
		t.Errorf("got %+v", got)
	}
}

func TestContainerVhostDomains(t *testing.T) {
	root := t.TempDir()
	// nginx runs in a container; its config names the site, whose root
	// /var/www/html is the host's /srv/site mounted in.
	put(t, root, "/proc/42/root/etc/nginx/conf.d/site.conf", "server {\n  server_name example.com www.example.com;\n  root /var/www/html;\n}\n", 0o644)
	put(t, root, "/srv/site/wp-includes/version.php", "$wp_version = '6.8.3';", 0o644)
	e := &Env{Root: root, mounts: []string{"/srv/site"},
		containers: []containerRoot{{root: "/proc/42/root", mounts: [][2]string{{"/var/www/html", "/srv/site"}, {"/var/www", "/srv"}}}}}
	r := Report{}
	if err := (webApps{}).Detect(context.Background(), e, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Components) != 1 || r.Components[0].Path != "/srv/site" ||
		!reflect.DeepEqual(r.Components[0].Domains, []string{"example.com", "www.example.com"}) {
		t.Errorf("got %+v", r.Components)
	}
	c := e.containers[0]
	for in, want := range map[string]string{"/var/www/html/blog": "/srv/site/blog", "/var/www/x": "/srv/x", "/etc/nginx": ""} {
		if got := c.hostPath(in); got != want {
			t.Errorf("hostPath(%s) = %q, want %q", in, got, want)
		}
	}
}
