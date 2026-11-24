package inventory

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// put writes a file under root, creating its directories.
func put(t *testing.T, root, path, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

const dpkgStatus = `Package: nginx-core
Status: install ok installed
Architecture: amd64
Source: nginx
Version: 1.22.1-9+deb12u1
Description: nginx web server
 a continuation line: Version: 0

Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl (3.0.15-1~deb12u1)
Version: 3.0.15-1~deb12u1+b1

Package: oldthing
Status: deinstall ok config-files
Version: 1.0

Package: adduser
Status: install ok installed
Architecture: all
Version: 3.134
`

func TestParseDpkgStatus(t *testing.T) {
	got := parseDpkgStatus([]byte(dpkgStatus))
	if len(got) != 3 {
		t.Fatalf("got %d packages, want 3 (config-files left out): %+v", len(got), got)
	}
	want := []Package{
		{Manager: "dpkg", Name: "nginx-core", Version: "1.22.1-9+deb12u1", Arch: "amd64", Source: "nginx", SourceVersion: "1.22.1-9+deb12u1"},
		{Manager: "dpkg", Name: "libssl3", Version: "3.0.15-1~deb12u1+b1", Arch: "amd64", Source: "openssl", SourceVersion: "3.0.15-1~deb12u1"},
		{Manager: "dpkg", Name: "adduser", Version: "3.134", Arch: "all", Source: "adduser", SourceVersion: "3.134"},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("package %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseRPMList(t *testing.T) {
	out := "openssl\t1:3.0.7-27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\n" +
		"bash\t0:5.1.8-9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\n" +
		"gpg-pubkey\t0:abc-def\t(none)\t(none)\n"
	got := parseRPMList([]byte(out))
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Version != "1:3.0.7-27.el9" || got[0].Source != "openssl" || got[0].SourceVersion != "3.0.7-27.el9" {
		t.Errorf("openssl = %+v", got[0])
	}
	if got[1].Version != "5.1.8-9.el9" {
		t.Errorf("epoch 0 kept: %+v", got[1])
	}
}

func TestVersions(t *testing.T) {
	for in, want := range map[string]string{
		"1:2.4.62-1~deb12u2":                    "2.4.62",
		"8.3.37-1+0~20261121.62+debian12~1.gbp": "8.3.37",
		"1.27.4":                                "1.27.4",
		"1:11.3.2+maria~ubu2204":                "11.3.2",
	} {
		if got := upstreamVersion(in); got != want {
			t.Errorf("upstreamVersion(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "1.0; rm -rf /", "<script>", "-1"} {
		if got := cleanVersion(bad); got != "" {
			t.Errorf("cleanVersion(%q) = %q, want empty", bad, got)
		}
	}
	for ref, want := range map[string]string{
		"php:8.3-fpm":                 "8.3-fpm",
		"nginx:alpine":                "",
		"registry:5000/app":           "",
		"victoriametrics/vm:v1.53.0":  "v1.53.0",
		"app@sha256:abcd":             "",
		"sha256:6d9cd1673939b540d272": "",
		"mongo":                       "",
	} {
		if got := imageTag(ref); got != want {
			t.Errorf("imageTag(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestWebApps(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/var/www/blog/wp-includes/version.php", "<?php\n$wp_version = '6.8.3';\n", 0o644)
	put(t, root, "/home/shop/public_html/libraries/src/Version.php",
		"const MAJOR_VERSION = 5;\nconst MINOR_VERSION = 2;\nconst PATCH_VERSION = 1;\n", 0o644)
	// A Laravel app whose document root (public/) is only in the nginx config.
	put(t, root, "/etc/nginx/sites-enabled/app", "server {\n  root /srv/app/public;\n  root $document_root;\n}\n", 0o644)
	put(t, root, "/srv/app/public/index.php", "<?php", 0o644)
	put(t, root, "/srv/app/composer.lock", `{"packages":[{"name":"laravel/framework","version":"v11.9.2"},{"name":"monolog/monolog","version":"3.0.0"}]}`, 0o644)
	// index.php alone is not OpenCart.
	put(t, root, "/var/www/other/index.php", "define('VERSION', '1.0');", 0o644)
	// phpMyAdmin one level under a document root.
	put(t, root, "/var/www/html/phpmyadmin/libraries/classes/Version.php", "public const VERSION = '5.2.1';", 0o644)

	r := Report{}
	if err := (webApps{}).Detect(context.Background(), &Env{Root: root}, &r); err != nil {
		t.Fatal(err)
	}
	got := map[string]Component{}
	for _, c := range r.Components {
		got[c.Name] = c
	}
	check := func(name, version, path, kind string) {
		t.Helper()
		c, ok := got[name]
		if !ok {
			t.Errorf("%s not found in %+v", name, r.Components)
			return
		}
		if c.Version != version || c.Path != path || c.Kind != kind {
			t.Errorf("%s = %+v, want %s at %s (%s)", name, c, version, path, kind)
		}
	}
	check("wordpress", "6.8.3", "/var/www/blog", KindWebApp)
	check("joomla", "5.2.1", "/home/shop/public_html", KindWebApp)
	check("laravel", "11.9.2", "/srv/app", KindFramework)
	check("phpmyadmin", "5.2.1", "/var/www/html/phpmyadmin", KindWebApp)
	if _, ok := got["opencart"]; ok {
		t.Error("a bare index.php was taken for OpenCart")
	}
	if len(r.Components) != 4 {
		t.Errorf("got %d components, want 4: %+v", len(r.Components), r.Components)
	}
}

func TestProcesses(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/var/lib/dpkg/status", dpkgStatus, 0o644)
	put(t, root, "/var/lib/dpkg/info/nginx-core.list", "/.\n/usr\n/usr/sbin/nginx\n", 0o644)
	proc := func(pid, exe, cgroup string, ppid ...string) {
		parent := "1"
		if len(ppid) > 0 {
			parent = ppid[0]
		}
		put(t, root, "/proc/"+pid+"/cgroup", cgroup, 0o644)
		put(t, root, "/proc/"+pid+"/stat", pid+" (a (b) c) S "+parent+" 1 1 0", 0o644)
		if err := os.Symlink(exe, filepath.Join(root, "proc", pid, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	proc("100", "/usr/sbin/nginx", "0::/system.slice/nginx.service\n")
	proc("101", "/usr/sbin/nginx", "0::/system.slice/nginx.service\n")
	proc("200", "/usr/sbin/cron", "0::/system.slice/cron.service\n")                // boring
	proc("300", "/usr/bin/php", "0::/system.slice/docker-abc.scope\n")              // a container's
	proc("400", "/usr/bin/vim", "0::/user.slice/user-1000.slice/session-1.scope\n") // a login session
	proc("500", "/opt/app/bin/worker", "0::/system.slice/worker.service\n")
	proc("600", "/usr/lib/nagios/plugins/check_ping", "0::/system.slice/worker.service\n", "500") // a child of the service
	put(t, root, "/proc/self/cgroup", "", 0o644)                                                  // not a pid

	r := Report{Packages: parseDpkgStatus([]byte(dpkgStatus))}
	e := &Env{Root: root, Run: func(context.Context, bool, string, ...string) ([]byte, error) { return nil, errors.New("no") }}
	if err := (&processes{}).Detect(context.Background(), e, &r); err != nil {
		t.Fatal(err)
	}
	r.Components = dedupe(r.Components)
	if len(r.Components) != 2 {
		t.Fatalf("got %+v, want nginx and worker", r.Components)
	}
	n := r.Components[0]
	if n.Name != "nginx" || n.Version != "1.22.1" || n.Package != "nginx-core" || n.Unit != "nginx.service" || n.Source != "package" {
		t.Errorf("nginx = %+v", n)
	}
	w := r.Components[1]
	if w.Name != "worker" || w.Package != "" || w.Version != "" || w.Unit != "worker.service" {
		t.Errorf("worker = %+v", w)
	}
}

func TestLocalBinaries(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/usr/local/bin/tool", "\x7fELF....", 0o755)
	put(t, root, "/usr/local/bin/script", "#!/bin/sh\necho hi\n", 0o755)
	put(t, root, "/usr/local/bin/notexec", "\x7fELF....", 0o644)
	put(t, root, "/opt/node/bin/node", "\x7fELF....", 0o755)
	r := Report{}
	e := &Env{Root: root, Run: func(context.Context, bool, string, ...string) ([]byte, error) { return []byte("v20.1.0"), nil }}
	if err := (localBinaries{}).Detect(context.Background(), e, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Components) != 2 {
		t.Fatalf("got %+v, want node and tool", r.Components)
	}
	if r.Components[0].Name != "node" || r.Components[0].Path != "/opt/node/bin/node" {
		t.Errorf("first = %+v", r.Components[0])
	}
	// A file the test user owns is never run, even when it is a known program.
	if r.Components[0].Version != "" && os.Getuid() != 0 {
		t.Errorf("a file not owned by root was asked for its version: %+v", r.Components[0])
	}
}

type failing struct{ panics bool }

func (failing) Name() string { return "failing" }
func (f failing) Detect(context.Context, *Env, *Report) error {
	if f.panics {
		panic("boom")
	}
	return errors.New("broken")
}

func TestScanKeepsGoing(t *testing.T) {
	root := t.TempDir()
	put(t, root, "/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n", 0o644)
	put(t, root, "/var/lib/dpkg/status", dpkgStatus, 0o644)
	r := Scan(context.Background(), &Env{Root: root}, []Detector{failing{}, osRelease{}, failing{panics: true}, dpkgPackages{}, rpmPackages{}})
	if r.OS.ID != "debian" || r.OS.VersionID != "12" || r.OS.Codename != "bookworm" {
		t.Errorf("os = %+v", r.OS)
	}
	if len(r.Packages) != 3 || r.Packages[0].Name != "adduser" {
		t.Errorf("packages not sorted or missing: %+v", r.Packages)
	}
	if r.Errors["failing"] == "" {
		t.Errorf("errors = %v", r.Errors)
	}
	if _, ok := r.Errors["rpm"]; ok {
		t.Error("rpm on a Debian system is not an error")
	}
}

func TestSender(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	if err := Write(path, Report{Version: ReportVersion, Time: time.Now(), OS: OS{ID: "debian"}}); err != nil {
		t.Fatal(err)
	}
	var calls int
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/push/inventory" || r.Header.Get("Authorization") != "Bearer tok" ||
			r.Header.Get("X-Yomins-Hostname") != "web-1" || r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("request %s %v", r.URL.Path, r.Header)
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(zr)
		var got Report
		if json.Unmarshal(b, &got) != nil || got.OS.ID != "debian" {
			t.Errorf("body %s", b)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	now := time.Now()
	s := &Sender{Server: srv.URL + "/v1/push", Token: "tok", Hostname: "web-1", AgentID: "a1", Path: path, StateDir: dir, now: func() time.Time { return now }}
	if !s.Tick(context.Background()) || calls != 1 {
		t.Fatalf("first tick: calls %d", calls)
	}
	if s.Tick(context.Background()) || calls != 1 {
		t.Fatalf("unchanged report sent again: calls %d", calls)
	}
	now = now.Add(25 * time.Hour)
	if !s.Tick(context.Background()) || calls != 2 {
		t.Fatalf("daily resend: calls %d", calls)
	}
	// A new report goes out at once; an old server (404) is left alone for a while.
	if err := Write(path, Report{Version: ReportVersion, Time: time.Now(), OS: OS{ID: "debian", VersionID: "12"}}); err != nil {
		t.Fatal(err)
	}
	status = http.StatusNotFound
	if s.Tick(context.Background()) || calls != 3 {
		t.Fatalf("changed report: calls %d", calls)
	}
	if s.Tick(context.Background()) || calls != 3 {
		t.Fatalf("asked again right after a 404: calls %d", calls)
	}
}
