package logs

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// fakeDocker points dockerRoot at a temp dir holding one container per call
// of add, and restores it after the test.
type fakeDocker struct {
	t    *testing.T
	root string
}

func newFakeDocker(t *testing.T) *fakeDocker {
	old := dockerRoot
	dockerRoot = t.TempDir()
	t.Cleanup(func() { dockerRoot = old })
	return &fakeDocker{t: t, root: dockerRoot}
}

// add writes a container's config.v2.json and returns its directory.
func (d *fakeDocker) add(id, config string) string {
	d.t.Helper()
	dir := filepath.Join(d.root, "containers", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.v2.json"), []byte(config), 0o644); err != nil {
		d.t.Fatal(err)
	}
	return dir
}

func touch(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestContainerLogSpecs_NginxLogsMountedFromTheHost(t *testing.T) {
	d := newFakeDocker(t)
	host := t.TempDir()
	logsDir := filepath.Join(host, "edge", "nginx", "logs")
	touch(t, filepath.Join(logsDir, "yomins.com.access.log"))
	touch(t, filepath.Join(logsDir, "yomins.com.error.log"))
	d.add("abc", `{"ID":"abc","Name":"/edge-nginx-1","Config":{"Image":"nginx:1.27.4"},"MountPoints":{
		"/var/log/nginx":{"Source":"`+logsDir+`","Destination":"/var/log/nginx"},
		"/etc/nginx/nginx.conf":{"Source":"/srv/nginx.conf","Destination":"/etc/nginx/nginx.conf"},
		"/tmp":{"Source":"","Destination":"/tmp"}}}`)

	specs := containerLogSpecs(dockerContainers())
	want := []FileSpec{
		{Source: "nginx", Parser: ParserNginxAccess, Globs: []string{logsDir + "/*access*.log", logsDir + "/*analytics*.log"}, Container: "edge-nginx-1"},
		{Source: "nginx", Parser: ParserNginxError, Globs: []string{logsDir + "/*error*.log"}, Container: "edge-nginx-1"},
	}
	if !reflect.DeepEqual(specs, want) {
		t.Errorf("specs:\n got %+v\nwant %+v", specs, want)
	}
}

func TestContainerLogSpecs_NothingWithoutLogMounts(t *testing.T) {
	d := newFakeDocker(t)
	d.add("abc", `{"Name":"/app","MountPoints":{"/data":{"Source":"/srv/data","Destination":"/data"},"/":{"Source":"/","Destination":"/"}}}`)
	d.add("bad", `not json`)
	if specs := containerLogSpecs(dockerContainers()); len(specs) != 0 {
		t.Errorf("specs = %+v, want none", specs)
	}
}

func TestDiscover_ContainerPathsExtendTheAllowList(t *testing.T) {
	d := newFakeDocker(t)
	logsDir := filepath.Join(t.TempDir(), "logs")
	touch(t, filepath.Join(logsDir, "site.error.log"))
	d.add("abc", `{"Name":"/web","MountPoints":{"/var/log/nginx":{"Source":"`+logsDir+`","Destination":"/var/log/nginx"}}}`)

	plan := Discover(nil, []string{"/x/*"})
	if !reflect.DeepEqual(plan.ContainerAllow, []string{logsDir + "/*error*.log"}) {
		t.Errorf("container allow = %v", plan.ContainerAllow)
	}
	var found bool
	for _, f := range plan.Files {
		if f.Container == "web" {
			found = true
			if !reflect.DeepEqual(f.Exclude, []string{"/x/*"}) {
				t.Errorf("exclude not applied: %+v", f)
			}
		}
	}
	if !found {
		t.Errorf("no container spec in %+v", plan.Files)
	}
}

func TestSplitTyped(t *testing.T) {
	for _, c := range []struct{ in, source, glob string }{
		{"nginx:/srv/x/*.log", "nginx", "/srv/x/*.log"},
		{"php-fpm:/var/www/a/logs/php.log", "php-fpm", "/var/www/a/logs/php.log"},
		{"/srv/x/*.log", "", "/srv/x/*.log"},
		{"/srv/a:b/*.log", "", "/srv/a:b/*.log"},
		{"Nginx:/srv/x.log", "", "Nginx:/srv/x.log"},
		{"nginx:relative/x.log", "", "nginx:relative/x.log"},
	} {
		if s, g := SplitTyped(c.in); s != c.source || g != c.glob {
			t.Errorf("SplitTyped(%q) = %q, %q; want %q, %q", c.in, s, g, c.source, c.glob)
		}
	}
}

func TestExtraSpecs(t *testing.T) {
	got := extraSpecs([]string{"nginx:/a/*.log", "/b/*.log", "mariadb:/c/*.err", "nginx:/d/*.log", "myapp:/e/*.log"}, []string{"/z"})
	want := []FileSpec{
		{Source: "nginx", Parser: ParserNginxAny, Globs: []string{"/a/*.log", "/d/*.log"}, Exclude: []string{"/z"}},
		{Source: "custom", Parser: ParserAuto, Globs: []string{"/b/*.log"}, Exclude: []string{"/z"}},
		{Source: "mysql", Parser: ParserMySQL, Globs: []string{"/c/*.err"}, Exclude: []string{"/z"}},
		{Source: "myapp", Parser: ParserAuto, Globs: []string{"/e/*.log"}, Exclude: []string{"/z"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %+v\nwant %+v", got, want)
	}
}

func TestParserForFile_WebServerByName(t *testing.T) {
	e := parserForFile(ParserNginxAny, "/srv/site.error.log")("2026/10/18 13:43:01 [error] 1#1: boom")
	if e.Level != LevelError || e.Fields["pid"] != "1" {
		t.Errorf("error log: %+v", e)
	}
	e = parserForFile(ParserNginxAny, "/srv/site.access.log")(`1.2.3.4 - - [18/Oct/2026:13:43:01 +0000] "GET / HTTP/1.1" 500 12 "-" "curl"`)
	if e.Fields["status"] != "500" {
		t.Errorf("access log: %+v", e)
	}
}

func TestTail_DockerLinesNameTheirContainer(t *testing.T) {
	d := newFakeDocker(t)
	dir := d.add("abc123", `{"ID":"abc123","Name":"/yominscom-php83-1","Config":{"Image":"php83:latest"}}`)
	logPath := filepath.Join(dir, "abc123-json.log")
	touch(t, logPath)

	src := NewFileSource([]FileSpec{{Source: "docker", Parser: ParserDockerJSON, Globs: []string{filepath.Join(d.root, "containers", "*", "*-json.log")}}},
		[]string{d.root + "/**"}, LoadPositions(t.TempDir()))
	src.started = time.Now()
	out := make(chan Entry, 10)
	src.scan()
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"log":"PHP Fatal error:  boom\n","stream":"stderr","time":"2026-10-19T19:18:00Z"}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, tf := range src.sorted() {
		_ = src.read(context.Background(), tf, out)
	}
	e := <-out
	if e.Fields["container"] != "yominscom-php83-1" || e.Fields["image"] != "php83:latest" || e.Level != LevelError {
		t.Errorf("%+v", e)
	}
}

func TestTail_CountsFilesOutsideTheAllowList(t *testing.T) {
	h := newHarness(t, nil)
	h.src.allow = []string{"/nowhere/**"}
	h.write("a.log", "")
	h.write("a.log.1", "")
	h.round()
	if got := h.src.Outside(); got != 1 {
		t.Errorf("outside = %d, want 1 (rotated files are not counted)", got)
	}
}
