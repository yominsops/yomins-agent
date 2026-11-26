package inventory

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPackageChangelogs(t *testing.T) {
	root := t.TempDir()
	write := func(p string, b []byte) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("/var/lib/dpkg/status", []byte("Package: php7.4-fpm\nStatus: install ok installed\nVersion: 1:7.4.33-31\n"))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte("php7.4 (1:7.4.33-31) bookworm; urgency=medium\n\n  * Backported from 8.2.35 [CVE-2026-109618, CVE-2026-109619]\n  * CVE-2026-109618 again\n\nphp7.4 (1:7.4.33-1)\n  * CVE-2024-4577\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	write("/usr/share/doc/php7.4-common/changelog.Debian.gz", gz.Bytes())
	// Debian links a binary package's doc directory to its sibling's.
	if err := os.Symlink("php7.4-common", filepath.Join(root, "/usr/share/doc/php7.4-fpm")); err != nil {
		t.Fatal(err)
	}

	r := Report{Components: []Component{
		{Kind: KindService, Name: "php-fpm", Version: "7.4.33", Package: "php7.4-fpm"},
		{Kind: KindService, Name: "php-fpm", Version: "7.4.33", Package: "php7.4-fpm", Container: "web"},
		{Kind: KindService, Name: "nginx", Version: "1.30.7", Package: "nginx"}, // no changelog
		{Kind: KindBinary, Name: "node", Version: "26.5.1"},
	}}
	if err := (packageChangelogs{}).Detect(context.Background(), &Env{Root: root}, &r); err != nil {
		t.Fatal(err)
	}
	want := []string{"CVE-2024-4577", "CVE-2026-109618", "CVE-2026-109619"}
	if !reflect.DeepEqual(r.Components[0].FixedCVEs, want) {
		t.Errorf("host php-fpm: got %v, want %v", r.Components[0].FixedCVEs, want)
	}
	for _, c := range r.Components[1:] {
		if c.FixedCVEs != nil {
			t.Errorf("%s (%s): got %v, want none", c.Name, c.Container, c.FixedCVEs)
		}
	}
}

func TestPackageChangelogsRPM(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "/var/lib/rpm"), 0o755); err != nil {
		t.Fatal(err)
	}
	var asked [][]string
	e := &Env{Root: root, Run: func(_ context.Context, _ bool, name string, args ...string) ([]byte, error) {
		asked = append(asked, append([]string{name}, args...))
		if args[len(args)-1] != "php-fpm" {
			return nil, errors.New("package nginx is not installed")
		}
		return []byte("* Tue Nov 18 2026 Builder <b@example.com> - 8.3.37-1\n- fix CVE-2026-109618\n- Resolves: CVE-2024-4577, CVE-2026-109618\n"), nil
	}}
	r := Report{Components: []Component{
		{Kind: KindService, Name: "php-fpm", Package: "php-fpm"},
		{Kind: KindService, Name: "php-fpm", Package: "php-fpm"}, // cached
		{Kind: KindService, Name: "nginx", Package: "nginx"},
		{Kind: KindService, Name: "bad", Package: "-q;rm"},
	}}
	if err := (packageChangelogs{}).Detect(context.Background(), e, &r); err != nil {
		t.Fatal(err)
	}
	want := []string{"CVE-2024-4577", "CVE-2026-109618"}
	for _, c := range r.Components[:2] {
		if !reflect.DeepEqual(c.FixedCVEs, want) {
			t.Errorf("php-fpm: got %v, want %v", c.FixedCVEs, want)
		}
	}
	for _, c := range r.Components[2:] {
		if c.FixedCVEs != nil {
			t.Errorf("%s: got %v, want none", c.Package, c.FixedCVEs)
		}
	}
	wantAsked := [][]string{{"rpm", "-q", "--changelog", "--", "php-fpm"}, {"rpm", "-q", "--changelog", "--", "nginx"}}
	if !reflect.DeepEqual(asked, wantAsked) {
		t.Errorf("ran %v, want %v", asked, wantAsked)
	}
}

func TestPackageChangelogsNotHere(t *testing.T) {
	r := Report{Components: []Component{{Kind: KindService, Name: "nginx", Package: "nginx"}}}
	if err := (packageChangelogs{}).Detect(context.Background(), &Env{Root: t.TempDir()}, &r); err != errNotHere {
		t.Errorf("got %v, want errNotHere", err)
	}
}
