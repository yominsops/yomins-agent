package inventory

import (
	"bytes"
	"compress/gzip"
	"context"
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
	zw.Write([]byte("php7.4 (1:7.4.33-31) bookworm; urgency=medium\n\n  * Backported from 8.2.35 [CVE-2026-109618, CVE-2026-109619]\n  * CVE-2026-109618 again\n\nphp7.4 (1:7.4.33-1)\n  * CVE-2024-4577\n"))
	zw.Close()
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

func TestPackageChangelogsNotOnRPM(t *testing.T) {
	r := Report{Components: []Component{{Kind: KindService, Name: "nginx", Package: "nginx"}}}
	if err := (packageChangelogs{}).Detect(context.Background(), &Env{Root: t.TempDir()}, &r); err != errNotHere {
		t.Errorf("got %v, want errNotHere", err)
	}
}
