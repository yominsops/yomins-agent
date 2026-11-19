//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRPMInstallTimes(t *testing.T) {
	out := []byte("1700000000 bash\n1800000000 kernel-core\n1750000000 kernel-default\n1810000000 glibc\n1600000000 kernel\nnot-a-number x\n\n1900000000 kernel-headers\n")
	kernel, software := rpmInstallTimes(out)
	if kernel != 1800000000 {
		t.Errorf("kernel = %d (kernel-headers is not a kernel)", kernel)
	}
	if software != 1900000000 {
		t.Errorf("software = %d", software)
	}
	if k, s := rpmInstallTimes(nil); k != 0 || s != 0 {
		t.Errorf("empty output: %d %d", k, s)
	}
}

func TestDpkgInfoTimes(t *testing.T) {
	dir := t.TempDir()
	set := func(name string, at time.Time) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	kernel := time.Unix(1700000000, 0)
	newest := time.Unix(1800000000, 0)
	set("linux-image-6.1.0-26-amd64.list", kernel)
	set("libc6:amd64.list", newest)
	set("libc6:amd64.md5sums", time.Unix(1900000000, 0)) // not a file list
	k, s := dpkgInfoTimes(dir)
	if k != kernel.Unix() || s != newest.Unix() {
		t.Errorf("got %d %d", k, s)
	}
}
