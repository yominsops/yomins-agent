package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/config"
)

func TestFileFreshnessCollector(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	fresh := time.Now().Add(-time.Hour).Truncate(time.Second)
	for name, at := range map[string]time.Time{"a.tar.gz": old, "b.tar.gz": fresh} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	// A newer subdirectory is not a file.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()

	c := NewFileFreshnessCollector([]config.WatchedFile{
		{Name: "site_backups", Path: dir, MaxAge: 192 * time.Hour},
		{Name: "empty", Path: empty},
		{Name: "missing", Path: filepath.Join(dir, "nope")},
	})
	if c.Name() != "file_freshness" {
		t.Fatalf("name %q", c.Name())
	}
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Labels["check"]+"/"+p.Name] = p.Value
	}
	want := map[string]float64{
		"site_backups/file_freshness_newest_timestamp_seconds": float64(fresh.Unix()),
		"site_backups/file_freshness_files":                    2,
		"site_backups/file_freshness_max_age_seconds":          (192 * time.Hour).Seconds(),
		"empty/file_freshness_newest_timestamp_seconds":        0,
		"empty/file_freshness_files":                           0,
		"missing/file_freshness_newest_timestamp_seconds":      0,
		"missing/file_freshness_files":                         0,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestFileFreshnessCollectorReadError(t *testing.T) {
	c := NewFileFreshnessCollector([]config.WatchedFile{{Name: "x", Path: "/x"}, {Name: "y", Path: "/y"}})
	c.readDir = func(p string) ([]os.DirEntry, error) {
		if p == "/x" {
			return nil, os.ErrPermission
		}
		return nil, nil
	}
	pts, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("an unreadable directory is an error")
	}
	if len(pts) != 2 || pts[0].Labels["check"] != "y" {
		t.Fatalf("the readable one is still reported: %v", pts)
	}
}
