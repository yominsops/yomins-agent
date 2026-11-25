package collector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/yominsops/yomins-agent/internal/config"
	"github.com/yominsops/yomins-agent/internal/metrics"
)

// FileFreshnessCollector reports, for each watched directory of the remote
// configuration, how many regular files it holds (not recursive) and when the newest
// was last modified: a dump or export job that stopped writing shows as stale. A
// directory that does not exist counts as empty (newest 0), so the server's rule fires.
type FileFreshnessCollector struct {
	dirs    []config.WatchedFile
	readDir func(string) ([]os.DirEntry, error)
}

// NewFileFreshnessCollector watches the given directories.
func NewFileFreshnessCollector(dirs []config.WatchedFile) *FileFreshnessCollector {
	return &FileFreshnessCollector{dirs: dirs, readDir: os.ReadDir}
}

func (c *FileFreshnessCollector) Name() string { return "file_freshness" }

func (c *FileFreshnessCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	var errs []error
	for _, d := range c.dirs {
		newest, count, err := c.scan(d.Path)
		if err != nil {
			errs = append(errs, fmt.Errorf("file_freshness %s: %w", d.Name, err))
			continue
		}
		labels := map[string]string{"check": d.Name, "path": d.Path}
		var ts float64
		if !newest.IsZero() {
			ts = float64(newest.Unix())
		}
		pts = append(pts,
			metrics.MetricPoint{Name: "file_freshness_newest_timestamp_seconds", Help: "When the newest file of a watched directory was modified (0: none)",
				Type: metrics.Gauge, Value: ts, Labels: labels},
			metrics.MetricPoint{Name: "file_freshness_files", Help: "Regular files in a watched directory",
				Type: metrics.Gauge, Value: float64(count), Labels: labels},
		)
		if d.MaxAge > 0 {
			pts = append(pts, metrics.MetricPoint{Name: "file_freshness_max_age_seconds", Help: "How old the newest file may be (agent configuration)",
				Type: metrics.Gauge, Value: d.MaxAge.Seconds(), Labels: labels})
		}
	}
	return pts, errors.Join(errs...)
}

// scan returns the newest modification time of the directory's regular files and their
// count; a missing directory is empty.
func (c *FileFreshnessCollector) scan(dir string) (time.Time, int, error) {
	entries, err := c.readDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, 0, nil
	}
	if err != nil {
		return time.Time{}, 0, err
	}
	var newest time.Time
	count := 0
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // removed meanwhile
		}
		count++
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest, count, nil
}
