package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/yominsops/yomins-agent/internal/config"
	"github.com/yominsops/yomins-agent/internal/metrics"
)

type backupReport struct {
	Status    string      `json:"status"`
	StartTime time.Time   `json:"start_time"`
	EndTime   time.Time   `json:"end_time"`
	Stat      *backupStat `json:"stat"`
}

type backupStat struct {
	TotalFilesProcessed float64 `json:"total_files_processed"`
	TotalBytesProcessed float64 `json:"total_bytes_processed"`
}

// BackupReader abstracts reading a backup report file.
type BackupReader interface {
	ReadReport(path string) ([]byte, error)
}

// BackupCollector collects metrics from backup reports in the last_run.json format
// yomins-backup writes (any job writing the same format can be watched): by default the
// one at config.DefaultBackupReport, or the ones in the remote configuration. Every
// metric carries a backup label with the report's name. A report that does not exist
// emits nothing — expected where the job is not installed.
type BackupCollector struct {
	reader  BackupReader
	reports []config.WatchedFile
}

// NewBackupCollector returns a BackupCollector for the given reports (nil: the default)
// backed by the real filesystem.
func NewBackupCollector(reports []config.WatchedFile) *BackupCollector {
	return NewBackupCollectorWithReader(realBackupReader{}, reports)
}

// NewBackupCollectorWithReader returns a BackupCollector with an injected reader.
func NewBackupCollectorWithReader(r BackupReader, reports []config.WatchedFile) *BackupCollector {
	if reports == nil {
		reports = config.DefaultBackups()
	}
	return &BackupCollector{reader: r, reports: reports}
}

func (c *BackupCollector) Name() string { return "backup" }

func (c *BackupCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	var errs []error
	for _, r := range c.reports {
		got, err := c.collectReport(r)
		if err != nil {
			errs = append(errs, fmt.Errorf("backup %s: %w", r.Name, err))
			continue
		}
		pts = append(pts, got...)
	}
	return pts, errors.Join(errs...)
}

func (c *BackupCollector) collectReport(r config.WatchedFile) ([]metrics.MetricPoint, error) {
	data, err := c.reader.ReadReport(r.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read backup report: %w", err)
	}

	var report backupReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse backup report: %w", err)
	}

	labels := map[string]string{"backup": r.Name}
	point := func(name, help string, v float64) metrics.MetricPoint {
		return metrics.MetricPoint{Name: name, Help: help, Type: metrics.Gauge, Value: v, Labels: labels}
	}

	var status float64
	if report.Status == "success" {
		status = 1
	}
	pts := []metrics.MetricPoint{
		point("yomins_backup_last_status", "Status of the last backup run (1=success, 0=error)", status),
		point("yomins_backup_last_duration_seconds", "Duration of the last backup run in seconds", report.EndTime.Sub(report.StartTime).Seconds()),
	}
	if r.MaxAge > 0 {
		pts = append(pts, point("yomins_backup_max_age_seconds", "How old the last successful backup may be (agent configuration)", r.MaxAge.Seconds()))
	}
	if report.Status == "success" {
		pts = append(pts, point("yomins_backup_last_success_timestamp", "Unix timestamp of the last successful backup", float64(report.EndTime.Unix())))
		if report.Stat != nil {
			pts = append(pts,
				point("yomins_backup_files_total", "Total number of files processed in the last backup", report.Stat.TotalFilesProcessed),
				point("yomins_backup_bytes_total", "Total number of bytes processed in the last backup", report.Stat.TotalBytesProcessed),
			)
		}
	}
	return pts, nil
}

type realBackupReader struct{}

func (realBackupReader) ReadReport(path string) ([]byte, error) {
	return os.ReadFile(path)
}
