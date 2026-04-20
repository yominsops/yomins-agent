package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

const backupReportFile = "/var/lib/yomins/backup/last_run.json"

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

// BackupReader abstracts reading the yomins-backup report file.
type BackupReader interface {
	ReadReport() ([]byte, error)
}

// BackupCollector collects metrics from the yomins-backup last_run.json report.
// If the report file does not exist, no metrics are emitted — this is expected
// on hosts where yomins-backup is not installed.
type BackupCollector struct {
	reader BackupReader
}

// NewBackupCollector returns a BackupCollector backed by the real filesystem.
func NewBackupCollector() *BackupCollector {
	return &BackupCollector{reader: realBackupReader{}}
}

// NewBackupCollectorWithReader returns a BackupCollector with an injected reader.
func NewBackupCollectorWithReader(r BackupReader) *BackupCollector {
	return &BackupCollector{reader: r}
}

func (c *BackupCollector) Name() string { return "backup" }

func (c *BackupCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	data, err := c.reader.ReadReport()
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

	duration := report.EndTime.Sub(report.StartTime).Seconds()

	var status float64
	if report.Status == "success" {
		status = 1
	}

	pts := []metrics.MetricPoint{
		{
			Name:  "yomins_backup_last_status",
			Help:  "Status of the last backup run (1=success, 0=error)",
			Type:  metrics.Gauge,
			Value: status,
		},
		{
			Name:  "yomins_backup_last_duration_seconds",
			Help:  "Duration of the last backup run in seconds",
			Type:  metrics.Gauge,
			Value: duration,
		},
	}

	if report.Status == "success" {
		pts = append(pts, metrics.MetricPoint{
			Name:  "yomins_backup_last_success_timestamp",
			Help:  "Unix timestamp of the last successful backup",
			Type:  metrics.Gauge,
			Value: float64(report.EndTime.Unix()),
		})

		if report.Stat != nil {
			pts = append(pts,
				metrics.MetricPoint{
					Name:  "yomins_backup_files_total",
					Help:  "Total number of files processed in the last backup",
					Type:  metrics.Gauge,
					Value: report.Stat.TotalFilesProcessed,
				},
				metrics.MetricPoint{
					Name:  "yomins_backup_bytes_total",
					Help:  "Total number of bytes processed in the last backup",
					Type:  metrics.Gauge,
					Value: report.Stat.TotalBytesProcessed,
				},
			)
		}
	}

	return pts, nil
}

type realBackupReader struct{}

func (realBackupReader) ReadReport() ([]byte, error) {
	return os.ReadFile(backupReportFile)
}
