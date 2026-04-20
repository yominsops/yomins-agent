package collector_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/collector"
)

type mockBackupReader struct {
	data []byte
	err  error
}

func (m *mockBackupReader) ReadReport() ([]byte, error) {
	return m.data, m.err
}

func TestBackupCollector_Name(t *testing.T) {
	c := collector.NewBackupCollectorWithReader(&mockBackupReader{err: os.ErrNotExist})
	if c.Name() != "backup" {
		t.Errorf("Name() = %q, want backup", c.Name())
	}
}

func TestBackupCollector_FileNotExist(t *testing.T) {
	c := collector.NewBackupCollectorWithReader(&mockBackupReader{err: os.ErrNotExist})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if len(pts) != 0 {
		t.Errorf("expected no points for missing file, got %d", len(pts))
	}
}

func TestBackupCollector_MalformedJSON(t *testing.T) {
	c := collector.NewBackupCollectorWithReader(&mockBackupReader{data: []byte("not json")})
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestBackupCollector_ReadError(t *testing.T) {
	c := collector.NewBackupCollectorWithReader(&mockBackupReader{err: fmt.Errorf("disk error")})
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestBackupCollector_SuccessReport(t *testing.T) {
	start := time.Date(2024, 4, 19, 10, 0, 0, 0, time.UTC)
	end := time.Date(2024, 4, 19, 10, 5, 6, 700000000, time.UTC) // 306.7s later

	json := fmt.Sprintf(`{
		"status": "success",
		"start_time": %q,
		"end_time": %q,
		"stat": {
			"total_files_processed": 865582,
			"total_bytes_processed": 63511596397
		}
	}`, start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))

	c := collector.NewBackupCollectorWithReader(&mockBackupReader{data: []byte(json)})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Expect: last_status, last_duration_seconds, last_success_timestamp, files_total, bytes_total
	if len(pts) != 5 {
		t.Fatalf("points count = %d, want 5", len(pts))
	}

	byName := make(map[string]float64)
	for _, p := range pts {
		byName[p.Name] = p.Value
	}

	if byName["yomins_backup_last_status"] != 1 {
		t.Errorf("last_status = %v, want 1", byName["yomins_backup_last_status"])
	}
	wantDuration := end.Sub(start).Seconds()
	if byName["yomins_backup_last_duration_seconds"] != wantDuration {
		t.Errorf("last_duration_seconds = %v, want %v", byName["yomins_backup_last_duration_seconds"], wantDuration)
	}
	if byName["yomins_backup_last_success_timestamp"] != float64(end.Unix()) {
		t.Errorf("last_success_timestamp = %v, want %v", byName["yomins_backup_last_success_timestamp"], float64(end.Unix()))
	}
	if byName["yomins_backup_files_total"] != 865582 {
		t.Errorf("files_total = %v, want 865582", byName["yomins_backup_files_total"])
	}
	if byName["yomins_backup_bytes_total"] != 63511596397 {
		t.Errorf("bytes_total = %v, want 63511596397", byName["yomins_backup_bytes_total"])
	}
}

func TestBackupCollector_ErrorReport(t *testing.T) {
	start := time.Date(2024, 4, 19, 10, 0, 0, 0, time.UTC)
	end := time.Date(2024, 4, 19, 10, 1, 0, 0, time.UTC) // 60s later

	json := fmt.Sprintf(`{
		"status": "error",
		"start_time": %q,
		"end_time": %q,
		"error_line": 115,
		"log_tail": "something went wrong"
	}`, start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))

	c := collector.NewBackupCollectorWithReader(&mockBackupReader{data: []byte(json)})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Expect: last_status, last_duration_seconds only (no success-only metrics)
	if len(pts) != 2 {
		t.Fatalf("points count = %d, want 2", len(pts))
	}

	byName := make(map[string]float64)
	for _, p := range pts {
		byName[p.Name] = p.Value
	}

	if byName["yomins_backup_last_status"] != 0 {
		t.Errorf("last_status = %v, want 0", byName["yomins_backup_last_status"])
	}
	if byName["yomins_backup_last_duration_seconds"] != 60 {
		t.Errorf("last_duration_seconds = %v, want 60", byName["yomins_backup_last_duration_seconds"])
	}
	if _, ok := byName["yomins_backup_last_success_timestamp"]; ok {
		t.Error("last_success_timestamp should not be present on error report")
	}
}
