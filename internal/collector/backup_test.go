package collector_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/collector"
	"github.com/yominsops/yomins-agent/internal/config"
)

type mockBackupReader struct {
	data []byte
	err  error
}

func (m *mockBackupReader) ReadReport(string) ([]byte, error) {
	return m.data, m.err
}

func TestBackupCollector_Name(t *testing.T) {
	c := collector.NewBackupCollectorWithReader(&mockBackupReader{err: os.ErrNotExist}, nil)
	if c.Name() != "backup" {
		t.Errorf("Name() = %q, want backup", c.Name())
	}
}

func TestBackupCollector_FileNotExist(t *testing.T) {
	c := collector.NewBackupCollectorWithReader(&mockBackupReader{err: os.ErrNotExist}, nil)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if len(pts) != 0 {
		t.Errorf("expected no points for missing file, got %d", len(pts))
	}
}

func TestBackupCollector_MalformedJSON(t *testing.T) {
	c := collector.NewBackupCollectorWithReader(&mockBackupReader{data: []byte("not json")}, nil)
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestBackupCollector_ReadError(t *testing.T) {
	c := collector.NewBackupCollectorWithReader(&mockBackupReader{err: fmt.Errorf("disk error")}, nil)
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

	c := collector.NewBackupCollectorWithReader(&mockBackupReader{data: []byte(json)}, nil)
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

	c := collector.NewBackupCollectorWithReader(&mockBackupReader{data: []byte(json)}, nil)
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

type mapBackupReader map[string]string

func (m mapBackupReader) ReadReport(path string) ([]byte, error) {
	if path == "/broken.json" {
		return nil, fmt.Errorf("permission denied")
	}
	v, ok := m[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(v), nil
}

// Several reports: each is labeled with its name, carries its limit when set; a missing
// one is skipped, an unreadable one is an error that does not hide the others.
func TestBackupCollector_SeveralReports(t *testing.T) {
	ok := `{"status":"success","start_time":"2026-11-25T04:15:01+02:00","end_time":"2026-11-25T04:21:27+02:00"}`
	r := mapBackupReader{"/home.json": ok, "/sync.json": `{"status":"error","start_time":"2026-11-22T03:00:01Z","end_time":"2026-11-22T03:00:02Z"}`}
	c := collector.NewBackupCollectorWithReader(r, []config.WatchedFile{
		{Name: "backup", Path: "/home.json"},
		{Name: "s3-to-ftp", Path: "/sync.json", MaxAge: 504 * time.Hour},
		{Name: "absent", Path: "/absent.json"},
		{Name: "broken", Path: "/broken.json"},
	})
	pts, err := c.Collect(context.Background())
	if err == nil {
		t.Fatal("the unreadable report must be reported")
	}
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Labels["backup"]+"/"+p.Name] = p.Value
	}
	if got["backup/yomins_backup_last_status"] != 1 || got["s3-to-ftp/yomins_backup_last_status"] != 0 {
		t.Errorf("statuses: %v", got)
	}
	if got["s3-to-ftp/yomins_backup_max_age_seconds"] != (504 * time.Hour).Seconds() {
		t.Errorf("limit: %v", got)
	}
	if _, set := got["backup/yomins_backup_max_age_seconds"]; set {
		t.Error("no limit, no metric")
	}
	for k := range got {
		if strings.HasPrefix(k, "absent/") || strings.HasPrefix(k, "broken/") {
			t.Errorf("unexpected %s", k)
		}
	}
}
