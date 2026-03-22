package collector_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yominsops/yomins-agent/internal/collector"
)

type mockDiskReader struct {
	partitions []collector.PartitionStat
	usage      map[string]*collector.DiskUsageStat
	partsErr   error
}

func (m *mockDiskReader) PartitionsWithContext(_ context.Context, _ bool) ([]collector.PartitionStat, error) {
	return m.partitions, m.partsErr
}

func (m *mockDiskReader) UsageWithContext(_ context.Context, path string) (*collector.DiskUsageStat, error) {
	if u, ok := m.usage[path]; ok {
		return u, nil
	}
	return nil, errors.New("usage not found")
}

func TestDiskCollector_Name(t *testing.T) {
	c := collector.NewDiskCollectorWithReader(&mockDiskReader{})
	if c.Name() != "disk" {
		t.Errorf("Name() = %q, want disk", c.Name())
	}
}

func TestDiskCollector_Collect(t *testing.T) {
	mock := &mockDiskReader{
		partitions: []collector.PartitionStat{
			{Mountpoint: "/", Fstype: "ext4", Device: "/dev/sda1"},
		},
		usage: map[string]*collector.DiskUsageStat{
			"/": {
				Total:             100 * 1024 * 1024 * 1024,
				Used:              60 * 1024 * 1024 * 1024,
				Free:              40 * 1024 * 1024 * 1024,
				UsedPercent:       60.0,
				InodesTotal:       1000000,
				InodesUsed:        500000,
				InodesFree:        500000,
				InodesUsedPercent: 50.0,
			},
		},
	}
	c := collector.NewDiskCollectorWithReader(mock)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 8 metrics per partition
	if len(pts) != 8 {
		t.Errorf("points count = %d, want 8", len(pts))
	}

	byName := make(map[string]float64)
	for _, p := range pts {
		byName[p.Name] = p.Value
	}
	if byName["disk_used_percent"] != 60.0 {
		t.Errorf("disk_used_percent = %v, want 60.0", byName["disk_used_percent"])
	}
	if byName["disk_inodes_used_percent"] != 50.0 {
		t.Errorf("disk_inodes_used_percent = %v, want 50.0", byName["disk_inodes_used_percent"])
	}
}

func TestDiskCollector_PartitionsError(t *testing.T) {
	mock := &mockDiskReader{partsErr: errors.New("no partitions")}
	c := collector.NewDiskCollectorWithReader(mock)
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestDiskCollector_ExcludeMountpoint(t *testing.T) {
	mock := &mockDiskReader{
		partitions: []collector.PartitionStat{
			{Mountpoint: "/", Fstype: "ext4", Device: "/dev/sda1"},
			{Mountpoint: "/tmp", Fstype: "tmpfs", Device: "tmpfs"},
		},
		usage: map[string]*collector.DiskUsageStat{
			"/":    {Total: 100, UsedPercent: 10},
			"/tmp": {Total: 50, UsedPercent: 5},
		},
	}
	c := collector.NewDiskCollectorWithReaderAndExcludes(mock, []string{"/tmp"})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 8 metrics for "/" only; "/tmp" is excluded
	if len(pts) != 8 {
		t.Errorf("points count = %d, want 8", len(pts))
	}
	for _, p := range pts {
		if p.Labels["mountpoint"] == "/tmp" {
			t.Error("excluded mountpoint /tmp should not appear in results")
		}
	}
}

func TestDiskCollector_ExcludeAll(t *testing.T) {
	mock := &mockDiskReader{
		partitions: []collector.PartitionStat{
			{Mountpoint: "/", Fstype: "ext4"},
		},
		usage: map[string]*collector.DiskUsageStat{
			"/": {Total: 100},
		},
	}
	c := collector.NewDiskCollectorWithReaderAndExcludes(mock, []string{"/"})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pts) != 0 {
		t.Errorf("points count = %d, want 0 (all excluded)", len(pts))
	}
}

func TestDiskCollector_UsageErrorSkipped(t *testing.T) {
	// Individual partition usage errors are skipped; others still collected.
	mock := &mockDiskReader{
		partitions: []collector.PartitionStat{
			{Mountpoint: "/", Fstype: "ext4"},
			{Mountpoint: "/data", Fstype: "ext4"},
		},
		usage: map[string]*collector.DiskUsageStat{
			// Only "/" has usage; "/data" will return error.
			"/": {Total: 100, UsedPercent: 10},
		},
	}
	c := collector.NewDiskCollectorWithReader(mock)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 8 metrics for "/" only
	if len(pts) != 8 {
		t.Errorf("points count = %d, want 8", len(pts))
	}
}
