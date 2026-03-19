package collector

import (
	"context"

	"github.com/shirou/gopsutil/v3/disk"
)

type realDiskReader struct{}

func (realDiskReader) PartitionsWithContext(ctx context.Context, all bool) ([]PartitionStat, error) {
	parts, err := disk.PartitionsWithContext(ctx, all)
	if err != nil {
		return nil, err
	}
	result := make([]PartitionStat, len(parts))
	for i, p := range parts {
		result[i] = PartitionStat{
			Mountpoint: p.Mountpoint,
			Fstype:     p.Fstype,
			Device:     p.Device,
		}
	}
	return result, nil
}

func (realDiskReader) UsageWithContext(ctx context.Context, path string) (*DiskUsageStat, error) {
	u, err := disk.UsageWithContext(ctx, path)
	if err != nil {
		return nil, err
	}
	return &DiskUsageStat{
		Total:             u.Total,
		Free:              u.Free,
		Used:              u.Used,
		UsedPercent:       u.UsedPercent,
		InodesTotal:       u.InodesTotal,
		InodesUsed:        u.InodesUsed,
		InodesFree:        u.InodesFree,
		InodesUsedPercent: u.InodesUsedPercent,
	}, nil
}
