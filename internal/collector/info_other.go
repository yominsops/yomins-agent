//go:build !linux

package collector

import (
	"context"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

type realInfoReader struct {
	virtOverride string
}

func newRealInfoReader(virtOverride string) InfoReader {
	return &realInfoReader{virtOverride: virtOverride}
}

func (r *realInfoReader) SystemInfoWithContext(_ context.Context) (*SystemInfoStat, error) {
	return &SystemInfoStat{Virtualization: r.virtOverride}, nil
}

func (r *realInfoReader) CPUInfoWithContext(ctx context.Context) (*CPUInfoStat, error) {
	infos, err := cpu.InfoWithContext(ctx)
	if err != nil {
		return &CPUInfoStat{}, nil
	}
	model := ""
	if len(infos) > 0 {
		model = infos[0].ModelName
	}
	physCores, _ := cpu.CountsWithContext(ctx, false)
	logThreads, _ := cpu.CountsWithContext(ctx, true)
	return &CPUInfoStat{
		Model:   model,
		Cores:   physCores,
		Threads: logThreads,
	}, nil
}

func (r *realInfoReader) PackageUpdateTimesWithContext(_ context.Context) (*PackageUpdateTimes, error) {
	return &PackageUpdateTimes{}, nil
}

func (r *realInfoReader) KernelCareInfoWithContext(_ context.Context) (*KernelCareInfoStat, error) {
	return &KernelCareInfoStat{Installed: false}, nil
}

func (r *realInfoReader) MemoryInfoWithContext(ctx context.Context) (*MemoryInfo, error) {
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return &MemoryInfo{}, nil
	}
	return &MemoryInfo{TotalMB: int(vm.Total / (1024 * 1024))}, nil
}

func (r *realInfoReader) DiskHardwareWithContext(_ context.Context) ([]DiskHardwareStat, error) {
	return nil, nil
}

func (r *realInfoReader) NetworkHardwareWithContext(_ context.Context) ([]NetworkHardwareStat, error) {
	return nil, nil
}

func (r *realInfoReader) SystemHardwareWithContext(_ context.Context) (*SystemHardwareStat, error) {
	return &SystemHardwareStat{}, nil
}
