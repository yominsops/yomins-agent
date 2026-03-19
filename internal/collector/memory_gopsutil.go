package collector

import (
	"context"

	"github.com/shirou/gopsutil/v3/mem"
)

type realMemoryReader struct{}

func (realMemoryReader) VirtualMemoryWithContext(ctx context.Context) (*VirtualMemoryStat, error) {
	v, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return &VirtualMemoryStat{
		Total:       v.Total,
		Available:   v.Available,
		Used:        v.Used,
		UsedPercent: v.UsedPercent,
	}, nil
}

func (realMemoryReader) SwapMemoryWithContext(ctx context.Context) (*SwapMemoryStat, error) {
	s, err := mem.SwapMemoryWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return &SwapMemoryStat{
		Total:       s.Total,
		Used:        s.Used,
		Free:        s.Free,
		UsedPercent: s.UsedPercent,
	}, nil
}
