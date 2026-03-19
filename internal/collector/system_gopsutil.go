package collector

import (
	"context"

	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
)

type realSystemReader struct{}

func (realSystemReader) UptimeWithContext(ctx context.Context) (uint64, error) {
	return host.UptimeWithContext(ctx)
}

func (realSystemReader) LoadAvgWithContext(ctx context.Context) (*LoadAvgStat, error) {
	l, err := load.AvgWithContext(ctx)
	if err != nil {
		return nil, err
	}
	return &LoadAvgStat{
		Load1:  l.Load1,
		Load5:  l.Load5,
		Load15: l.Load15,
	}, nil
}
