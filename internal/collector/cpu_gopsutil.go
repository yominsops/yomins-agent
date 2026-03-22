package collector

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
)

// realCPUReader implements both CPUReader and CPUTimesReader using gopsutil.
type realCPUReader struct{}

func (realCPUReader) PercentWithContext(ctx context.Context, interval time.Duration, percpu bool) ([]float64, error) {
	return cpu.PercentWithContext(ctx, interval, percpu)
}

func (realCPUReader) TimesWithContext(ctx context.Context, percpu bool) ([]CPUTimesStat, error) {
	times, err := cpu.TimesWithContext(ctx, percpu)
	if err != nil {
		return nil, err
	}
	result := make([]CPUTimesStat, len(times))
	for i, t := range times {
		result[i] = CPUTimesStat{
			User:   t.User,
			System: t.System,
			Idle:   t.Idle,
			Iowait: t.Iowait,
		}
	}
	return result, nil
}
