package collector

import (
	"context"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
)

// realCPUReader implements CPUReader using gopsutil.
type realCPUReader struct{}

func (realCPUReader) PercentWithContext(ctx context.Context, interval time.Duration, percpu bool) ([]float64, error) {
	return cpu.PercentWithContext(ctx, interval, percpu)
}
