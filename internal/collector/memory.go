package collector

import (
	"context"
	"fmt"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// VirtualMemoryStat holds the fields we need from gopsutil.
type VirtualMemoryStat struct {
	Total       uint64
	Available   uint64
	Used        uint64
	UsedPercent float64
}

// SwapMemoryStat holds swap memory fields.
type SwapMemoryStat struct {
	Total       uint64
	Used        uint64
	Free        uint64
	UsedPercent float64
}

// MemoryReader abstracts gopsutil memory calls.
type MemoryReader interface {
	VirtualMemoryWithContext(ctx context.Context) (*VirtualMemoryStat, error)
	SwapMemoryWithContext(ctx context.Context) (*SwapMemoryStat, error)
}

// MemoryCollector collects virtual and swap memory metrics.
type MemoryCollector struct {
	reader MemoryReader
}

// NewMemoryCollector returns a MemoryCollector backed by the real OS.
func NewMemoryCollector() *MemoryCollector {
	return &MemoryCollector{reader: realMemoryReader{}}
}

// NewMemoryCollectorWithReader returns a MemoryCollector with an injected reader.
func NewMemoryCollectorWithReader(r MemoryReader) *MemoryCollector {
	return &MemoryCollector{reader: r}
}

func (c *MemoryCollector) Name() string { return "memory" }

func (c *MemoryCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	vm, err := c.reader.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("virtual memory: %w", err)
	}

	pts := []metrics.MetricPoint{
		{Name: "memory_total_bytes", Help: "Total physical memory in bytes", Type: metrics.Gauge, Value: float64(vm.Total)},
		{Name: "memory_available_bytes", Help: "Available memory in bytes", Type: metrics.Gauge, Value: float64(vm.Available)},
		{Name: "memory_used_bytes", Help: "Used memory in bytes", Type: metrics.Gauge, Value: float64(vm.Used)},
		{Name: "memory_used_percent", Help: "Memory usage percentage (0-100)", Type: metrics.Gauge, Value: vm.UsedPercent},
	}

	swap, err := c.reader.SwapMemoryWithContext(ctx)
	if err == nil {
		pts = append(pts,
			metrics.MetricPoint{Name: "swap_total_bytes", Help: "Total swap memory in bytes", Type: metrics.Gauge, Value: float64(swap.Total)},
			metrics.MetricPoint{Name: "swap_used_bytes", Help: "Used swap memory in bytes", Type: metrics.Gauge, Value: float64(swap.Used)},
			metrics.MetricPoint{Name: "swap_free_bytes", Help: "Free swap memory in bytes", Type: metrics.Gauge, Value: float64(swap.Free)},
			metrics.MetricPoint{Name: "swap_used_percent", Help: "Swap usage percentage (0-100)", Type: metrics.Gauge, Value: swap.UsedPercent},
		)
	}

	return pts, nil
}
