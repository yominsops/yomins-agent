package collector_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yominsops/yomins-agent/internal/collector"
	"github.com/yominsops/yomins-agent/internal/metrics"
)

type mockMemoryReader struct {
	vm    *collector.VirtualMemoryStat
	swap  *collector.SwapMemoryStat
	vmErr error
}

func (m *mockMemoryReader) VirtualMemoryWithContext(_ context.Context) (*collector.VirtualMemoryStat, error) {
	return m.vm, m.vmErr
}
func (m *mockMemoryReader) SwapMemoryWithContext(_ context.Context) (*collector.SwapMemoryStat, error) {
	if m.swap == nil {
		return nil, errors.New("no swap")
	}
	return m.swap, nil
}

func TestMemoryCollector_Name(t *testing.T) {
	c := collector.NewMemoryCollectorWithReader(&mockMemoryReader{vm: &collector.VirtualMemoryStat{}})
	if c.Name() != "memory" {
		t.Errorf("Name() = %q, want memory", c.Name())
	}
}

func TestMemoryCollector_Collect(t *testing.T) {
	mock := &mockMemoryReader{
		vm: &collector.VirtualMemoryStat{
			Total:       8 * 1024 * 1024 * 1024,
			Available:   4 * 1024 * 1024 * 1024,
			Used:        4 * 1024 * 1024 * 1024,
			UsedPercent: 50.0,
		},
		swap: &collector.SwapMemoryStat{
			Total:       2 * 1024 * 1024 * 1024,
			Used:        512 * 1024 * 1024,
			Free:        1536 * 1024 * 1024,
			UsedPercent: 25.0,
		},
	}
	c := collector.NewMemoryCollectorWithReader(mock)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 4 vm metrics + 4 swap metrics
	if len(pts) != 8 {
		t.Errorf("points count = %d, want 8", len(pts))
	}

	byName := make(map[string]metrics.MetricPoint)
	for _, p := range pts {
		byName[p.Name] = p
	}

	if byName["memory_used_percent"].Value != 50.0 {
		t.Errorf("memory_used_percent = %v, want 50.0", byName["memory_used_percent"].Value)
	}
	if byName["swap_used_percent"].Value != 25.0 {
		t.Errorf("swap_used_percent = %v, want 25.0", byName["swap_used_percent"].Value)
	}
}

func TestMemoryCollector_VMError(t *testing.T) {
	mock := &mockMemoryReader{vmErr: errors.New("no mem")}
	c := collector.NewMemoryCollectorWithReader(mock)
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestMemoryCollector_SwapErrorIgnored(t *testing.T) {
	// Swap failure is non-fatal: VM metrics should still be returned.
	mock := &mockMemoryReader{
		vm: &collector.VirtualMemoryStat{Total: 1024, UsedPercent: 10},
		// swap is nil → returns error
	}
	c := collector.NewMemoryCollectorWithReader(mock)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pts) != 4 {
		t.Errorf("points count = %d, want 4 (no swap)", len(pts))
	}
}
