//go:build integration

package collector_test

import (
	"context"
	"testing"

	"github.com/yominsops/yomins-agent/internal/collector"
)

// Integration tests run against the real OS. Use: go test -tags=integration ./...

func TestCPUCollector_Integration(t *testing.T) {
	c := collector.NewCPUCollector()
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("real CPU collect: %v", err)
	}
	if len(pts) == 0 {
		t.Fatal("expected at least one metric point")
	}
	for _, p := range pts {
		switch p.Name {
		case "cpu_usage_percent", "cpu_iowait_percent":
			if p.Value < 0 || p.Value > 100 {
				t.Errorf("%s = %v, want 0-100", p.Name, p.Value)
			}
		case "cpu_seconds_total":
			if p.Value < 0 {
				t.Errorf("cpu_seconds_total = %v, want >= 0", p.Value)
			}
		default:
			t.Errorf("unexpected CPU metric %q", p.Name)
		}
	}
}

func TestMemoryCollector_Integration(t *testing.T) {
	c := collector.NewMemoryCollector()
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("real memory collect: %v", err)
	}
	if len(pts) == 0 {
		t.Fatal("expected at least one metric point")
	}
}

func TestDiskCollector_Integration(t *testing.T) {
	c := collector.NewDiskCollector()
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("real disk collect: %v", err)
	}
	// Most systems have at least a root filesystem.
	if len(pts) == 0 {
		t.Log("warning: no disk metrics collected (may be expected in some environments)")
	}
}

func TestNetworkCollector_Integration(t *testing.T) {
	c := collector.NewNetworkCollector()
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("real network collect: %v", err)
	}
	_ = pts // some CI environments may have no non-loopback interfaces
}

func TestSystemCollector_Integration(t *testing.T) {
	c := collector.NewSystemCollector()
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("real system collect: %v", err)
	}
	if len(pts) != 4 {
		t.Errorf("points count = %d, want 4", len(pts))
	}
}
