package collector_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yominsops/yomins-agent/internal/collector"
)

type mockSystemReader struct {
	uptime  uint64
	load    *collector.LoadAvgStat
	upErr   error
	loadErr error
}

func (m *mockSystemReader) UptimeWithContext(_ context.Context) (uint64, error) {
	return m.uptime, m.upErr
}
func (m *mockSystemReader) LoadAvgWithContext(_ context.Context) (*collector.LoadAvgStat, error) {
	return m.load, m.loadErr
}

func TestSystemCollector_Name(t *testing.T) {
	c := collector.NewSystemCollectorWithReader(&mockSystemReader{load: &collector.LoadAvgStat{}})
	if c.Name() != "system" {
		t.Errorf("Name() = %q, want system", c.Name())
	}
}

func TestSystemCollector_Collect(t *testing.T) {
	mock := &mockSystemReader{
		uptime: 86400,
		load:   &collector.LoadAvgStat{Load1: 1.0, Load5: 0.8, Load15: 0.6},
	}
	c := collector.NewSystemCollectorWithReader(mock)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 uptime + 3 load average (1m, 5m, 15m)
	if len(pts) != 4 {
		t.Fatalf("points count = %d, want 4", len(pts))
	}

	byPeriod := make(map[string]float64)
	var uptime float64
	for _, p := range pts {
		if p.Name == "system_uptime_seconds" {
			uptime = p.Value
		}
		if p.Name == "system_load_average" {
			byPeriod[p.Labels["period"]] = p.Value
		}
	}

	if uptime != 86400 {
		t.Errorf("uptime = %v, want 86400", uptime)
	}
	if byPeriod["1m"] != 1.0 {
		t.Errorf("load 1m = %v, want 1.0", byPeriod["1m"])
	}
	if byPeriod["5m"] != 0.8 {
		t.Errorf("load 5m = %v, want 0.8", byPeriod["5m"])
	}
	if byPeriod["15m"] != 0.6 {
		t.Errorf("load 15m = %v, want 0.6", byPeriod["15m"])
	}
}

func TestSystemCollector_UptimeError(t *testing.T) {
	mock := &mockSystemReader{upErr: errors.New("no uptime")}
	c := collector.NewSystemCollectorWithReader(mock)
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestSystemCollector_LoadError(t *testing.T) {
	mock := &mockSystemReader{uptime: 100, loadErr: errors.New("no load")}
	c := collector.NewSystemCollectorWithReader(mock)
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}
