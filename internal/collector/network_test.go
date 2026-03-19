package collector_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yominsops/yomins-agent/internal/collector"
	"github.com/yominsops/yomins-agent/internal/metrics"
)

type mockNetworkReader struct {
	counters []collector.IOCountersStat
	err      error
}

func (m *mockNetworkReader) IOCountersWithContext(_ context.Context, _ bool) ([]collector.IOCountersStat, error) {
	return m.counters, m.err
}

func TestNetworkCollector_Name(t *testing.T) {
	c := collector.NewNetworkCollectorWithReader(&mockNetworkReader{})
	if c.Name() != "network" {
		t.Errorf("Name() = %q, want network", c.Name())
	}
}

func TestNetworkCollector_Collect(t *testing.T) {
	mock := &mockNetworkReader{
		counters: []collector.IOCountersStat{
			{Name: "eth0", BytesSent: 1000, BytesRecv: 2000, PacketsSent: 10, PacketsRecv: 20},
		},
	}
	c := collector.NewNetworkCollectorWithReader(mock)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pts) != 4 {
		t.Errorf("points count = %d, want 4", len(pts))
	}

	byName := make(map[string]metrics.MetricPoint)
	for _, p := range pts {
		byName[p.Name] = p
	}

	if byName["network_bytes_sent_total"].Value != 1000 {
		t.Errorf("bytes_sent = %v, want 1000", byName["network_bytes_sent_total"].Value)
	}
	if byName["network_bytes_sent_total"].Type != metrics.Counter {
		t.Errorf("type should be Counter")
	}
	if byName["network_bytes_sent_total"].Labels["interface"] != "eth0" {
		t.Errorf("interface label = %q, want eth0", byName["network_bytes_sent_total"].Labels["interface"])
	}
}

func TestNetworkCollector_LoopbackFiltered(t *testing.T) {
	mock := &mockNetworkReader{
		counters: []collector.IOCountersStat{
			{Name: "lo", BytesSent: 999, BytesRecv: 999},
			{Name: "eth0", BytesSent: 1000, BytesRecv: 2000},
		},
	}
	c := collector.NewNetworkCollectorWithReader(mock)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Only eth0 (4 metrics); lo is filtered.
	if len(pts) != 4 {
		t.Errorf("points count = %d, want 4 (lo filtered)", len(pts))
	}
	for _, p := range pts {
		if p.Labels["interface"] == "lo" {
			t.Error("loopback interface should be filtered")
		}
	}
}

func TestNetworkCollector_ReaderError(t *testing.T) {
	mock := &mockNetworkReader{err: errors.New("no net")}
	c := collector.NewNetworkCollectorWithReader(mock)
	_, err := c.Collect(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
}
