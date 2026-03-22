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
	if len(pts) != 8 {
		t.Errorf("points count = %d, want 8", len(pts))
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
	// Only eth0 (8 metrics); lo is filtered.
	if len(pts) != 8 {
		t.Errorf("points count = %d, want 8 (lo filtered)", len(pts))
	}
	for _, p := range pts {
		if p.Labels["interface"] == "lo" {
			t.Error("loopback interface should be filtered")
		}
	}
}

func TestNetworkCollector_ErrorDropCounters(t *testing.T) {
	mock := &mockNetworkReader{
		counters: []collector.IOCountersStat{
			{
				Name:        "eth0",
				BytesSent:   100, BytesRecv: 200,
				PacketsSent: 5, PacketsRecv: 10,
				Errin: 3, Errout: 1,
				Dropin: 7, Dropout: 2,
			},
		},
	}
	c := collector.NewNetworkCollectorWithReader(mock)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(pts) != 8 {
		t.Fatalf("points count = %d, want 8", len(pts))
	}
	byName := make(map[string]metrics.MetricPoint)
	for _, p := range pts {
		byName[p.Name] = p
	}
	checks := map[string]float64{
		"network_errors_in_total":  3,
		"network_errors_out_total": 1,
		"network_drops_in_total":   7,
		"network_drops_out_total":  2,
	}
	for name, want := range checks {
		got, ok := byName[name]
		if !ok {
			t.Errorf("metric %q not found", name)
			continue
		}
		if got.Value != want {
			t.Errorf("%s = %v, want %v", name, got.Value, want)
		}
		if got.Type != metrics.Counter {
			t.Errorf("%s type = %v, want Counter", name, got.Type)
		}
	}
}

func TestNetworkCollector_ExcludeInterface(t *testing.T) {
	mock := &mockNetworkReader{
		counters: []collector.IOCountersStat{
			{Name: "eth0", BytesSent: 100, BytesRecv: 200, PacketsSent: 5, PacketsRecv: 10},
			{Name: "eth1", BytesSent: 300, BytesRecv: 400, PacketsSent: 15, PacketsRecv: 20},
		},
	}
	// Exclude lo (default) and eth1
	c := collector.NewNetworkCollectorWithReaderAndExcludes(mock, []string{"lo", "eth1"})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 8 metrics for eth0 only; eth1 excluded
	if len(pts) != 8 {
		t.Errorf("points count = %d, want 8", len(pts))
	}
	for _, p := range pts {
		if p.Labels["interface"] == "eth1" {
			t.Error("excluded interface eth1 should not appear in results")
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
