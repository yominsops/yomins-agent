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
	// Default includes (eth*, ens*, enp*, eno*, wlan*, wlp*) match eth0 but not lo.
	c := collector.NewNetworkCollectorWithReader(mock)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
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

// TestNetworkCollector_ExcludeInterface tests the legacy exclude-mode shim.
func TestNetworkCollector_ExcludeInterface(t *testing.T) {
	mock := &mockNetworkReader{
		counters: []collector.IOCountersStat{
			{Name: "eth0", BytesSent: 100, BytesRecv: 200, PacketsSent: 5, PacketsRecv: 10},
			{Name: "eth1", BytesSent: 300, BytesRecv: 400, PacketsSent: 15, PacketsRecv: 20},
		},
	}
	// Exclude lo and eth1 (exclude mode, no includes).
	c := collector.NewNetworkCollectorWithReaderAndExcludes(mock, []string{"lo", "eth1"})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
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

// TestNetworkCollector_IncludeGlob verifies include mode with glob patterns.
func TestNetworkCollector_IncludeGlob(t *testing.T) {
	mock := &mockNetworkReader{
		counters: []collector.IOCountersStat{
			{Name: "eth0", BytesSent: 100},
			{Name: "ens3", BytesSent: 200},
			{Name: "docker0", BytesSent: 300},
			{Name: "veth1a2b3c", BytesSent: 400},
			{Name: "lo", BytesSent: 500},
		},
	}
	c := collector.NewNetworkCollectorWithReaderAndFilters(mock, []string{"eth*", "ens*"}, nil)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Only eth0 and ens3 should pass (2 × 8 = 16 points).
	if len(pts) != 16 {
		t.Errorf("points count = %d, want 16", len(pts))
	}
	seen := make(map[string]bool)
	for _, p := range pts {
		seen[p.Labels["interface"]] = true
	}
	if !seen["eth0"] {
		t.Error("eth0 should be included")
	}
	if !seen["ens3"] {
		t.Error("ens3 should be included")
	}
	for _, unwanted := range []string{"docker0", "veth1a2b3c", "lo"} {
		if seen[unwanted] {
			t.Errorf("interface %q should not be included", unwanted)
		}
	}
}

// TestNetworkCollector_ExcludeGlob verifies exclude mode with glob patterns.
func TestNetworkCollector_ExcludeGlob(t *testing.T) {
	mock := &mockNetworkReader{
		counters: []collector.IOCountersStat{
			{Name: "eth0", BytesSent: 100},
			{Name: "docker0", BytesSent: 200},
			{Name: "veth1a2b3c", BytesSent: 300},
			{Name: "br-abc123", BytesSent: 400},
			{Name: "tun0", BytesSent: 500},
		},
	}
	// Explicit exclude patterns, no includes → exclude mode.
	c := collector.NewNetworkCollectorWithReaderAndFilters(mock, nil,
		[]string{"docker*", "veth*", "br-*", "tun*", "lo"})
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Only eth0 should survive (8 points).
	if len(pts) != 8 {
		t.Errorf("points count = %d, want 8", len(pts))
	}
	for _, p := range pts {
		if p.Labels["interface"] != "eth0" {
			t.Errorf("unexpected interface %q", p.Labels["interface"])
		}
	}
}

// TestNetworkCollector_DefaultExcludePatterns verifies that DefaultNetworkExcludePatterns
// are applied when no includes and no excludes are provided.
func TestNetworkCollector_DefaultExcludePatterns(t *testing.T) {
	mock := &mockNetworkReader{
		counters: []collector.IOCountersStat{
			{Name: "eth0", BytesSent: 100},
			{Name: "lo", BytesSent: 200},
			{Name: "docker0", BytesSent: 300},
			{Name: "veth1a2b3c", BytesSent: 400},
			{Name: "br-abc", BytesSent: 500},
			{Name: "tun0", BytesSent: 600},
			{Name: "wg0", BytesSent: 700},
		},
	}
	// No includes, no excludes → built-in DefaultNetworkExcludePatterns apply.
	c := collector.NewNetworkCollectorWithReaderAndFilters(mock, nil, nil)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Only eth0 passes the default excludes (8 points).
	if len(pts) != 8 {
		t.Errorf("points count = %d, want 8", len(pts))
	}
	for _, p := range pts {
		if p.Labels["interface"] != "eth0" {
			t.Errorf("unexpected interface %q in output", p.Labels["interface"])
		}
	}
}

// TestNetworkCollector_DefaultIncludeMode verifies that the default constructor
// uses include mode and only passes interfaces matching DefaultNetworkIncludePatterns.
func TestNetworkCollector_DefaultIncludeMode(t *testing.T) {
	mock := &mockNetworkReader{
		counters: []collector.IOCountersStat{
			{Name: "eth0"},
			{Name: "ens3"},
			{Name: "enp2s0"},
			{Name: "eno1"},
			{Name: "wlan0"},
			{Name: "wlp3s0"},
			{Name: "docker0"},
			{Name: "veth1"},
			{Name: "lo"},
			{Name: "erspan0"},
		},
	}
	c := collector.NewNetworkCollectorWithReader(mock)
	pts, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 6 matching interfaces × 8 metrics = 48.
	if len(pts) != 48 {
		t.Errorf("points count = %d, want 48", len(pts))
	}
	seen := make(map[string]bool)
	for _, p := range pts {
		seen[p.Labels["interface"]] = true
	}
	for _, want := range []string{"eth0", "ens3", "enp2s0", "eno1", "wlan0", "wlp3s0"} {
		if !seen[want] {
			t.Errorf("expected interface %q to be included", want)
		}
	}
	for _, unwanted := range []string{"docker0", "veth1", "lo", "erspan0"} {
		if seen[unwanted] {
			t.Errorf("interface %q should not be included", unwanted)
		}
	}
}
