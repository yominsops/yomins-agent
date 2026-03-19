package metrics_test

import (
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

func TestEncode_GaugeMetric(t *testing.T) {
	ms := metrics.MetricSet{
		AgentID:  "test-agent-id",
		Hostname: "test-host",
		Version:  "1.0.0",
		Source:   "yomins_agent",
		Points: []metrics.MetricPoint{
			{
				Name:  "cpu_usage_percent",
				Help:  "CPU usage percentage",
				Type:  metrics.Gauge,
				Value: 42.5,
			},
		},
		CollectedAt: time.Now(),
	}

	data, err := metrics.Encode(ms)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	families := parseText(t, data)

	fam, ok := families["cpu_usage_percent"]
	if !ok {
		t.Fatalf("metric cpu_usage_percent not found in output")
	}
	if fam.GetType() != dto.MetricType_GAUGE {
		t.Errorf("type = %v, want GAUGE", fam.GetType())
	}
	if len(fam.Metric) != 1 {
		t.Fatalf("metric count = %d, want 1", len(fam.Metric))
	}
	m := fam.Metric[0]
	if m.GetGauge().GetValue() != 42.5 {
		t.Errorf("gauge value = %v, want 42.5", m.GetGauge().GetValue())
	}
	assertLabel(t, m, "agent_id", "test-agent-id")
	assertLabel(t, m, "hostname", "test-host")
	assertLabel(t, m, "agent_version", "1.0.0")
	assertLabel(t, m, "source", "yomins_agent")
}

func TestEncode_CounterMetric(t *testing.T) {
	ms := metrics.MetricSet{
		AgentID:  "agent-1",
		Hostname: "host-1",
		Version:  "0.1.0",
		Source:   "yomins_agent",
		Points: []metrics.MetricPoint{
			{
				Name:  "network_bytes_recv_total",
				Help:  "Total received bytes",
				Type:  metrics.Counter,
				Value: 123456,
				Labels: map[string]string{
					"interface": "eth0",
				},
			},
		},
	}

	data, err := metrics.Encode(ms)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	families := parseText(t, data)
	fam, ok := families["network_bytes_recv_total"]
	if !ok {
		t.Fatalf("metric network_bytes_recv_total not found")
	}
	if fam.GetType() != dto.MetricType_COUNTER {
		t.Errorf("type = %v, want COUNTER", fam.GetType())
	}
	m := fam.Metric[0]
	if m.GetCounter().GetValue() != 123456 {
		t.Errorf("counter value = %v, want 123456", m.GetCounter().GetValue())
	}
	assertLabel(t, m, "interface", "eth0")
}

func TestEncode_MultiplePointsSameMetric(t *testing.T) {
	ms := metrics.MetricSet{
		AgentID:  "a",
		Hostname: "h",
		Version:  "v",
		Source:   "yomins_agent",
		Points: []metrics.MetricPoint{
			{Name: "disk_usage_percent", Type: metrics.Gauge, Value: 60, Labels: map[string]string{"mountpoint": "/"}},
			{Name: "disk_usage_percent", Type: metrics.Gauge, Value: 80, Labels: map[string]string{"mountpoint": "/data"}},
		},
	}

	data, err := metrics.Encode(ms)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	families := parseText(t, data)
	fam, ok := families["disk_usage_percent"]
	if !ok {
		t.Fatalf("disk_usage_percent not found")
	}
	if len(fam.Metric) != 2 {
		t.Errorf("metric count = %d, want 2", len(fam.Metric))
	}
}

func TestEncode_EmptyMetricSet(t *testing.T) {
	ms := metrics.MetricSet{Source: "yomins_agent"}
	data, err := metrics.Encode(ms)
	if err != nil {
		t.Fatalf("Encode empty: %v", err)
	}
	// Output may be empty or just comments — it must not error.
	_ = data
}

func TestEncode_ContentType(t *testing.T) {
	if !strings.Contains(metrics.ContentType, "text/plain") {
		t.Errorf("ContentType = %q, expected text/plain", metrics.ContentType)
	}
}

// parseText is a test helper that decodes Prometheus text format into a map.
func parseText(t *testing.T, data []byte) map[string]*dto.MetricFamily {
	t.Helper()
	var parser expfmt.TextParser
	families, err := parser.TextToMetricFamilies(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse output: %v", err)
	}
	return families
}

func assertLabel(t *testing.T, m *dto.Metric, name, want string) {
	t.Helper()
	for _, lp := range m.Label {
		if lp.GetName() == name {
			if lp.GetValue() != want {
				t.Errorf("label %q = %q, want %q", name, lp.GetValue(), want)
			}
			return
		}
	}
	t.Errorf("label %q not found", name)
}
