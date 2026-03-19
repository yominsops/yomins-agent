package metrics

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/proto"
)

// ContentType is the Prometheus text exposition format content-type header value.
const ContentType = `text/plain; version=0.0.4; charset=utf-8`

// Encode serialises a MetricSet into Prometheus text format (v0.0.4).
// Agent-level labels (agent_id, hostname, version, source) are injected into
// every metric here so that individual collectors remain identity-agnostic.
func Encode(ms MetricSet) ([]byte, error) {
	families := buildFamilies(ms)

	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, f := range families {
		if err := enc.Encode(f); err != nil {
			return nil, fmt.Errorf("encode metric family %q: %w", f.GetName(), err)
		}
	}
	if closer, ok := enc.(io.Closer); ok {
		_ = closer.Close()
	}
	return buf.Bytes(), nil
}

// buildFamilies groups MetricPoints by name into dto.MetricFamily slices.
func buildFamilies(ms MetricSet) []*dto.MetricFamily {
	// preserve insertion order while deduplicating by name
	order := make([]string, 0)
	byName := make(map[string]*dto.MetricFamily)

	agentLabels := agentLabelPairs(ms)

	for _, pt := range ms.Points {
		fam, exists := byName[pt.Name]
		if !exists {
			fam = &dto.MetricFamily{
				Name: proto.String(pt.Name),
				Help: proto.String(pt.Help),
				Type: dtoType(pt.Type),
			}
			byName[pt.Name] = fam
			order = append(order, pt.Name)
		}
		fam.Metric = append(fam.Metric, dtoMetric(pt, agentLabels))
	}

	result := make([]*dto.MetricFamily, 0, len(order))
	for _, name := range order {
		result = append(result, byName[name])
	}
	return result
}

func agentLabelPairs(ms MetricSet) []*dto.LabelPair {
	return []*dto.LabelPair{
		labelPair("agent_id", ms.AgentID),
		labelPair("hostname", ms.Hostname),
		labelPair("agent_version", ms.Version),
		labelPair("source", ms.Source),
	}
}

func dtoMetric(pt MetricPoint, agentLabels []*dto.LabelPair) *dto.Metric {
	labels := make([]*dto.LabelPair, 0, len(agentLabels)+len(pt.Labels))
	labels = append(labels, agentLabels...)

	// Deterministic label order for per-point labels.
	pointLabelKeys := make([]string, 0, len(pt.Labels))
	for k := range pt.Labels {
		pointLabelKeys = append(pointLabelKeys, k)
	}
	sort.Strings(pointLabelKeys)
	for _, k := range pointLabelKeys {
		labels = append(labels, labelPair(k, pt.Labels[k]))
	}

	m := &dto.Metric{Label: labels}
	switch pt.Type {
	case Counter:
		m.Counter = &dto.Counter{Value: proto.Float64(pt.Value)}
	default:
		m.Gauge = &dto.Gauge{Value: proto.Float64(pt.Value)}
	}
	return m
}

func dtoType(t MetricType) *dto.MetricType {
	switch t {
	case Counter:
		v := dto.MetricType_COUNTER
		return &v
	default:
		v := dto.MetricType_GAUGE
		return &v
	}
}

func labelPair(name, value string) *dto.LabelPair {
	return &dto.LabelPair{
		Name:  proto.String(name),
		Value: proto.String(value),
	}
}
