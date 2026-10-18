// Package integrations collects metrics from the services on the host
// (nginx, PHP-FPM, MySQL, mail queues, local Prometheus endpoints). Each one
// finds its service itself and reports agent_integration_status, so the
// portal can tell "not installed" from "installed, needs a status page".
package integrations

import (
	"github.com/yominsops/yomins-agent/internal/metrics"
)

// Integration states.
const (
	StatusOK = "ok"
	// StatusUnconfigured: the service runs but exposes no statistics yet
	// (e.g. no nginx stub_status, no pm.status_path).
	StatusUnconfigured = "unconfigured"
	// StatusError: statistics are configured but could not be read.
	StatusError = "error"
)

// status is the point reporting how an integration fared on this pass.
func status(integration, state, instance string) metrics.MetricPoint {
	l := map[string]string{"integration": integration, "status": state}
	if instance != "" {
		l["instance"] = instance
	}
	return metrics.MetricPoint{Name: "agent_integration_status", Help: "1 per integration and instance, labelled with how reading it went (ok, unconfigured, error)", Type: metrics.Gauge, Value: 1, Labels: l}
}

func gauge(name, help string, v float64, labels map[string]string) metrics.MetricPoint {
	return metrics.MetricPoint{Name: name, Help: help, Type: metrics.Gauge, Value: v, Labels: labels}
}

func counter(name, help string, v float64, labels map[string]string) metrics.MetricPoint {
	return metrics.MetricPoint{Name: name, Help: help, Type: metrics.Counter, Value: v, Labels: labels}
}
