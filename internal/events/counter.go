package events

import (
	"context"
	"sort"
	"sync"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// AllTypes lists every event type the agent can report.
var AllTypes = []EventType{
	EventAuthLoginSuccess, EventAuthLoginFailed, EventAuthLogout, EventAuthSudo, EventAuthBruteforceDetected, EventAuthLoginNewIP,
	EventProcessStart, EventProcessStop, EventProcessHighCPU, EventProcessHighMemory, EventProcessSuspicious, EventProcessExecTmp, EventProcessReverseShell,
	EventNetworkConnectionOpen, EventNetworkScanDetected, EventNetworkSuspiciousPort,
	EventSystemReboot, EventSystemOOMKiller, EventSystemUserCreated, EventSystemUserDeleted, EventSystemConfigModified,
}

// Counter counts the events by type and reports them with the metrics as
// security_events_total{type}, so alert rules can fire on them. Every type
// starts at zero: a rate over a series that appears with its first event
// would miss that event.
type Counter struct {
	mu     sync.Mutex
	counts map[EventType]float64
}

// NewCounter returns a counter with every known type at zero.
func NewCounter() *Counter {
	c := &Counter{counts: make(map[EventType]float64, len(AllTypes))}
	for _, t := range AllTypes {
		c.counts[t] = 0
	}
	return c
}

// Add counts one event.
func (c *Counter) Add(ev Event) {
	c.mu.Lock()
	c.counts[ev.Type]++
	c.mu.Unlock()
}

func (c *Counter) Name() string { return "security_events" }

func (c *Counter) Collect(context.Context) ([]metrics.MetricPoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	types := make([]string, 0, len(c.counts))
	for t := range c.counts {
		types = append(types, string(t))
	}
	sort.Strings(types)
	pts := make([]metrics.MetricPoint, 0, len(types))
	for _, t := range types {
		pts = append(pts, metrics.MetricPoint{Name: "security_events_total", Help: "Security events detected since the agent started, by type",
			Type: metrics.Counter, Value: c.counts[EventType(t)], Labels: map[string]string{"type": t}})
	}
	return pts, nil
}
