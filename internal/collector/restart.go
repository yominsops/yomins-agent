package collector

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
	"github.com/yominsops/yomins-agent/internal/restartscan"
)

// restartMaxAge is how old a report may be before it is dropped: the timer
// runs hourly, so three missed runs mean it has stopped.
const restartMaxAge = 3 * time.Hour

// RestartCollector turns the report of the root restart timer
// (yomins-agent-restart.timer, `yomins-agent restart-scan`) into metrics:
// services still running code an update replaced. Without a report (an
// install without the timer) it reports nothing.
type RestartCollector struct {
	path string
	now  func() time.Time
}

// NewRestartCollector creates the collector reading the report at path.
func NewRestartCollector(path string) *RestartCollector {
	return &RestartCollector{path: path, now: time.Now}
}

func (c *RestartCollector) Name() string { return "restart" }

func (c *RestartCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	r, err := restartscan.Read(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pts := []metrics.MetricPoint{
		gauge("restart_scan_timestamp_seconds", "When the restart timer last looked for services running replaced code", float64(r.Time.Unix()), nil),
	}
	if r.Error != "" {
		return append(pts, gauge("restart_scan_ok", "1 when the last restart scan worked", 0, nil)), nil
	}
	pts = append(pts, gauge("restart_scan_ok", "1 when the last restart scan worked", 1, nil))
	if c.now().Sub(r.Time) > restartMaxAge {
		return pts, nil
	}
	pts = append(pts,
		gauge("system_services_restart_required", "Services still running a library or binary an update replaced: the fix takes effect when they restart", float64(len(r.Units)), nil),
		gauge("system_processes_restart_required_other", "Processes outside a service (login sessions, user managers) still running replaced code", float64(r.Other), nil))
	for _, u := range r.Units {
		pts = append(pts, gauge("system_service_restart_required", "1 for each service that needs a restart to use updated code", 1, map[string]string{"unit": u}))
	}
	return pts, nil
}
