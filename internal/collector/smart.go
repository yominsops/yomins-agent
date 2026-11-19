package collector

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
	"github.com/yominsops/yomins-agent/internal/smart"
)

// smartMaxAge is how old a report may be before its readings are dropped:
// the timer runs hourly, so three missed runs mean it has stopped.
const smartMaxAge = 3 * time.Hour

// SMARTCollector turns the report of the root SMART timer
// (yomins-agent-smart.timer, `yomins-agent smart-scan`) into metrics. Without
// a report (an install without the timer) it reports nothing.
type SMARTCollector struct {
	path string
	now  func() time.Time
}

// NewSMARTCollector creates the collector reading the report at path.
func NewSMARTCollector(path string) *SMARTCollector {
	return &SMARTCollector{path: path, now: time.Now}
}

func (c *SMARTCollector) Name() string { return "smart" }

func (c *SMARTCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	r, err := smart.Read(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pts := []metrics.MetricPoint{
		gauge("smart_smartctl_installed", "1 when smartmontools is installed: without it disk health cannot be read", b2f(r.Smartctl), nil),
		gauge("smart_scan_timestamp_seconds", "When the SMART timer last read the disks", float64(r.Time.Unix()), nil),
	}
	if r.Error != "" {
		pts = append(pts, gauge("smart_scan_ok", "1 when the last SMART scan worked", 0, nil))
	} else if r.Smartctl {
		pts = append(pts, gauge("smart_scan_ok", "1 when the last SMART scan worked", 1, nil))
	}
	if c.now().Sub(r.Time) > smartMaxAge {
		return pts, nil
	}
	for _, d := range r.Devices {
		l := map[string]string{"device": d.Name, "type": d.Type, "protocol": d.Protocol, "model": d.Model, "serial": d.Serial}
		pts = append(pts, gauge("smart_device_standby", "1 when the disk was asleep and left so: its readings are from an earlier scan or absent", b2f(d.Standby), l))
		if d.Healthy != nil {
			pts = append(pts, gauge("smart_device_healthy", "The drive's own verdict (SMART overall health): 0 means it expects to fail — replace it", b2f(*d.Healthy), l))
		}
		if d.TemperatureC != nil {
			pts = append(pts, gauge("smart_temperature_celsius", "Drive temperature", *d.TemperatureC, l))
		}
		if d.PowerOnHours != nil {
			pts = append(pts, gauge("smart_power_on_hours", "Hours the drive has been powered on", *d.PowerOnHours, l))
		}
		for name, v := range d.Attributes {
			al := map[string]string{"device": d.Name, "type": d.Type, "model": d.Model, "serial": d.Serial, "attribute": name}
			pts = append(pts, gauge("smart_attribute", "A drive counter that predicts failure (raw value): reallocated, pending and uncorrectable sectors, CRC errors, NVMe wear and media errors", v, al))
		}
	}
	return pts, nil
}
