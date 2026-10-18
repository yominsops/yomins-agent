//go:build linux

package collector

import (
	"context"

	"golang.org/x/sys/unix"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// TimeSyncCollector reports whether the kernel clock is synchronised (by
// chrony, ntpd or systemd-timesyncd) and its estimated error. A drifting
// clock breaks TLS, cron, token expiry and log ordering.
type TimeSyncCollector struct{}

// NewTimeSyncCollector creates the collector.
func NewTimeSyncCollector() *TimeSyncCollector { return &TimeSyncCollector{} }

func (c *TimeSyncCollector) Name() string { return "timesync" }

func (c *TimeSyncCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	var tx unix.Timex // Modes 0: read only
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return nil, err
	}
	synced := 1.0
	if state == unix.TIME_ERROR || tx.Status&unix.STA_UNSYNC != 0 {
		synced = 0
	}
	// Offset is in µs, or ns when STA_NANO is set; esterror is always µs.
	offset := float64(tx.Offset) / 1e6
	if tx.Status&unix.STA_NANO != 0 {
		offset = float64(tx.Offset) / 1e9
	}
	return []metrics.MetricPoint{
		gauge("time_synced", "1 when the clock is synchronised to a time source", synced, nil),
		gauge("time_offset_seconds", "Offset of the clock from its time source", offset, nil),
		gauge("time_estimated_error_seconds", "Estimated error of the clock", float64(tx.Esterror)/1e6, nil),
	}, nil
}
