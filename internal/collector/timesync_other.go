//go:build !linux

package collector

import (
	"context"
	"errors"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// TimeSyncCollector is Linux-only.
type TimeSyncCollector struct{}

// NewTimeSyncCollector creates the collector.
func NewTimeSyncCollector() *TimeSyncCollector { return &TimeSyncCollector{} }

func (c *TimeSyncCollector) Name() string { return "timesync" }

func (c *TimeSyncCollector) Collect(context.Context) ([]metrics.MetricPoint, error) {
	return nil, errors.New("not supported on this platform")
}
