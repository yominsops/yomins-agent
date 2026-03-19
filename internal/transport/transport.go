package transport

import (
	"context"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// Transport is responsible for delivering a MetricSet to a remote endpoint.
// Push must be safe to call concurrently. Retries are handled internally
// by the implementation; the caller treats each call as a single attempt.
type Transport interface {
	Push(ctx context.Context, ms metrics.MetricSet) error
}
