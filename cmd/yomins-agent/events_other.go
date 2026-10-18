//go:build !linux

package main

import (
	"context"
	"log/slog"

	"github.com/yominsops/yomins-agent/internal/config"
	"github.com/yominsops/yomins-agent/internal/transport"
)

// startEventPipeline is a no-op on non-Linux platforms.
// Event collection requires Linux kernel interfaces (/proc, /dev/kmsg, wtmp).
func startEventPipeline(ctx context.Context, cfg *config.Config, hostname string, _ *transport.Session) {
	_ = ctx
	if !cfg.DisableEvents {
		slog.Warn("event collection is not supported on this platform (Linux only)")
	}
}
