//go:build linux

package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/yominsops/yomins-agent/internal/config"
	"github.com/yominsops/yomins-agent/internal/events"
	"github.com/yominsops/yomins-agent/internal/events/auth"
	"github.com/yominsops/yomins-agent/internal/events/network"
	evtprocess "github.com/yominsops/yomins-agent/internal/events/process"
	"github.com/yominsops/yomins-agent/internal/events/system"
	"github.com/yominsops/yomins-agent/internal/version"
)

// startEventPipeline builds and starts the event collection pipeline in a
// background goroutine. It returns immediately; the pipeline runs until ctx
// is cancelled. This function is a no-op if cfg.DisableEvents is true.
func startEventPipeline(ctx context.Context, cfg *config.Config, hostname string) {
	if cfg.DisableEvents {
		return
	}

	hostIP := resolveHostIP()
	host := events.HostInfo{Hostname: hostname, IP: hostIP}
	agent := events.AgentInfo{Name: "yomins-agent", Version: version.Version}

	var collectors []events.EventCollector

	if !cfg.DisableAuthEvents {
		collectors = append(collectors, auth.NewCollector(auth.Config{
			WtmpPath:    cfg.WtmpPath,
			AuthLogPath: cfg.AuthLogPath,
			StateDir:    cfg.StateDir,
			Host:        host,
			Agent:       agent,
		}))
	}

	if !cfg.DisableProcessEvents {
		collectors = append(collectors, evtprocess.NewCollector(evtprocess.Config{
			PollInterval:       2 * time.Second,
			SuspiciousPatterns: cfg.SuspiciousPatterns,
			Host:               host,
			Agent:              agent,
		}))
	}

	if !cfg.DisableNetworkEvents {
		collectors = append(collectors, network.NewCollector(network.Config{
			Host:  host,
			Agent: agent,
		}))
	}

	if !cfg.DisableSystemEvents {
		collectors = append(collectors, system.NewCollector(system.Config{
			StateDir: cfg.StateDir,
			Host:     host,
			Agent:    agent,
		}))
	}

	if len(collectors) == 0 {
		return
	}

	pipeline := events.NewPipeline(events.PipelineConfig{
		BufferSize: cfg.EventBufferSize,
	}, collectors...)

	go func() {
		if err := pipeline.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("event pipeline exited", "error", err)
		}
	}()
}

// resolveHostIP returns the first non-loopback IPv4 address found on the host.
// Falls back to an empty string if none is found.
func resolveHostIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return ""
}
