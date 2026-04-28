//go:build linux

package network

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/yominsops/yomins-agent/internal/events"
)

// Config holds configuration for the NetworkCollector.
type Config struct {
	PollInterval       time.Duration // default: 5s
	ScanDeltaThreshold int           // minimum connection delta to consider a scan; default: 50
	ScanMultiplier     float64       // alert when count > prev × multiplier; default: 2.0
	Host               events.HostInfo
	Agent              events.AgentInfo
}

// listenerScanner is a function that returns the current LISTEN sockets and
// total connection count. Decoupled from /proc to allow injection in tests.
type listenerScanner func() ([]listenEntry, int, error)

// Collector watches for new listening ports and detects connection count bursts.
type Collector struct {
	cfg        Config
	scanner    listenerScanner
	prevListen map[string]listenEntry // key → entry
	prevTotal  int
}

// NewCollector creates a new NetworkCollector.
func NewCollector(cfg Config) *Collector {
	return newCollectorWithScanner(cfg, scanListeners)
}

// newCollectorWithScanner creates a NetworkCollector with a custom scanner.
// Used in tests to inject fake /proc/net/tcp data without OS interaction.
func newCollectorWithScanner(cfg Config, scanner listenerScanner) *Collector {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.ScanDeltaThreshold <= 0 {
		cfg.ScanDeltaThreshold = 50
	}
	if cfg.ScanMultiplier <= 0 {
		cfg.ScanMultiplier = 2.0
	}
	return &Collector{
		cfg:        cfg,
		scanner:    scanner,
		prevListen: make(map[string]listenEntry),
	}
}

func (c *Collector) Name() string { return "network" }

// Run polls /proc/net/tcp for listening port and connection count changes.
func (c *Collector) Run(ctx context.Context, out chan<- events.Event) error {
	// Build initial baseline — no events for pre-existing listeners.
	listeners, total, err := c.scanner()
	if err != nil {
		slog.Warn("network: /proc/net/tcp unavailable, network events disabled", "error", err)
		return nil
	}
	for _, l := range listeners {
		c.prevListen[l.key()] = l
	}
	c.prevTotal = total

	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			evs := c.poll()
			for _, ev := range evs {
				select {
				case out <- ev:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}

func (c *Collector) poll() []events.Event {
	listeners, total, err := c.scanner()
	if err != nil {
		slog.Warn("network: failed to scan /proc/net/tcp", "error", err)
		return nil
	}

	now := time.Now().UTC()
	var evs []events.Event

	// Detect new listeners.
	currentListen := make(map[string]listenEntry, len(listeners))
	for _, l := range listeners {
		currentListen[l.key()] = l
		if _, known := c.prevListen[l.key()]; !known {
			evs = append(evs, c.makeConnectionOpenEvent(l, now))
			evs = append(evs, c.makeSuspiciousPortEvent(l, now))
		}
	}
	c.prevListen = currentListen

	// Detect connection burst.
	delta := total - c.prevTotal
	if c.prevTotal > 0 &&
		delta >= c.cfg.ScanDeltaThreshold &&
		float64(total) >= float64(c.prevTotal)*c.cfg.ScanMultiplier {
		evs = append(evs, c.makeScanDetectedEvent(c.prevTotal, total, delta, now))
	}
	c.prevTotal = total

	return evs
}

func (c *Collector) makeConnectionOpenEvent(l listenEntry, now time.Time) events.Event {
	return events.Event{
		ID:        uuid.New().String(),
		Timestamp: now,
		Type:      events.EventNetworkConnectionOpen,
		Category:  events.CategorySystemCheck,
		Severity:  events.SeverityInfo,
		Host:      c.cfg.Host,
		Agent:     c.cfg.Agent,
		Network: &events.NetworkDetail{
			LocalIP:   l.LocalIP,
			LocalPort: l.LocalPort,
			Proto:     l.Proto,
		},
		Tags: []string{"network", "listen"},
	}
}

func (c *Collector) makeSuspiciousPortEvent(l listenEntry, now time.Time) events.Event {
	return events.Event{
		ID:         uuid.New().String(),
		Timestamp:  now,
		Type:       events.EventNetworkSuspiciousPort,
		Category:   events.CategoryThreatActivity,
		Severity:   events.SeverityWarning,
		Confidence: events.ConfidenceMedium,
		Host:       c.cfg.Host,
		Agent:      c.cfg.Agent,
		Network: &events.NetworkDetail{
			LocalIP:   l.LocalIP,
			LocalPort: l.LocalPort,
			Proto:     l.Proto,
		},
		Tags: []string{"network", "suspicious_port"},
	}
}

func (c *Collector) makeScanDetectedEvent(prev, current, delta int, now time.Time) events.Event {
	return events.Event{
		ID:        uuid.New().String(),
		Timestamp: now,
		Type:      events.EventNetworkScanDetected,
		Category:  events.CategoryThreatActivity,
		Severity:  events.SeverityCritical,
		Host:      c.cfg.Host,
		Agent:     c.cfg.Agent,
		Context: &events.ContextInfo{
			Reason: "connection_burst",
		},
		Tags: []string{"network", "scan"},
	}
}
