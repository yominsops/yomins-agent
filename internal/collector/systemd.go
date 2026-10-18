package collector

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// SystemdCollector reports failed units, whether the system is degraded,
// and for the services that usually matter (web, PHP, databases, mail,
// Docker, SSH, cron) whether they run and how often systemd restarted them:
// a service crash-looping under Restart=always looks "active" otherwise.
type SystemdCollector struct {
	run runner
}

// NewSystemdCollector creates the collector.
func NewSystemdCollector() *SystemdCollector { return &SystemdCollector{run: execRunner} }

func (c *SystemdCollector) Name() string { return "systemd" }

// trackedServices are glob patterns of services whose state is reported.
var trackedServices = []string{
	"nginx.service", "apache2.service", "httpd.service", "caddy.service", "haproxy.service", "varnish.service",
	"php*-fpm.service", "php-fpm.service",
	"mysql.service", "mysqld.service", "mariadb.service", "postgresql*.service", "redis*.service", "mongod.service",
	"memcached.service", "elasticsearch.service", "rabbitmq-server.service",
	"exim4.service", "postfix.service", "dovecot.service", "spamd.service", "spamassassin.service", "clamav-daemon.service",
	"docker.service", "containerd.service", "ssh.service", "sshd.service", "cron.service", "crond.service",
	"vsftpd.service", "proftpd.service", "pure-ftpd.service", "fail2ban.service", "named.service", "bind9.service",
}

const maxFailedUnits = 50

func (c *SystemdCollector) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	out, err := c.run(ctx, "systemctl", "list-units", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return nil, fmt.Errorf("systemctl: %w", err)
	}
	var pts []metrics.MetricPoint
	var tracked []string
	failed := 0
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		unit, active := f[0], f[2]
		if active == "failed" {
			failed++
			if failed <= maxFailedUnits {
				pts = append(pts, gauge("systemd_unit_failed", "1 for every unit in the failed state", 1, map[string]string{"unit": unit}))
			}
		}
		// Installed but stopped on purpose (apache2 next to nginx) is not
		// "down"; failed units are counted above.
		if f[1] == "loaded" && active != "inactive" && matchesAny(unit, trackedServices) {
			tracked = append(tracked, unit)
		}
	}
	pts = append(pts, gauge("systemd_units_failed", "Units in the failed state", float64(failed), nil))

	if state, err := c.run(ctx, "systemctl", "is-system-running"); len(state) > 0 || err == nil {
		s := strings.TrimSpace(string(state))
		degraded := 0.0
		if s == "degraded" || s == "maintenance" {
			degraded = 1
		}
		pts = append(pts, gauge("systemd_system_degraded", "1 when systemd reports the system degraded (a unit failed)", degraded, nil))
	}

	if len(tracked) > 0 {
		args := append([]string{"show", "--no-pager", "-p", "Id,ActiveState,SubState,NRestarts"}, tracked...)
		if out, err := c.run(ctx, "systemctl", args...); err == nil {
			pts = append(pts, parseShow(string(out))...)
		}
	}
	return pts, nil
}

// parseShow reads `systemctl show` output: blocks of key=value separated by blank lines.
func parseShow(out string) []metrics.MetricPoint {
	var pts []metrics.MetricPoint
	for _, block := range strings.Split(out, "\n\n") {
		kv := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				kv[k] = v
			}
		}
		id := kv["Id"]
		if id == "" {
			continue
		}
		l := map[string]string{"unit": id}
		up := 0.0
		if kv["ActiveState"] == "active" {
			up = 1
		}
		pts = append(pts, gauge("systemd_service_active", "1 when the service is active", up, map[string]string{"unit": id, "state": kv["SubState"]}))
		if n, err := strconv.ParseFloat(kv["NRestarts"], 64); err == nil {
			pts = append(pts, counter("systemd_service_restarts_total", "Times systemd restarted the service since it was started", n, l))
		}
	}
	return pts
}

func matchesAny(name string, globs []string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}
