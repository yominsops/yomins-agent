package integrations

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// DefaultPHPFPMPoolGlobs are the pool configurations PHP-FPM packages install.
var DefaultPHPFPMPoolGlobs = []string{"/etc/php/*/fpm/pool.d/*.conf", "/etc/php-fpm.d/*.conf", "/etc/opt/remi/php*/php-fpm.d/*.conf", "/usr/local/etc/php-fpm.d/*.conf"}

// PHPFPM reads every pool's status page over the pool's own socket: busy
// and idle workers, the listen queue, "max children reached" (requests
// waiting for a free worker) and slow requests.
type PHPFPM struct {
	globs []string
	get   func(ctx context.Context, network, address, path, query string) ([]byte, error)
}

// NewPHPFPM creates the integration.
func NewPHPFPM() *PHPFPM { return &PHPFPM{globs: DefaultPHPFPMPoolGlobs, get: fcgiGet} }

func (p *PHPFPM) Name() string { return "php_fpm" }

// fpmPool is one [pool] section: where it listens and its status path.
type fpmPool struct {
	name, listen, status string
}

var reVersion = regexp.MustCompile(`/php/?([0-9.]+)/`)

func (p *PHPFPM) pools() []fpmPool {
	var out []fpmPool
	for _, g := range p.globs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			version := ""
			if m := reVersion.FindStringSubmatch(f); m != nil {
				version = m[1] + "/"
			}
			var cur *fpmPool
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || line[0] == ';' || line[0] == '#' {
					continue
				}
				if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
					out = append(out, fpmPool{name: version + strings.Trim(line, "[]")})
					cur = &out[len(out)-1]
					continue
				}
				k, v, ok := strings.Cut(line, "=")
				if !ok || cur == nil {
					continue
				}
				switch strings.TrimSpace(k) {
				case "listen":
					cur.listen = strings.TrimSpace(v)
				case "pm.status_path":
					cur.status = strings.TrimSpace(v)
				}
			}
		}
	}
	return out
}

type fpmStatus struct {
	AcceptedConn       float64 `json:"accepted conn"`
	ListenQueue        float64 `json:"listen queue"`
	MaxListenQueue     float64 `json:"max listen queue"`
	ListenQueueLen     float64 `json:"listen queue len"`
	IdleProcesses      float64 `json:"idle processes"`
	ActiveProcesses    float64 `json:"active processes"`
	TotalProcesses     float64 `json:"total processes"`
	MaxActiveProcesses float64 `json:"max active processes"`
	MaxChildrenReached float64 `json:"max children reached"`
	SlowRequests       float64 `json:"slow requests"`
}

func (p *PHPFPM) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	for _, pool := range p.pools() {
		if pool.status == "" || pool.listen == "" {
			pts = append(pts, status("php_fpm", StatusUnconfigured, pool.name))
			continue
		}
		network, address := "unix", pool.listen
		if !strings.HasPrefix(address, "/") {
			network = "tcp"
			if !strings.Contains(address, ":") {
				address = "127.0.0.1:" + address
			}
		}
		body, err := p.get(ctx, network, address, pool.status, "json")
		var st fpmStatus
		if err == nil {
			err = json.Unmarshal(body, &st)
		}
		if err != nil {
			pts = append(pts, status("php_fpm", StatusError, pool.name))
			continue
		}
		l := map[string]string{"pool": pool.name}
		pts = append(pts,
			status("php_fpm", StatusOK, pool.name),
			counter("phpfpm_accepted_connections_total", "Requests the pool accepted", st.AcceptedConn, l),
			gauge("phpfpm_listen_queue", "Requests waiting for a free worker", st.ListenQueue, l),
			gauge("phpfpm_listen_queue_max", "Most requests ever waiting since the pool started", st.MaxListenQueue, l),
			gauge("phpfpm_processes", "Workers by state", st.ActiveProcesses, map[string]string{"pool": pool.name, "state": "active"}),
			gauge("phpfpm_processes", "Workers by state", st.IdleProcesses, map[string]string{"pool": pool.name, "state": "idle"}),
			gauge("phpfpm_processes_max_active", "Most workers ever busy at once", st.MaxActiveProcesses, l),
			counter("phpfpm_max_children_reached_total", "Times every worker was busy (pm.max_children reached)", st.MaxChildrenReached, l),
			counter("phpfpm_slow_requests_total", "Requests slower than request_slowlog_timeout", st.SlowRequests, l),
		)
	}
	return pts, nil
}
