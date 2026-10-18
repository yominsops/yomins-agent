package integrations

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// DefaultNginxStatusURLs are tried in turn until one answers like stub_status.
// 127.0.0.1:8099 is the status server the yomins setup guide recommends for
// hosts whose nginx listens on public addresses only.
var DefaultNginxStatusURLs = []string{
	"http://127.0.0.1:8099/nginx_status",
	"http://127.0.0.1/nginx_status",
	"http://127.0.0.1/stub_status",
	"http://127.0.0.1:8080/nginx_status",
	"http://127.0.0.1/basic_status",
}

// Nginx reads nginx's stub_status page: connections and requests.
type Nginx struct {
	urls      []string
	found     string
	client    *http.Client
	installed func() bool
}

// NewNginx creates the integration. url, when set, is the only one tried.
func NewNginx(url string) *Nginx {
	urls := DefaultNginxStatusURLs
	if url != "" {
		urls = []string{url}
	}
	return &Nginx{urls: urls, client: &http.Client{Timeout: 3 * time.Second}, installed: func() bool {
		_, err := exec.LookPath("nginx")
		return err == nil
	}}
}

func (n *Nginx) Name() string { return "nginx" }

var reStub = regexp.MustCompile(`(?s)Active connections:\s*(\d+).*?(\d+)\s+(\d+)\s+(\d+).*?Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)`)

func (n *Nginx) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	if !n.installed() {
		return nil, nil
	}
	urls := n.urls
	if n.found != "" {
		urls = []string{n.found}
	}
	for _, u := range urls {
		pts, err := n.read(ctx, u)
		if err == nil {
			n.found = u
			return append(pts, status("nginx", StatusOK, "")), nil
		}
	}
	if n.found != "" {
		return []metrics.MetricPoint{status("nginx", StatusError, "")}, nil
	}
	return []metrics.MetricPoint{status("nginx", StatusUnconfigured, "")}, nil
}

func (n *Nginx) read(ctx context.Context, url string) ([]metrics.MetricPoint, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	m := reStub.FindStringSubmatch(string(b))
	if resp.StatusCode != http.StatusOK || m == nil {
		return nil, fmt.Errorf("not a stub_status page")
	}
	v := func(i int) float64 { f, _ := strconv.ParseFloat(m[i], 64); return f }
	return []metrics.MetricPoint{
		gauge("nginx_connections_active", "Open client connections", v(1), nil),
		counter("nginx_connections_accepted_total", "Accepted client connections", v(2), nil),
		counter("nginx_connections_handled_total", "Handled client connections (less than accepted when a limit is hit)", v(3), nil),
		counter("nginx_requests_total", "Client requests", v(4), nil),
		gauge("nginx_connections", "Connections by state", v(5), map[string]string{"state": "reading"}),
		gauge("nginx_connections", "Connections by state", v(6), map[string]string{"state": "writing"}),
		gauge("nginx_connections", "Connections by state", v(7), map[string]string{"state": "waiting"}),
	}, nil
}
