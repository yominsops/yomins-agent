package integrations

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// maxScrapeSeries bounds what one endpoint may add per push.
const maxScrapeSeries = 5000

// reservedLabels are set by the agent or the server; an endpoint's labels
// with these names are kept as exported_<name>.
var reservedLabels = map[string]bool{"agent_id": true, "hostname": true, "source": true, "target_name": true, "target_type": true,
	"project_id": true, "customer_id": true, "environment": true, "scrape_target": true}

// Scrape reads local Prometheus endpoints (node_exporter, an application's
// /metrics…) and forwards their series with a scrape_target label: any
// software with a Prometheus endpoint is covered without agent changes.
type Scrape struct {
	urls   []string
	client *http.Client
}

// NewScrape creates the integration for the given URLs.
func NewScrape(urls []string) *Scrape {
	return &Scrape{urls: urls, client: &http.Client{Timeout: 5 * time.Second}}
}

func (s *Scrape) Name() string { return "scrape" }

func (s *Scrape) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	for _, u := range s.urls {
		target := u
		if pu, err := url.Parse(u); err == nil {
			target = pu.Host
		}
		got, err := s.scrape(ctx, u, target)
		if err != nil {
			pts = append(pts, status("scrape", StatusError, target),
				gauge("scrape_up", "1 when the endpoint answered with metrics", 0, map[string]string{"scrape_target": target}))
			continue
		}
		pts = append(pts, got...)
		pts = append(pts, status("scrape", StatusOK, target),
			gauge("scrape_up", "1 when the endpoint answered with metrics", 1, map[string]string{"scrape_target": target}))
	}
	return pts, nil
}

func (s *Scrape) scrape(ctx context.Context, u, target string) ([]metrics.MetricPoint, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain;version=0.0.4")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var p expfmt.TextParser
	fams, err := p.TextToMetricFamilies(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(fams))
	for n := range fams {
		names = append(names, n)
	}
	sort.Strings(names)
	var pts []metrics.MetricPoint
	for _, n := range names {
		pts = append(pts, flatten(fams[n], target)...)
		if len(pts) > maxScrapeSeries {
			return pts[:maxScrapeSeries], nil
		}
	}
	return pts, nil
}

// flatten turns a family into plain counters and gauges, the way the
// Prometheus text format spells histograms and summaries.
func flatten(f *dto.MetricFamily, target string) []metrics.MetricPoint {
	var pts []metrics.MetricPoint
	name, help := f.GetName(), f.GetHelp()
	for _, m := range f.GetMetric() {
		labels := map[string]string{"scrape_target": target}
		for _, lp := range m.GetLabel() {
			k := lp.GetName()
			if reservedLabels[k] {
				k = "exported_" + k
			}
			labels[k] = lp.GetValue()
		}
		with := func(k, v string) map[string]string {
			l := make(map[string]string, len(labels)+1)
			for a, b := range labels {
				l[a] = b
			}
			l[k] = v
			return l
		}
		switch f.GetType() {
		case dto.MetricType_COUNTER:
			pts = append(pts, counter(name, help, m.GetCounter().GetValue(), labels))
		case dto.MetricType_GAUGE:
			pts = append(pts, gauge(name, help, m.GetGauge().GetValue(), labels))
		case dto.MetricType_UNTYPED:
			pts = append(pts, gauge(name, help, m.GetUntyped().GetValue(), labels))
		case dto.MetricType_SUMMARY:
			sm := m.GetSummary()
			for _, q := range sm.GetQuantile() {
				pts = append(pts, gauge(name, help, q.GetValue(), with("quantile", strconv.FormatFloat(q.GetQuantile(), 'g', -1, 64))))
			}
			pts = append(pts, counter(name+"_sum", help, sm.GetSampleSum(), labels), counter(name+"_count", help, float64(sm.GetSampleCount()), labels))
		case dto.MetricType_HISTOGRAM:
			h := m.GetHistogram()
			inf := false
			for _, b := range h.GetBucket() {
				le := strconv.FormatFloat(b.GetUpperBound(), 'g', -1, 64)
				if math.IsInf(b.GetUpperBound(), 1) {
					le, inf = "+Inf", true
				}
				pts = append(pts, counter(name+"_bucket", help, float64(b.GetCumulativeCount()), with("le", le)))
			}
			if !inf {
				pts = append(pts, counter(name+"_bucket", help, float64(h.GetSampleCount()), with("le", "+Inf")))
			}
			pts = append(pts, counter(name+"_sum", help, h.GetSampleSum(), labels), counter(name+"_count", help, float64(h.GetSampleCount()), labels))
		}
	}
	return pts
}
