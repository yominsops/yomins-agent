package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yominsops/yomins-agent/internal/config"
)

func ptr[T any](v T) *T { return &v }

func sample() Config {
	return Config{
		Interval:           ptr("30s"),
		DisabledCollectors: []string{"process_groups"},
		Logs:               &LogsConfig{Enabled: ptr(true), Paths: []string{"/srv/app/*.log"}, Exclude: []string{"/var/log/nginx/prom_*"}, Redact: []string{`x-\d+`}},
		Integrations:       &IntegrationsConfig{Enabled: ptr(false), NginxStatusURL: ptr("http://127.0.0.1:8099/nginx_status"), ScrapeURLs: []string{"http://127.0.0.1:9100/metrics"}},
		Events:             &EventsConfig{Process: ptr(false), ProcessLifecycle: ptr(true)},
	}
}

func TestApply_Full(t *testing.T) {
	cfg := &config.Config{Interval: time.Minute, Logs: "off", LogPaths: []string{"/local/*.log"}}
	Apply(cfg, sample(), ModeFull)
	if cfg.Interval != 30*time.Second || cfg.Logs != "auto" || len(cfg.DisabledCollectors) != 1 {
		t.Errorf("%+v", cfg)
	}
	if len(cfg.LogPaths) != 2 || cfg.LogPaths[0] != "/local/*.log" {
		t.Errorf("local paths are kept and extended: %v", cfg.LogPaths)
	}
	if !cfg.DisableIntegrations || cfg.NginxStatusURL == "" || len(cfg.ScrapeURLs) != 1 {
		t.Errorf("integrations: %+v", cfg)
	}
	if !cfg.DisableProcessEvents || !cfg.MonitorProcessLifecycle || cfg.DisableEvents {
		t.Errorf("events: %+v", cfg)
	}
	if len(cfg.LogRedact) != 1 || len(cfg.LogExclude) != 1 {
		t.Error("redact and exclude")
	}
}

func TestApply_LimitedSkipsWhatChoosesWhatIsRead(t *testing.T) {
	cfg := &config.Config{}
	Apply(cfg, sample(), ModeLimited)
	if len(cfg.LogPaths) != 0 || len(cfg.ScrapeURLs) != 0 || cfg.NginxStatusURL != "" {
		t.Errorf("limited mode: %+v", cfg)
	}
	if cfg.Logs != "auto" || len(cfg.LogExclude) != 1 {
		t.Error("switches and narrowing still apply")
	}
}

func TestApply_Off(t *testing.T) {
	cfg := &config.Config{Interval: time.Minute}
	Apply(cfg, sample(), ModeOff)
	if cfg.Interval != time.Minute || cfg.Logs != "" {
		t.Errorf("off: %+v", cfg)
	}
}

func TestApply_LocalNginxURLWins(t *testing.T) {
	cfg := &config.Config{NginxStatusURL: "http://local/status"}
	Apply(cfg, sample(), ModeFull)
	if cfg.NginxStatusURL != "http://local/status" {
		t.Error("the host's own setting is kept")
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(sample()); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{Interval: ptr("1s")},
		{Logs: &LogsConfig{Redact: []string{"("}}},
		{Logs: &LogsConfig{Paths: []string{"relative/*.log"}}},
	} {
		if Validate(c) == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	if _, ok := Load(dir); ok {
		t.Fatal("nothing stored yet")
	}
	if err := Save(dir, Stored{Version: "v1", Config: sample()}); err != nil {
		t.Fatal(err)
	}
	s, ok := Load(dir)
	if !ok || s.Version != "v1" || *s.Config.Interval != "30s" {
		t.Errorf("%+v", s)
	}
}

func TestFetcher(t *testing.T) {
	var answer atomic.Value
	answer.Store(Stored{Version: "v2", Config: Config{Interval: ptr("30s")}})
	var lastETag, lastHost atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastETag.Store(r.Header.Get("If-None-Match"))
		lastHost.Store(r.Header.Get("X-Yomins-Hostname"))
		s := answer.Load().(Stored)
		if r.Header.Get("If-None-Match") == `"`+s.Version+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(s)
	}))
	defer srv.Close()

	dir := t.TempDir()
	f := &Fetcher{Server: srv.URL, Token: "t", Hostname: "web-1", StateDir: dir, Mode: ModeFull, Current: "v1", Client: srv.Client()}
	s, changed := f.check(context.Background())
	if !changed || s.Version != "v2" || lastETag.Load() != `"v1"` || lastHost.Load() != "web-1" {
		t.Fatalf("new version: %+v %v", s, changed)
	}
	if stored, ok := Load(dir); !ok || stored.Version != "v2" {
		t.Error("saved before the restart")
	}

	f.Current = "v2"
	if _, changed := f.check(context.Background()); changed {
		t.Error("304: unchanged")
	}

	answer.Store(Stored{Version: "v3", Config: Config{Interval: ptr("1s")}})
	if _, changed := f.check(context.Background()); changed {
		t.Error("an invalid configuration is refused")
	}
	if stored, _ := Load(dir); stored.Version != "v2" {
		t.Error("the refused one is not saved")
	}
}

func TestFetcherRun_RestartsAfterMinUptime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Stored{Version: "v9", Config: Config{}})
	}))
	defer srv.Close()
	restarted := make(chan string, 1)
	f := &Fetcher{Server: srv.URL, Token: "t", StateDir: t.TempDir(), Mode: ModeFull, Started: time.Now(), MinUptime: 50 * time.Millisecond,
		Restart: func(v string) { restarted <- v }, Client: srv.Client()}
	start := time.Now()
	go f.Run(context.Background())
	select {
	case v := <-restarted:
		if v != "v9" || time.Since(start) < 40*time.Millisecond {
			t.Errorf("restart %q after %v", v, time.Since(start))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no restart")
	}
}

func TestInfoCollector(t *testing.T) {
	pts, _ := InfoCollector{Version: "abc", Mode: ModeFull}.Collect(context.Background())
	if pts[0].Labels["config_source"] != "remote" || pts[0].Labels["version"] != "abc" {
		t.Errorf("%v", pts)
	}
	pts, _ = InfoCollector{Mode: ModeFull}.Collect(context.Background())
	if pts[0].Labels["config_source"] != "local" {
		t.Error("no remote version: local")
	}
}
