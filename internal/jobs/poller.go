package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/yominsops/yomins-agent/internal/transport"
)

// Poller is the agent's side: it fetches this server's jobs into the inbox and
// posts back the results the root runner left in the outbox. It never runs
// anything itself.
type Poller struct {
	Server   string // the push base URL (…/v1/push)
	Token    string
	Hostname string
	AgentID  string
	Paths    Paths
	Interval time.Duration // default 60s
	Session  *transport.Session
	Client   *http.Client
}

// Enabled tells whether this server takes jobs: the job key was installed
// (yomins-agent install --maintenance).
func Enabled(p Paths) bool {
	_, err := os.Stat(p.PublicKey)
	return err == nil
}

// Run polls until ctx is done.
func (p *Poller) Run(ctx context.Context) {
	if p.Interval <= 0 {
		p.Interval = time.Minute
	}
	if p.Client == nil {
		p.Client = &http.Client{Timeout: 20 * time.Second}
	}
	for _, d := range []string{p.Paths.inbox(), p.Paths.outbox()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			slog.Warn("jobs: cannot create directory", "dir", d, "error", err)
			return
		}
	}
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		p.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick posts the results waiting in the outbox, then fetches new jobs.
func (p *Poller) Tick(ctx context.Context) {
	if p.Session != nil && p.Session.Paused() {
		return
	}
	p.postResults(ctx)
	p.fetch(ctx)
}

func (p *Poller) request(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.Server+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("X-Yomins-Hostname", p.Hostname)
	req.Header.Set("X-Yomins-Agent-Id", p.AgentID)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return p.Client.Do(req)
}

func (p *Poller) fetch(ctx context.Context) {
	resp, err := p.request(ctx, http.MethodGet, "/jobs", nil)
	if err != nil {
		slog.Debug("jobs: fetch failed", "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 404: an ingest server without jobs.
		return
	}
	var got struct {
		Jobs []Inbox `json:"jobs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&got); err != nil {
		slog.Warn("jobs: unreadable answer", "error", err)
		return
	}
	for _, j := range got.Jobs {
		if !ValidID(j.ID) || p.known(j.ID) {
			continue
		}
		b, _ := json.Marshal(j)
		if err := writeAtomic(p.Paths.inbox(), j.ID+".json", b); err != nil {
			slog.Warn("jobs: cannot queue", "job_id", j.ID, "error", err)
			continue
		}
		slog.Info("jobs: received", "job_id", j.ID)
	}
}

// known: the job waits in the inbox, or its result in the outbox.
func (p *Poller) known(id string) bool {
	for _, d := range []string{p.Paths.inbox(), p.Paths.outbox()} {
		if _, err := os.Lstat(filepath.Join(d, id+".json")); err == nil {
			return true
		}
	}
	return false
}

func (p *Poller) postResults(ctx context.Context) {
	files, _ := filepath.Glob(filepath.Join(p.Paths.outbox(), "*.json"))
	for _, f := range files {
		b, err := readLimited(f, MaxOutput+4096)
		var r Result
		if err != nil || json.Unmarshal(b, &r) != nil || !ValidID(r.ID) {
			os.Remove(f)
			continue
		}
		resp, err := p.request(ctx, http.MethodPost, "/jobs/result", b)
		if err != nil {
			return // try again next tick
		}
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound:
			// Taken, or the server does not know the job: either way done here.
			os.Remove(f)
			slog.Info("jobs: result sent", "job_id", r.ID, "ok", r.OK, "status", resp.StatusCode)
		default:
			return
		}
	}
}

func writeAtomic(dir, name string, b []byte) error {
	tmp, err := os.CreateTemp(dir, ".job-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}
