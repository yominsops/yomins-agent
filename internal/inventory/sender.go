package inventory

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/yominsops/yomins-agent/internal/transport"
)

// Sender is the agent's side: it sends the report the root timer wrote, when
// it changed and at least once a day.
type Sender struct {
	Server   string // the push base URL (…/v1/push)
	Token    string
	Hostname string
	AgentID  string
	Path     string // the report (DefaultReportPath)
	StateDir string // where the last send is remembered
	Session  *transport.Session
	Client   *http.Client
	// Interval is how often the report is looked at (default 15 minutes),
	// Resend how often an unchanged one is sent again (default 24 hours).
	Interval time.Duration
	Resend   time.Duration
	now      func() time.Time
	// notBefore holds sends back after the server said it has no
	// inventory endpoint.
	notBefore time.Time
}

// sentState is what was sent last.
type sentState struct {
	Hash   string    `json:"hash"`
	SentAt time.Time `json:"sent_at"`
}

func (s *Sender) statePath() string { return filepath.Join(s.StateDir, "inventory.sent") }

// Run checks the report until ctx is done.
func (s *Sender) Run(ctx context.Context) {
	if s.Interval <= 0 {
		s.Interval = 15 * time.Minute
	}
	// The first look a little after start: the agent's first pushes first.
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
	}
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		s.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick sends the report if it is due; it reports whether it did.
func (s *Sender) Tick(ctx context.Context) bool {
	if s.now == nil {
		s.now = time.Now
	}
	if s.Resend <= 0 {
		s.Resend = 24 * time.Hour
	}
	if s.Client == nil {
		s.Client = &http.Client{Timeout: 60 * time.Second}
	}
	if s.Session != nil && s.Session.Paused() {
		return false
	}
	if s.now().Before(s.notBefore) {
		return false
	}
	_, body, err := Read(s.Path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Debug("inventory: report unreadable", "error", err)
		}
		return false
	}
	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	var last sentState
	if b, err := os.ReadFile(s.statePath()); err == nil {
		_ = json.Unmarshal(b, &last)
	}
	if last.Hash == hash && s.now().Sub(last.SentAt) < s.Resend {
		return false
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(body)
	_ = w.Close()
	size := gz.Len() // the request reads the buffer empty
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Server+"/inventory", &gz)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-Yomins-Hostname", s.Hostname)
	req.Header.Set("X-Yomins-Agent-Id", s.AgentID)
	resp, err := s.Client.Do(req)
	if err != nil {
		slog.Debug("inventory: send failed", "error", err)
		return false
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		b, _ := json.Marshal(sentState{Hash: hash, SentAt: s.now().UTC()})
		_ = os.WriteFile(s.statePath(), b, 0o600)
		slog.Info("inventory: sent", "bytes", size)
		return true
	case resp.StatusCode == http.StatusNotFound:
		// An ingest server without inventory: ask again in a few hours.
		s.notBefore = s.now().Add(6 * time.Hour)
	default:
		slog.Warn("inventory: server refused the report", "status", resp.StatusCode)
	}
	return false
}
