package jobs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Paths of the job files. Inbox and outbox live in the agent's state directory
// (the agent writes the inbox, root the outbox); Seen is root's own.
type Paths struct {
	StateDir  string // /var/lib/yomins/agent: agent_id, jobs/inbox, jobs/outbox
	PublicKey string // /etc/yomins-agent/jobs.pub
	Seen      string // /var/lib/yomins/jobs-seen: one file per job ever taken
	Yopatch   string // /usr/local/sbin/yopatch
}

// DefaultPaths are the installed locations.
var DefaultPaths = Paths{
	StateDir:  "/var/lib/yomins/agent",
	PublicKey: "/etc/yomins-agent/jobs.pub",
	Seen:      "/var/lib/yomins/jobs-seen",
	Yopatch:   "/usr/local/sbin/yopatch",
}

func (p Paths) inbox() string  { return filepath.Join(p.StateDir, "jobs", "inbox") }
func (p Paths) outbox() string { return filepath.Join(p.StateDir, "jobs", "outbox") }

// Inbox is a fetched job as the agent saves it.
type Inbox struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

// Result is what the runner leaves for the agent to post.
type Result struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Exit   int    `json:"exit"`
	Output string `json:"output"`
}

// MaxOutput is how much of yopatch's output is kept.
const MaxOutput = 64 << 10

// Runner runs the jobs in the inbox (as root).
type Runner struct {
	Paths   Paths
	Timeout time.Duration // per job; default 45m
	Now     func() time.Time
	// Exec runs yopatch; tests replace it.
	Exec func(ctx context.Context, path string, env []string, args ...string) (stdout []byte, exit int, err error)
}

func execYopatch(ctx context.Context, path string, env []string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.Bytes(), exit.ExitCode(), nil
	}
	if err != nil {
		return out.Bytes(), -1, err
	}
	return out.Bytes(), 0, nil
}

// RunAll takes every job in the inbox, oldest first, and leaves a result in the
// outbox for each, refused ones included (so the automation learns why).
func (r *Runner) RunAll(ctx context.Context) error {
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Exec == nil {
		r.Exec = execYopatch
	}
	if r.Timeout <= 0 {
		r.Timeout = 45 * time.Minute
	}
	keyPEM, err := os.ReadFile(r.Paths.PublicKey)
	if err != nil {
		return fmt.Errorf("job key: %w", err)
	}
	key, err := ParsePublicKey(keyPEM)
	if err != nil {
		return fmt.Errorf("job key: %w", err)
	}
	idBytes, err := os.ReadFile(filepath.Join(r.Paths.StateDir, "agent_id"))
	if err != nil {
		return fmt.Errorf("agent id: %w", err)
	}
	agentID := strings.TrimSpace(string(idBytes))
	if err := os.MkdirAll(r.Paths.Seen, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(r.Paths.outbox(), 0o755); err != nil {
		return err
	}
	files, _ := filepath.Glob(filepath.Join(r.Paths.inbox(), "*.json"))
	for _, f := range files {
		r.one(ctx, f, key, agentID)
	}
	r.forget()
	return nil
}

// one takes one inbox file: it is removed whatever happens, and a result is left.
func (r *Runner) one(ctx context.Context, file string, key *ecdsa.PublicKey, agentID string) {
	defer os.Remove(file)
	b, err := readLimited(file, 16<<10)
	var in Inbox
	if err != nil || json.Unmarshal(b, &in) != nil || !ValidID(in.ID) {
		slog.Warn("job: unreadable inbox file, dropped", "file", file)
		return
	}
	res := Result{ID: in.ID}
	c, err := Verify(in.Token, key, agentID, r.Now())
	switch {
	case err != nil:
		res.Output = refusal(err.Error())
	case c.ID != in.ID:
		res.Output = refusal("the token is another job's")
	case r.seen(c.ID):
		// A replay, or a job whose result was lost: never run it again, but answer, or
		// the agent would fetch it again until it expires.
		slog.Info("job: already taken, not run again", "job_id", c.ID)
		res.Output = refusal("already taken: a job runs once")
	default:
		r.markSeen(c.ID)
		res = r.run(ctx, c)
	}
	if res.Output != "" && !res.OK {
		slog.Warn("job: not done", "job_id", in.ID, "output", res.Output)
	}
	r.leave(res)
}

func (r *Runner) run(ctx context.Context, c Claims) Result {
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	slog.Info("job: running", "job_id", c.ID, "verb", c.Verb, "args", c.Args)
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "YOPATCH_CALLER=job:" + c.ID}
	out, exit, err := r.Exec(ctx, r.Paths.Yopatch, env, append([]string{c.Verb}, c.Args...)...)
	res := Result{ID: c.ID, Exit: exit, Output: lastLine(out)}
	switch {
	case err != nil:
		res.Output = refusal("yopatch did not run: " + err.Error())
	case ctx.Err() != nil:
		res.Output = refusal("yopatch timed out")
	default:
		res.OK = exit == 0
	}
	return res
}

// leave writes the result for the agent, atomically.
func (r *Runner) leave(res Result) {
	b, _ := json.Marshal(res)
	tmp, err := os.CreateTemp(r.Paths.outbox(), ".result-*")
	if err != nil {
		slog.Error("job: result not written", "job_id", res.ID, "error", err)
		return
	}
	_, werr := tmp.Write(b)
	_ = tmp.Chmod(0o644)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp.Name())
		return
	}
	if err := os.Rename(tmp.Name(), filepath.Join(r.Paths.outbox(), res.ID+".json")); err != nil {
		os.Remove(tmp.Name())
	}
}

func (r *Runner) seen(id string) bool {
	_, err := os.Stat(filepath.Join(r.Paths.Seen, id))
	return err == nil
}

func (r *Runner) markSeen(id string) {
	_ = os.WriteFile(filepath.Join(r.Paths.Seen, id), nil, 0o600)
}

// forget drops seen marks older than any token can live (24h) and a margin.
func (r *Runner) forget() {
	entries, _ := os.ReadDir(r.Paths.Seen)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && r.Now().Sub(info.ModTime()) > 72*time.Hour {
			os.Remove(filepath.Join(r.Paths.Seen, e.Name()))
		}
	}
}

func refusal(msg string) string {
	b, _ := json.Marshal(map[string]interface{}{"ok": false, "error": msg})
	return string(b)
}

// lastLine is yopatch's answer: its last non-empty line, at most MaxOutput bytes.
func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	s := strings.TrimSpace(lines[len(lines)-1])
	if len(s) > MaxOutput {
		s = s[:MaxOutput]
	}
	return s
}

// readLimited reads a small regular file the agent wrote, never through a symlink
// (the agent could point one at a root-only file).
func readLimited(path string, max int64) ([]byte, error) {
	if li, err := os.Lstat(path); err != nil || !li.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > max {
		return nil, errors.New("not a small regular file")
	}
	b := make([]byte, info.Size())
	_, err = f.Read(b)
	return b, err
}
