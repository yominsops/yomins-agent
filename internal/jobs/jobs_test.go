package jobs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const agentID = "71e60f64-0fbf-4bd3-b0d7-6943c2a6f094"

func newKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// sign makes a JWT the way n8n's JWT node does (ES256, JOSE r||s signature).
func sign(t *testing.T, k *ecdsa.PrivateKey, alg string, claims map[string]interface{}) string {
	t.Helper()
	enc := func(v interface{}) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]string{"alg": alg, "typ": "JWT"}) + "." + enc(claims)
	d := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func claims(id, verb string, args []string, exp time.Time) map[string]interface{} {
	return map[string]interface{}{"jti": id, "sub": agentID, "exp": exp.Unix(), "verb": verb, "args": args}
}

func TestVerify(t *testing.T) {
	k, pub := newKey(t)
	key, err := ParsePublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := newKey(t)
	now := time.Now()
	good := sign(t, k, "ES256", claims("job-00000001", "restart", []string{"nginx.service"}, now.Add(time.Hour)))
	c, err := Verify(good, key, agentID, now)
	if err != nil || c.Verb != "restart" || c.Args[0] != "nginx.service" || c.ID != "job-00000001" {
		t.Fatalf("%+v %v", c, err)
	}
	for name, tc := range map[string]struct {
		token string
		want  error
	}{
		"another key":     {sign(t, other, "ES256", claims("job-00000001", "plan", nil, now.Add(time.Hour))), ErrSignature},
		"alg none":        {strings.Replace(good, strings.Split(good, ".")[0], base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)), 1), ErrSignature},
		"tampered claims": {strings.Split(good, ".")[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"job-00000001","sub":"`+agentID+`","exp":9999999999,"verb":"reboot"}`)) + "." + strings.Split(good, ".")[2], ErrSignature},
		"two parts":       {"a.b", ErrMalformed},
		"unknown verb":    {sign(t, k, "ES256", claims("job-00000001", "shell", nil, now.Add(time.Hour))), ErrClaims},
		"shell argument":  {sign(t, k, "ES256", claims("job-00000001", "restart", []string{"$(id)"}, now.Add(time.Hour))), ErrClaims},
		"expired":         {sign(t, k, "ES256", claims("job-00000001", "plan", nil, now.Add(-time.Minute))), ErrExpired},
		"another agent":   {sign(t, k, "ES256", map[string]interface{}{"jti": "job-00000001", "sub": "aaaaaaaa-other", "exp": now.Add(time.Hour).Unix(), "verb": "plan"}), ErrAgent},
	} {
		if _, err := Verify(tc.token, key, agentID, now); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if _, err := ParsePublicKey([]byte("nope")); err == nil {
		t.Error("garbage key accepted")
	}
}

type ran struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *ran) exec(_ context.Context, path string, env []string, args ...string) ([]byte, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, args)
	if args[0] == "security" {
		return []byte("progress line\n{\"ok\":false,\"verb\":\"security\"}\n"), 1, nil
	}
	return []byte(`{"ok":true,"verb":"` + args[0] + `"}` + "\n"), 0, nil
}

func setup(t *testing.T) (Paths, *ecdsa.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	k, pub := newKey(t)
	p := Paths{StateDir: filepath.Join(dir, "state"), PublicKey: filepath.Join(dir, "jobs.pub"), Seen: filepath.Join(dir, "seen"), Yopatch: "/usr/local/sbin/yopatch"}
	for _, d := range []string{p.inbox(), p.outbox()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p.PublicKey, pub, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.StateDir, "agent_id"), []byte(agentID+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, k
}

func drop(t *testing.T, p Paths, id, token string) {
	t.Helper()
	b, _ := json.Marshal(Inbox{ID: id, Token: token})
	if err := os.WriteFile(filepath.Join(p.inbox(), id+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func result(t *testing.T, p Paths, id string) Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(p.outbox(), id+".json"))
	if err != nil {
		t.Fatalf("no result for %s: %v", id, err)
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRunner(t *testing.T) {
	p, k := setup(t)
	now := time.Now()
	drop(t, p, "job-00000001", sign(t, k, "ES256", claims("job-00000001", "restart", []string{"nginx.service"}, now.Add(time.Hour))))
	drop(t, p, "job-00000002", sign(t, k, "ES256", claims("job-00000002", "security", nil, now.Add(time.Hour))))
	drop(t, p, "job-00000003", "not.a.token")
	drop(t, p, "job-00000004", sign(t, k, "ES256", claims("job-00000009", "reboot", nil, now.Add(time.Hour)))) // another job's token
	// A symlink the agent planted at a root-only file is not read.
	secret := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secret, []byte(`{"id":"job-00000005","token":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(p.inbox(), "job-00000005.json")); err != nil {
		t.Fatal(err)
	}

	x := &ran{}
	r := &Runner{Paths: p, Exec: x.exec, Now: func() time.Time { return now }}
	if err := r.RunAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.calls) != 2 || strings.Join(x.calls[0], " ") != "restart nginx.service" || x.calls[1][0] != "security" {
		t.Fatalf("ran %v", x.calls)
	}
	if res := result(t, p, "job-00000001"); !res.OK || res.Exit != 0 || !strings.Contains(res.Output, `"verb":"restart"`) {
		t.Errorf("restart: %+v", res)
	}
	if res := result(t, p, "job-00000002"); res.OK || res.Exit != 1 || res.Output != `{"ok":false,"verb":"security"}` {
		t.Errorf("security: %+v (the last line is the answer)", res)
	}
	if res := result(t, p, "job-00000003"); res.OK || !strings.Contains(res.Output, "malformed") {
		t.Errorf("bad token: %+v", res)
	}
	if res := result(t, p, "job-00000004"); res.OK || !strings.Contains(res.Output, "another job") {
		t.Errorf("swapped token: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(p.outbox(), "job-00000005.json")); err == nil {
		t.Error("the symlinked file was read")
	}
	if left, _ := filepath.Glob(filepath.Join(p.inbox(), "*")); len(left) != 0 {
		t.Errorf("inbox not emptied: %v", left)
	}

	// The same job again: never run twice, but answered.
	os.Remove(filepath.Join(p.outbox(), "job-00000001.json"))
	drop(t, p, "job-00000001", sign(t, k, "ES256", claims("job-00000001", "restart", []string{"nginx.service"}, now.Add(time.Hour))))
	if err := r.RunAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(x.calls) != 2 {
		t.Errorf("a job ran twice: %v", x.calls)
	}
	if res := result(t, p, "job-00000001"); res.OK || !strings.Contains(res.Output, "already taken") {
		t.Errorf("replay: %+v", res)
	}

	// Without the key nothing runs.
	os.Remove(p.PublicKey)
	if err := r.RunAll(context.Background()); err == nil {
		t.Error("ran without the job key")
	}
}

func TestPoller(t *testing.T) {
	p, k := setup(t)
	token := sign(t, k, "ES256", claims("job-00000001", "plan", nil, time.Now().Add(time.Hour)))
	var mu sync.Mutex
	var results []Result
	pending := []Inbox{{ID: "job-00000001", Token: token}, {ID: "../escape", Token: "x"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("X-Yomins-Agent-Id") != agentID || r.Header.Get("X-Yomins-Hostname") != "web-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/push/jobs":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jobs": pending})
		case "/v1/push/jobs/result":
			var res Result
			_ = json.NewDecoder(r.Body).Decode(&res)
			results = append(results, res)
			pending = nil
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	pl := &Poller{Server: srv.URL + "/v1/push", Token: "tok", Hostname: "web-1", AgentID: agentID, Paths: p, Client: srv.Client()}
	if !Enabled(p) {
		t.Fatal("the key is installed")
	}
	pl.Tick(context.Background())
	in, _ := filepath.Glob(filepath.Join(p.inbox(), "*.json"))
	if len(in) != 1 || filepath.Base(in[0]) != "job-00000001.json" {
		t.Fatalf("inbox %v (an unsafe id is dropped)", in)
	}
	pl.Tick(context.Background()) // still pending at the server, already in the inbox: not queued twice

	x := &ran{}
	if err := (&Runner{Paths: p, Exec: x.exec}).RunAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	pl.Tick(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(results) != 1 || results[0].ID != "job-00000001" || !results[0].OK {
		t.Fatalf("results %+v", results)
	}
	if out, _ := filepath.Glob(filepath.Join(p.outbox(), "*.json")); len(out) != 0 {
		t.Errorf("outbox not emptied: %v", out)
	}
	os.Remove(p.PublicKey)
	if Enabled(p) {
		t.Error("enabled without the key")
	}
}
