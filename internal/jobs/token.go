// Package jobs runs the maintenance jobs the automation signs for this server.
//
// The unprivileged agent only carries them: it fetches the signed tokens from
// the ingest server into its state directory (jobs/inbox) and posts back the
// results it finds in jobs/outbox. The root runner (`yomins-agent job-run`,
// started by yomins-agent-jobs.path when a job arrives) checks each token —
// the signature against the public key pinned at install in
// /etc/yomins-agent/jobs.pub, which the agent cannot write; the agent id; the
// expiry; that it never ran before — and only then runs yopatch with the
// token's verb and arguments. Neither the agent process, the ingest server nor
// the backend can make this host run a job n8n did not sign.
package jobs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// Verbs yopatch knows.
var Verbs = map[string]bool{"plan": true, "security": true, "upgrade": true, "restart": true, "reboot": true}

// Claims of a job token.
type Claims struct {
	ID      string   `json:"jti"`
	AgentID string   `json:"sub"`
	Expires int64    `json:"exp"`
	Verb    string   `json:"verb"`
	Args    []string `json:"args,omitempty"`
}

var (
	ErrMalformed = errors.New("malformed job token")
	ErrSignature = errors.New("bad job signature")
	ErrClaims    = errors.New("job token lacks a valid id, agent, verb or arguments")
	ErrExpired   = errors.New("job token expired")
	ErrAgent     = errors.New("job token is for another agent")
)

var (
	reID  = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)
	reArg = regexp.MustCompile(`^[A-Za-z0-9@._+:*-]{1,128}$`)
)

// ParsePublicKey reads a PEM "PUBLIC KEY" (PKIX) holding a P-256 key.
func ParsePublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, errors.New("no PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("the job key must be an ECDSA P-256 key")
	}
	return ec, nil
}

// Verify checks a job token (JWT, ES256) and returns its claims: the signature
// with key, then that it is for agentID, unexpired at now, and a known verb with
// plain arguments.
func Verify(token string, key *ecdsa.PublicKey, agentID string, now time.Time) (Claims, error) {
	var c Claims
	if len(token) > 8<<10 {
		return c, ErrMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, ErrMalformed
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, ErrMalformed
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(header, &h) != nil {
		return c, ErrMalformed
	}
	// Only ES256: a token cannot pick a weaker algorithm (or "none").
	if h.Alg != "ES256" {
		return c, fmt.Errorf("%w: algorithm %q", ErrSignature, h.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return c, ErrSignature
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return c, ErrSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payload, &c) != nil {
		return c, ErrMalformed
	}
	if !reID.MatchString(c.ID) || !reID.MatchString(c.AgentID) || !Verbs[c.Verb] || len(c.Args) > 32 {
		return c, ErrClaims
	}
	for _, a := range c.Args {
		if !reArg.MatchString(a) {
			return c, ErrClaims
		}
	}
	if c.AgentID != agentID {
		return c, ErrAgent
	}
	if c.Expires == 0 || !time.Unix(c.Expires, 0).After(now) {
		return c, ErrExpired
	}
	return c, nil
}

// ValidID tells whether s may be a job id (also a safe file name).
func ValidID(s string) bool { return reID.MatchString(s) }
