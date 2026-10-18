package logs

import (
	"regexp"
	"strings"
)

const mask = "***"

// Redactor masks secrets in log lines before they leave the host. Some
// formats log request bodies or query strings (nginx "$request_body", PHP
// dumps), which carry passwords, tokens and card numbers.
type Redactor struct {
	rules []redactRule
}

type redactRule struct {
	re   *regexp.Regexp
	repl string
	fn   func(match []string) string // used instead of repl when set
}

// defaultRedactRules cover the common shapes: key=value / "key":"value" pairs
// with a secret-sounding key, Authorization headers, and bare card numbers
// (checked with Luhn so order IDs and timestamps survive).
var defaultRedactRules = []redactRule{
	// Authorization: Bearer …, Basic …, or a bare credential; the scheme stays.
	{re: regexp.MustCompile(`(?i)(authorization["']?\s*[=:]\s*["']?)(?:(bearer|basic|digest|token)\s+)?([^\s"',;}&]+)`), fn: func(m []string) string {
		if m[2] != "" {
			return m[1] + m[2] + " " + mask
		}
		return m[1] + mask
	}},
	{re: regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}`), repl: "${1} " + mask},
	// password=…, &token=…, api_key: … (query strings, form bodies, key: value)
	{re: regexp.MustCompile(`(?i)((?:^|[?&\s,;{"'])(?:pass(?:word|wd)?|pwd|secret|token|access_token|refresh_token|id_token|api[_-]?key|apikey|session(?:id)?|private[_-]?key|client_secret|card(?:_?number)?|cvv|cvc)["']?\s*[=:]\s*["']?)([^&\s"',;}]+)`), repl: "${1}" + mask},
	// URLs with credentials: scheme://user:pass@host
	{re: regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@`), repl: "${1}" + mask + "@"},
}

var reCardCandidate = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)

// NewRedactor builds a redactor with the default rules plus extra patterns
// (each match is replaced by ***). Invalid patterns are returned as an error.
func NewRedactor(extra []string) (*Redactor, error) {
	r := &Redactor{rules: append([]redactRule(nil), defaultRedactRules...)}
	for _, p := range extra {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		r.rules = append(r.rules, redactRule{re: re, repl: mask})
	}
	return r, nil
}

// Redact returns s with secrets masked.
func (r *Redactor) Redact(s string) string {
	for _, rule := range r.rules {
		if rule.fn != nil {
			re, fn := rule.re, rule.fn
			s = re.ReplaceAllStringFunc(s, func(m string) string { return fn(re.FindStringSubmatch(m)) })
			continue
		}
		s = rule.re.ReplaceAllString(s, rule.repl)
	}
	return reCardCandidate.ReplaceAllStringFunc(s, func(m string) string {
		digits := strings.Map(func(c rune) rune {
			if c >= '0' && c <= '9' {
				return c
			}
			return -1
		}, m)
		if len(digits) >= 13 && len(digits) <= 19 && luhn(digits) {
			return mask
		}
		return m
	})
}

func luhn(digits string) bool {
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
