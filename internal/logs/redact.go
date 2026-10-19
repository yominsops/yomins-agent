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
	// hint, when set, is a cheap test on the lower-cased line: the rule's
	// regexp runs only when it says the line may match. Most lines carry
	// no secret, and the regexps are most of the redactor's cost.
	hint func(lower string) bool
}

func hasAny(words ...string) func(string) bool {
	return func(lower string) bool {
		for _, w := range words {
			if strings.Contains(lower, w) {
				return true
			}
		}
		return false
	}
}

// defaultRedactRules cover the common shapes: key=value / "key":"value" pairs
// with a secret-sounding key, Authorization headers, and bare card numbers
// (checked with Luhn so order IDs and timestamps survive).
var defaultRedactRules = []redactRule{
	// Authorization: Bearer …, Basic …, or a bare credential; the scheme stays.
	{re: regexp.MustCompile(`(?i)(authorization["']?\s*[=:]\s*["']?)(?:(bearer|basic|digest|token)\s+)?([^\s"',;}&]+)`), hint: hasAny("authorization"), fn: func(m []string) string {
		if m[2] != "" {
			return m[1] + m[2] + " " + mask
		}
		return m[1] + mask
	}},
	{re: regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}`), repl: "${1} " + mask, hint: hasAny("bearer")},
	// password=…, &token=…, api_key: … (query strings, form bodies, key: value)
	{re: regexp.MustCompile(`(?i)((?:^|[?&\s,;{"'])(?:pass(?:word|wd)?|pwd|secret|token|access_token|refresh_token|id_token|api[_-]?key|apikey|session(?:id)?|private[_-]?key|client_secret|card(?:_?number)?|cvv|cvc)["']?\s*[=:]\s*["']?)([^&\s"',;}]+)`), repl: "${1}" + mask,
		hint: hasAny("pass", "pwd", "secret", "token", "key", "session", "card", "cvv", "cvc")},
	// URLs with credentials: scheme://user:pass@host
	{re: regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@`), repl: "${1}" + mask + "@",
		hint: func(lower string) bool { return strings.Contains(lower, "://") && strings.Contains(lower, "@") }},
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
	lower := strings.ToLower(s)
	for _, rule := range r.rules {
		if rule.hint != nil && !rule.hint(lower) {
			continue
		}
		if rule.fn != nil {
			re, fn := rule.re, rule.fn
			s = re.ReplaceAllStringFunc(s, func(m string) string { return fn(re.FindStringSubmatch(m)) })
			continue
		}
		s = rule.re.ReplaceAllString(s, rule.repl)
	}
	if !hasDigitRun(s, 13) {
		return s
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

// hasDigitRun reports whether s holds n digits with at most single spaces or
// dashes between them, the shape a card number needs.
func hasDigitRun(s string, n int) bool {
	run, sep := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			run++
			sep = false
			if run >= n {
				return true
			}
		case (c == ' ' || c == '-') && run > 0 && !sep:
			sep = true
		default:
			run, sep = 0, false
		}
	}
	return false
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
