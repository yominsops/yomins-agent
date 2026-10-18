package logs

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// DefaultAllow is where the agent may read logs unless the local
// configuration says otherwise. Remote configuration can choose files only
// inside it, so a compromised server cannot make the agent read /etc/shadow.
var DefaultAllow = []string{
	"/var/log/**",
	"/home/*/logs/**",
	"/home/*/log/**",
	"/var/www/**/logs/**",
	"/var/www/**/log/**",
	"/var/www/**/*.log",
	"/srv/**/*.log",
	"/opt/**/*.log",
	"/var/lib/docker/containers/*/*-json.log",
	"/var/lib/mysql/*.err",
	"/var/lib/mysql/*slow*.log",
}

var (
	globMu    sync.Mutex
	globCache = map[string]*regexp.Regexp{}
)

// Allowed reports whether path matches one of the allow globs. In the globs
// "**" spans directories, "*" and "?" stay within one path segment.
func Allowed(path string, allow []string) bool {
	path = filepath.Clean(path)
	for _, g := range allow {
		if globRegexp(g).MatchString(path) {
			return true
		}
	}
	return false
}

func globRegexp(g string) *regexp.Regexp {
	globMu.Lock()
	defer globMu.Unlock()
	if re, ok := globCache[g]; ok {
		return re
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); i++ {
		switch c := g[i]; {
		case c == '*' && i+1 < len(g) && g[i+1] == '*':
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re := regexp.MustCompile(b.String())
	globCache[g] = re
	return re
}
