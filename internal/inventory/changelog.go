package inventory

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"regexp"
	"sort"
)

// packageChangelogs adds to each service and program from a Debian package
// the CVE ids its package's changelog names. Third-party builds (sury's PHP
// 7.4 and 5.6, for one) backport fixes and keep the upstream version, so the
// version alone says "vulnerable" when it is not; the changelog says which
// CVEs the build fixed. Only components on the host itself: a container's
// files are not read.
type packageChangelogs struct{}

func (packageChangelogs) Name() string { return "changelogs" }

// maxChangelogCVEs bounds the list for one component; the newest entries
// are at the top of a changelog, so these are kept.
const maxChangelogCVEs = 3000

// maxChangelog bounds a decompressed changelog.
const maxChangelog = 32 << 20

var cveRe = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,7}`)

func (packageChangelogs) Detect(_ context.Context, e *Env, r *Report) error {
	if !e.Exists("/var/lib/dpkg/status") {
		return errNotHere
	}
	cache := map[string][]string{}
	for i := range r.Components {
		c := &r.Components[i]
		if c.Package == "" || c.Container != "" {
			continue
		}
		cves, ok := cache[c.Package]
		if !ok {
			cves = changelogCVEs(e, c.Package)
			cache[c.Package] = cves
		}
		c.FixedCVEs = cves
	}
	return nil
}

// changelogCVEs reads /usr/share/doc/PKG/changelog.Debian.gz; nil when there
// is none or it cannot be read.
func changelogCVEs(e *Env, pkg string) []string {
	if !pkgNameRe.MatchString(pkg) {
		return nil
	}
	b, err := e.ReadFile("/usr/share/doc/"+pkg+"/changelog.Debian.gz", 0)
	if err != nil {
		return nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	text, err := io.ReadAll(io.LimitReader(zr, maxChangelog))
	if err != nil && len(text) == 0 {
		return nil
	}
	return cveList(text)
}

var pkgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,99}$`)

// cveList returns the distinct CVE ids of a changelog, sorted, at most
// maxChangelogCVEs (the first ones met, the newest).
func cveList(text []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range cveRe.FindAll(text, -1) {
		id := string(m)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
		if len(out) == maxChangelogCVEs {
			break
		}
	}
	sort.Strings(out)
	return out
}
