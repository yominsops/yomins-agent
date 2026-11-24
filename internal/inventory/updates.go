package inventory

import (
	"context"
	"errors"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// pendingUpdates lists the packages the package manager would update, from
// its cached repository data (no download): apt-get's simulation or dnf/yum
// check-update, security ones marked. The agent's updates collector only
// counts them; the list tells which software is behind.
type pendingUpdates struct{}

func (pendingUpdates) Name() string { return "updates" }

// maxUpdates bounds the list.
const maxUpdates = 5000

func (pendingUpdates) Detect(ctx context.Context, e *Env, r *Report) error {
	switch {
	case e.Exists("/usr/bin/apt-get"):
		out, err := e.Run(ctx, false, "apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
		if err != nil {
			return err
		}
		r.Updates = parseAptSimulation(out)
	case e.Exists("/usr/bin/dnf") || e.Exists("/usr/bin/yum"):
		mgr := "dnf"
		if !e.Exists("/usr/bin/dnf") {
			mgr = "yum"
		}
		// check-update exits 100 when there are updates.
		out, err := e.Run(ctx, false, mgr, "-q", "-C", "check-update")
		var ee *exec.ExitError
		if err != nil && !(errors.As(err, &ee) && ee.ExitCode() == 100) {
			return err
		}
		ups := parseCheckUpdate(out)
		if sec, err := e.Run(ctx, false, mgr, "-q", "-C", "updateinfo", "list", "--security"); err == nil {
			names := securityPackages(sec)
			for i := range ups {
				if names[ups[i].Name] {
					ups[i].Security = true
				}
			}
		}
		r.Updates = ups
	default:
		return errNotHere
	}
	return nil
}

// parseAptSimulation reads the "Inst" lines of `apt-get -s dist-upgrade`:
//
//	Inst libc6 [2.36-9] (2.36-9+deb12u9 Debian-Security:12/stable-security [arm64])
//	Inst php-common [2:101] (2:102+debsuryorg12.1+3 bookworm [all])
func parseAptSimulation(out []byte) []Update {
	var ups []Update
	seen := map[string]bool{}
	for line := range strings.SplitSeq(string(out), "\n") {
		rest, ok := strings.CutPrefix(line, "Inst ")
		if !ok || len(ups) >= maxUpdates {
			continue
		}
		name, rest, _ := strings.Cut(rest, " ")
		i := strings.IndexByte(rest, '(')
		if i < 0 || seen[name] {
			continue
		}
		f := strings.Fields(strings.TrimSuffix(strings.TrimSpace(rest[i+1:]), ")"))
		if len(f) == 0 {
			continue
		}
		u := Update{Name: clean(name, 100), Version: cleanVersion(f[0])}
		if len(f) > 1 {
			// "Debian-Security:12/stable-security, Debian:12.8/stable"
			origins := strings.Join(f[1:], " ")
			if j := strings.LastIndex(origins, " ["); j >= 0 {
				origins = origins[:j]
			}
			u.Security = strings.Contains(origins, "-security") || strings.Contains(origins, "Debian-Security")
			first, _, _ := strings.Cut(origins, ",")
			first, _, _ = strings.Cut(first, ":")
			u.Origin = clean(first, 60)
		}
		if u.Name == "" || u.Version == "" {
			continue
		}
		seen[name] = true
		ups = append(ups, u)
	}
	sort.Slice(ups, func(i, j int) bool { return ups[i].Name < ups[j].Name })
	return ups
}

var rpmArch = regexp.MustCompile(`\.(noarch|x86_64|aarch64|i686|i386|ppc64le|s390x|armv7hl)$`)

// parseCheckUpdate reads `dnf/yum check-update`: "name.arch  version  repo".
// The "Obsoleting Packages" section is not updates.
func parseCheckUpdate(out []byte) []Update {
	var ups []Update
	seen := map[string]bool{}
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || !rpmArch.MatchString(f[0]) || len(ups) >= maxUpdates {
			continue
		}
		name := rpmArch.ReplaceAllString(f[0], "")
		if seen[name] {
			continue
		}
		u := Update{Name: clean(name, 100), Version: cleanVersion(strings.TrimPrefix(f[1], "0:")), Origin: clean(f[2], 60)}
		if u.Name == "" || u.Version == "" {
			continue
		}
		seen[name] = true
		ups = append(ups, u)
	}
	sort.Slice(ups, func(i, j int) bool { return ups[i].Name < ups[j].Name })
	return ups
}

var nevra = regexp.MustCompile(`^(\S+)-[^-\s]+-[^-\s]+` + rpmArch.String())

// securityPackages are the package names `updateinfo list --security`
// names ("ALSA-2024:1234 Important/Sec. openssl-1:3.0.7-28.el9.x86_64").
func securityPackages(out []byte) map[string]bool {
	names := map[string]bool{}
	for line := range strings.SplitSeq(string(out), "\n") {
		for _, f := range strings.Fields(line) {
			if m := nevra.FindStringSubmatch(f); m != nil {
				names[m[1]] = true
			}
		}
	}
	return names
}
