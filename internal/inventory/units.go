package inventory

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
)

// stoppedServices lists the services that should run and do not: enabled
// units that are inactive, and failed ones. Only known software counts (a
// stopped nginx, not one of the many oneshot units a system has), so the
// list stays what a person wants to see next to the running services.
type stoppedServices struct{}

func (stoppedServices) Name() string { return "units" }

var unitName = regexp.MustCompile(`^[A-Za-z0-9@._:\\-]{1,200}\.service$`)

// maxStoppedUnits bounds the units asked about in one systemctl call.
const maxStoppedUnits = 300

func (stoppedServices) Detect(ctx context.Context, e *Env, r *Report) error {
	if !e.Exists("/run/systemd/system") {
		return errNotHere
	}
	out, err := e.Run(ctx, false, "systemctl", "list-units", "--type=service", "--all", "--state=inactive,failed",
		"--no-legend", "--plain", "--no-pager")
	if err != nil {
		return err
	}
	var units []string
	for line := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "● "))
		if len(f) > 0 && unitName.MatchString(f[0]) && len(units) < maxStoppedUnits {
			units = append(units, f[0])
		}
	}
	if len(units) == 0 {
		return nil
	}
	args := append([]string{"show", "-p", "Id", "-p", "ActiveState", "-p", "UnitFileState", "-p", "Type", "-p", "ExecStart", "--"}, units...)
	out, err = e.Run(ctx, false, "systemctl", args...)
	if err != nil && len(out) == 0 {
		return err
	}
	running := map[string]bool{}
	for _, c := range r.Components {
		if c.Unit != "" {
			running[c.Unit] = true
		}
	}
	var found []Component
	var exes []string
	for _, u := range parseUnitShow(out) {
		state := ""
		switch {
		case u["ActiveState"] == "failed":
			state = StateFailed
		case u["ActiveState"] == "inactive" && u["UnitFileState"] == "enabled" && u["Type"] != "oneshot":
			state = StateStopped
		default:
			continue
		}
		if running[u["Id"]] {
			continue
		}
		exe := execPath(u["ExecStart"])
		s, ok := lookupKnown(filepath.Base(exe))
		if exe == "" || !ok || interpreters[s.name] {
			continue
		}
		found = append(found, Component{Kind: KindService, Name: s.name, Path: clean(exe, 200), Unit: clean(u["Id"], 120), State: state})
		exes = append(exes, exe)
	}
	if len(found) == 0 {
		return nil
	}
	own := owners(ctx, e, exes)
	pkgs := indexPackages(r.Packages)
	for i := range found {
		if pkg := own[exes[i]]; pkg != "" {
			found[i].Package = pkg
			if v, ok := pkgs[pkg]; ok {
				found[i].Version, found[i].Source = upstreamVersion(v.Version), "package"
			}
		}
	}
	r.Components = append(r.Components, found...)
	return nil
}

// interpreters run scripts: a stopped unit that starts one says nothing
// about which software stopped.
var interpreters = map[string]bool{"python": true, "node": true, "php": true, "java": true}

// parseUnitShow splits `systemctl show` output of several units (blocks of
// Key=value lines separated by empty lines).
func parseUnitShow(b []byte) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	for line := range strings.SplitSeq(string(b)+"\n", "\n") {
		if strings.TrimSpace(line) == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[k] = v
		}
	}
	return out
}

// execPath is the program of an ExecStart value:
// "{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g … ; … }".
func execPath(v string) string {
	_, rest, ok := strings.Cut(v, "path=")
	if !ok {
		return ""
	}
	p, _, _ := strings.Cut(rest, " ")
	p = strings.TrimSuffix(p, ";")
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	return p
}
