package inventory

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/yominsops/yomins-agent/internal/restartscan"
)

// processes lists the programs that run on the host (not in containers): a
// service, or a known program running outside one. The version comes from
// the package that installed the program, or from the program itself.
type processes struct{}

func (*processes) Name() string { return "processes" }

type running struct {
	exe   string
	units map[string]bool
}

func (*processes) Detect(ctx context.Context, e *Env, r *Report) error {
	entries, err := os.ReadDir(e.Path("/proc"))
	if err != nil {
		return err
	}
	byExe := map[string]*running{}
	for _, d := range entries {
		if _, err := strconv.Atoi(d.Name()); err != nil {
			continue
		}
		dir := filepath.Join("/proc", d.Name())
		exe, err := os.Readlink(e.Path(filepath.Join(dir, "exe")))
		if err != nil || exe == "" || !strings.HasPrefix(exe, "/") {
			continue // a kernel thread, a process gone meanwhile
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		cg, _ := e.ReadFile(filepath.Join(dir, "cgroup"), 64<<10)
		unit := restartscan.ServiceUnit(string(cg))
		if unit == "-" {
			continue // a container's: dockerContainers
		}
		base := filepath.Base(exe)
		if boring(base) {
			continue
		}
		if _, ok := lookupKnown(base); !ok && unit == "" {
			continue // a login session's program
		}
		p := byExe[exe]
		if p == nil {
			p = &running{exe: exe, units: map[string]bool{}}
			byExe[exe] = p
		}
		if unit != "" {
			p.units[unit] = true
		}
	}
	exes := make([]string, 0, len(byExe))
	for exe := range byExe {
		exes = append(exes, exe)
	}
	sort.Strings(exes)
	own := owners(ctx, e, exes)
	pkgs := indexPackages(r.Packages)
	for _, exe := range exes {
		p := byExe[exe]
		base := filepath.Base(exe)
		c := Component{Kind: KindService, Name: clean(base, 60), Path: clean(exe, 200), Unit: firstUnit(p.units)}
		s, isKnown := lookupKnown(base)
		if isKnown {
			c.Name = s.name
		}
		if pkg := own[exe]; pkg != "" {
			c.Package = pkg
			if v, ok := pkgs[pkg]; ok {
				c.Version, c.Source = upstreamVersion(v.Version), "package"
			}
		} else if isKnown {
			if v := probeVersion(ctx, e, s, exe); v != "" {
				c.Version, c.Source = v, "command"
			}
		}
		// mysqld on MariaDB systems.
		if c.Name == "mysql" && (strings.Contains(c.Package, "mariadb") || strings.HasSuffix(c.Version, "-MariaDB")) {
			c.Name, c.Version = "mariadb", strings.TrimSuffix(c.Version, "-MariaDB")
		}
		r.Components = append(r.Components, c)
	}
	return nil
}

func firstUnit(units map[string]bool) string {
	all := make([]string, 0, len(units))
	for u := range units {
		all = append(all, u)
	}
	if len(all) == 0 {
		return ""
	}
	sort.Strings(all)
	return clean(all[0], 120)
}
