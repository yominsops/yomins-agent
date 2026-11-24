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

// processes lists the programs that run on the host (not in containers): the
// main program of each service, or a known program running outside one. The
// programs a service starts (icinga's check plugins, a worker shelling out)
// are left out: only a process whose parent is outside its service counts.
// The version comes from the package that installed the program, or from the
// program itself.
type processes struct{}

type proc struct {
	pid, ppid int
	exe, unit string
}

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
	self := os.Getpid()
	var procs []proc
	unitOf := map[int]string{}
	for _, d := range entries {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || (pid == self && (e.Root == "" || e.Root == "/")) {
			continue
		}
		dir := filepath.Join("/proc", d.Name())
		exe, err := os.Readlink(e.Path(filepath.Join(dir, "exe")))
		if err != nil || exe == "" || !strings.HasPrefix(exe, "/") {
			continue // a kernel thread, a process gone meanwhile
		}
		cg, _ := e.ReadFile(filepath.Join(dir, "cgroup"), 64<<10)
		p := proc{pid: pid, ppid: parentPID(e, dir), exe: strings.TrimSuffix(exe, " (deleted)"), unit: restartscan.ServiceUnit(string(cg))}
		unitOf[pid] = p.unit
		procs = append(procs, p)
	}
	byExe := map[string]*running{}
	for _, p := range procs {
		if p.unit == "-" {
			continue // a container's: dockerContainers
		}
		base := filepath.Base(p.exe)
		if boring(base) {
			continue
		}
		if p.unit == "" {
			if _, ok := lookupKnown(base); !ok {
				continue // a login session's program
			}
		} else if parent, ok := unitOf[p.ppid]; ok && parent == p.unit {
			continue // started by its service's main program
		}
		r := byExe[p.exe]
		if r == nil {
			r = &running{exe: p.exe, units: map[string]bool{}}
			byExe[p.exe] = r
		}
		if p.unit != "" {
			r.units[p.unit] = true
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

// parentPID reads the parent from /proc/<pid>/stat ("pid (comm) state ppid …";
// comm may hold spaces and parentheses).
func parentPID(e *Env, dir string) int {
	b, err := e.ReadFile(filepath.Join(dir, "stat"), 4096)
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(f[1])
	return ppid
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
