package inventory

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
)

// owners maps files to the OS package that installed them, "" for a file of
// no package. Only the asked paths are looked up: the full file lists of all
// packages are far too big to keep.
func owners(ctx context.Context, e *Env, paths []string) map[string]string {
	out := map[string]string{}
	if len(paths) == 0 {
		return out
	}
	// With merged /usr, /usr/sbin/nginx is also /sbin/nginx, and the
	// package may list either.
	want := map[string]string{}
	for _, p := range paths {
		out[p] = ""
		want[p] = p
		if rest, ok := strings.CutPrefix(p, "/usr"); ok && strings.Count(rest, "/") == 2 {
			want[rest] = p
		} else if strings.Count(p, "/") == 2 {
			want["/usr"+p] = p
		}
	}
	if e.Exists("/var/lib/dpkg/info") {
		dpkgOwners(e, want, out)
	}
	if e.Exists("/var/lib/rpm") || e.Exists("/usr/lib/sysimage/rpm") {
		rpmOwners(ctx, e, paths, out)
	}
	return out
}

func dpkgOwners(e *Env, want map[string]string, out map[string]string) {
	lists, _ := filepath.Glob(filepath.Join(e.Path("/var/lib/dpkg/info"), "*.list"))
	left := len(want)
	for _, l := range lists {
		if left == 0 {
			return
		}
		pkg := strings.TrimSuffix(filepath.Base(l), ".list")
		pkg, _, _ = strings.Cut(pkg, ":") // libc6:amd64
		f, err := os.Open(l)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			if orig, ok := want[sc.Text()]; ok && out[orig] == "" {
				out[orig] = pkg
				left--
			}
		}
		f.Close()
	}
}

func rpmOwners(ctx context.Context, e *Env, paths []string, out map[string]string) {
	args := append([]string{"-qf", "--qf", `%{NAME}\n`}, paths...)
	b, _ := e.Run(ctx, false, "rpm", args...)
	// One line per path, in order; "file … is not owned by any package"
	// for the others.
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != len(paths) {
		return
	}
	for i, l := range lines {
		if l != "" && !strings.Contains(l, " ") {
			out[paths[i]] = clean(l, 100)
		}
	}
}
