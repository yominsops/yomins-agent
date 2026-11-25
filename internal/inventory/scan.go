package inventory

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Env is the system a scan reads. Root is "/" on a server and a test
// directory in tests; every path a detector opens goes through Path.
type Env struct {
	Root string
	// Run runs a command and returns its output; nil uses the real one
	// (exec.go). Tests replace it.
	Run func(ctx context.Context, user bool, name string, args ...string) ([]byte, error)
	// DockerSocket is the Docker API socket, "" for the default.
	DockerSocket string
	// mounts are the host directories mounted into containers, for the
	// site scan (set by dockerContainers).
	mounts []string
	// containers are the running containers' roots, for the web server
	// configurations inside them (set by dockerContainers).
	containers []containerRoot
}

// containerRoot is a running container seen from the host.
type containerRoot struct {
	root   string      // /proc/<pid>/root
	mounts [][2]string // container path → host path
}

// hostPath maps a path inside the container to the host's directory it is
// mounted from, "" when no mount covers it.
func (c containerRoot) hostPath(p string) string {
	best, host := "", ""
	for _, m := range c.mounts {
		dst := strings.TrimSuffix(m[0], "/")
		if (p == dst || strings.HasPrefix(p, dst+"/")) && len(dst) > len(best) {
			best, host = dst, filepath.Join(m[1], strings.TrimPrefix(p, dst))
		}
	}
	return host
}

// Path maps an absolute path into the scanned system.
func (e *Env) Path(p string) string {
	if e.Root == "" || e.Root == "/" {
		return p
	}
	return filepath.Join(e.Root, p)
}

// maxFile bounds every file a detector reads.
const maxFile = 8 << 20

// ReadFile reads a file of the scanned system, at most limit bytes (0: maxFile).
func (e *Env) ReadFile(p string, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = maxFile
	}
	f, err := os.Open(e.Path(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// Exists tells whether a path of the scanned system exists.
func (e *Env) Exists(p string) bool {
	_, err := os.Stat(e.Path(p))
	return err == nil
}

// Detector finds one kind of software and adds it to the report.
type Detector interface {
	Name() string
	Detect(ctx context.Context, e *Env, r *Report) error
}

// Detectors run in this order: packages first, the others look packages up.
func Detectors() []Detector {
	return []Detector{
		osRelease{},
		dpkgPackages{},
		rpmPackages{},
		&processes{},
		dockerContainers{},
		stoppedServices{}, // after processes: it skips the units that run
		localBinaries{},
		webApps{},
		pendingUpdates{},
		packageChangelogs{}, // last: it reads the packages of the components found
	}
}

// detectorTimeout bounds one detector; the scan as a whole is bounded by
// the unit's TimeoutStartSec.
const detectorTimeout = 5 * time.Minute

// Scan runs every detector. A detector that fails leaves an entry in
// Errors and the rest of the report.
func Scan(ctx context.Context, e *Env, detectors []Detector) Report {
	if e.Run == nil {
		e.Run = runCommand
	}
	r := Report{Version: ReportVersion, Time: time.Now().UTC(), Packages: []Package{}, Components: []Component{}}
	for _, d := range detectors {
		dctx, cancel := context.WithTimeout(ctx, detectorTimeout)
		err := safeDetect(dctx, d, e, &r)
		cancel()
		if err != nil && !errors.Is(err, errNotHere) {
			if r.Errors == nil {
				r.Errors = map[string]string{}
			}
			r.Errors[d.Name()] = clean(err.Error(), 300)
		}
	}
	sort.Slice(r.Packages, func(i, j int) bool {
		if r.Packages[i].Name != r.Packages[j].Name {
			return r.Packages[i].Name < r.Packages[j].Name
		}
		return r.Packages[i].Arch < r.Packages[j].Arch
	})
	r.Components = dedupe(r.Components)
	return r
}

// errNotHere: the detector does not apply to this server (no rpm on Debian).
var errNotHere = errors.New("not on this server")

func safeDetect(ctx context.Context, d Detector, e *Env, r *Report) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return d.Detect(ctx, e, r)
}

// dedupe drops repeated components (several php-fpm workers, one site under
// two names) and sorts them by kind and name.
func dedupe(in []Component) []Component {
	seen := map[string]bool{}
	out := make([]Component, 0, len(in))
	for _, c := range in {
		k := strings.Join([]string{c.Kind, c.Name, c.Version, c.Path, c.Container}, "\x00")
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	order := map[string]int{KindService: 0, KindContainer: 1, KindWebApp: 2, KindFramework: 3, KindBinary: 4}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return order[a.Kind] < order[b.Kind]
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Path < b.Path
	})
	return out
}

// osRelease reads /etc/os-release.
type osRelease struct{}

func (osRelease) Name() string { return "os" }

func (osRelease) Detect(_ context.Context, e *Env, r *Report) error {
	b, err := e.ReadFile("/etc/os-release", 64<<10)
	if err != nil {
		b, err = e.ReadFile("/usr/lib/os-release", 64<<10)
	}
	if err != nil {
		return err
	}
	r.OS = parseOSRelease(b)
	return nil
}

func parseOSRelease(b []byte) OS {
	kv := keyValues(b)
	o := OS{
		ID:        clean(kv["ID"], 40),
		VersionID: clean(kv["VERSION_ID"], 40),
		Codename:  clean(kv["VERSION_CODENAME"], 40),
		Name:      clean(kv["PRETTY_NAME"], 100),
	}
	if o.Codename == "" {
		o.Codename = clean(kv["UBUNTU_CODENAME"], 40)
	}
	return o
}

// keyValues parses KEY=value lines (os-release, container environment).
func keyValues(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}
