package logs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// dockerRoot is Docker's data directory; tests point it elsewhere.
var dockerRoot = "/var/lib/docker"

// container is what the agent needs of a Docker container: its name for the
// lines it writes, and its mounts to find the log files it keeps on the host.
type container struct {
	ID     string
	Name   string
	Image  string
	Mounts []mount
}

type mount struct {
	Source      string // on the host
	Destination string // in the container
}

// dockerContainers reads the containers' configuration from Docker's data
// directory, so the agent needs neither the Docker socket nor root.
func dockerContainers() []container {
	paths, _ := filepath.Glob(filepath.Join(dockerRoot, "containers", "*", "config.v2.json"))
	out := make([]container, 0, len(paths))
	for _, p := range paths {
		if c, ok := readContainer(p); ok {
			out = append(out, c)
		}
	}
	return out
}

func readContainer(configPath string) (container, bool) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return container{}, false
	}
	var raw struct {
		ID     string
		Name   string
		Config struct{ Image string }
		// Keyed by the destination; Source is empty for tmpfs and the like.
		MountPoints map[string]struct {
			Source      string
			Destination string
		}
	}
	if json.Unmarshal(b, &raw) != nil {
		return container{}, false
	}
	c := container{ID: raw.ID, Name: strings.TrimPrefix(raw.Name, "/"), Image: raw.Config.Image}
	if c.ID == "" {
		c.ID = filepath.Base(filepath.Dir(configPath))
	}
	for _, m := range raw.MountPoints {
		if m.Source != "" && filepath.IsAbs(m.Source) && filepath.IsAbs(m.Destination) {
			c.Mounts = append(c.Mounts, mount{Source: filepath.Clean(m.Source), Destination: filepath.Clean(m.Destination)})
		}
	}
	return c, true
}

// containerLogSpecs maps the known log files of software running in
// containers to where they are on the host. nginx in a container writing
// /var/log/nginx, mounted from /srv/edge/logs, is read at /srv/edge/logs with
// the nginx parsers, and its lines say which container wrote them.
func containerLogSpecs(containers []container) []FileSpec {
	var out []FileSpec
	seen := map[string]bool{}
	for _, c := range containers {
		for _, m := range c.Mounts {
			for _, spec := range knownLogs {
				if spec.Source == "docker" {
					continue
				}
				var globs []string
				for _, g := range spec.Globs {
					if hg, ok := hostGlob(g, m); ok && !seen[hg] {
						seen[hg] = true
						globs = append(globs, hg)
					}
				}
				if len(globs) > 0 && anyMatch(globs) {
					out = append(out, FileSpec{Source: spec.Source, Parser: spec.Parser, Globs: globs, Container: c.Name})
				}
			}
		}
	}
	return out
}

// hostGlob rewrites a glob inside the container to the host side of mount m,
// when the glob lies under the mount's destination.
func hostGlob(g string, m mount) (string, bool) {
	if m.Destination == "/" {
		return "", false // the container's whole root: nothing to learn from it
	}
	rest, ok := strings.CutPrefix(g, m.Destination+"/")
	if !ok {
		return "", false
	}
	return filepath.Join(m.Source, rest), true
}

// containerOfLog returns the container whose Docker json log is at path
// (<docker root>/containers/<id>/<id>-json.log).
func containerOfLog(path string) (container, bool) {
	return readContainer(filepath.Join(filepath.Dir(path), "config.v2.json"))
}
