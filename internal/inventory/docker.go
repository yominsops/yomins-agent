package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// dockerContainers lists the running containers through the Docker API (or
// Podman's, which answers the same), read only. For each: its image, the
// distribution inside and the versions official images put in the
// environment (PHP_VERSION, NGINX_VERSION…), since what a container runs
// comes from its image, not from the host's packages.
type dockerContainers struct{}

func (dockerContainers) Name() string { return "docker" }

var dockerSockets = []string{"/var/run/docker.sock", "/run/podman/podman.sock"}

// maxContainers bounds one scan.
const maxContainers = 200

type dockerSummary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
	Ports  []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

type dockerInspect struct {
	State struct {
		Pid       int    `json:"Pid"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image string   `json:"Image"`
		Env   []string `json:"Env"`
	} `json:"Config"`
	Mounts []struct {
		Type   string `json:"Type"`
		Source string `json:"Source"`
	} `json:"Mounts"`
}

func (dockerContainers) Detect(ctx context.Context, e *Env, r *Report) error {
	sock := e.DockerSocket
	if sock == "" {
		for _, s := range dockerSockets {
			if st, err := os.Stat(e.Path(s)); err == nil && st.Mode()&os.ModeSocket != 0 {
				sock = e.Path(s)
				break
			}
		}
	}
	if sock == "" {
		return errNotHere
	}
	c := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}},
	}
	var list []dockerSummary
	// Stopped containers too: a compose service that exited is worth seeing.
	if err := dockerGet(ctx, c, "/containers/json?all=1", &list); err != nil {
		return err
	}
	for i, s := range list {
		if i >= maxContainers {
			break
		}
		name := s.ID
		if len(name) > 12 {
			name = name[:12]
		}
		if len(s.Names) > 0 {
			name = strings.TrimPrefix(s.Names[0], "/")
		}
		name = clean(name, 100)
		image := clean(s.Image, 200)
		if strings.HasPrefix(image, "sha256:") && len(image) > 19 {
			image = image[:19] // an image no tag names any more
		}
		base := Component{Kind: KindContainer, Name: name, Image: image, Container: name,
			State: clean(s.State, 20), Project: clean(s.Labels["com.docker.compose.project"], 100)}
		base.Ports = containerPorts(s)
		var in dockerInspect
		if err := dockerGet(ctx, c, "/containers/"+url.PathEscape(s.ID)+"/json", &in); err != nil {
			r.Components = append(r.Components, base)
			continue
		}
		cont := base
		cont.Version = cleanVersion(imageTag(image))
		// A stopped container's start time is of a run that is over.
		if t, err := time.Parse(time.RFC3339Nano, in.State.StartedAt); err == nil && t.Year() > 1 && s.State == "running" {
			t = t.UTC()
			cont.StartedAt = &t
		}
		if in.State.Health != nil {
			cont.Health = clean(in.State.Health.Status, 20)
		}
		env := map[string]string{}
		for _, kv := range in.Config.Env {
			if k, v, ok := strings.Cut(kv, "="); ok {
				env[k] = v
			}
		}
		// The distribution inside, from its os-release.
		if in.State.Pid > 0 {
			root := filepath.Join("/proc", strconv.Itoa(in.State.Pid), "root")
			for _, f := range []string{"etc/os-release", "usr/lib/os-release"} {
				if b, err := e.ReadFile(filepath.Join(root, f), 64<<10); err == nil {
					cont.Detail = parseOSRelease(b).Name
					break
				}
			}
		}
		r.Components = append(r.Components, cont)
		// A site served from a container lives in a directory of the host
		// mounted into it: the site scan looks there too.
		for _, m := range in.Mounts {
			if (m.Type == "bind" || m.Type == "volume") && strings.HasPrefix(m.Source, "/") && !strings.HasPrefix(m.Source, "/proc") &&
				!strings.HasPrefix(m.Source, "/sys") && !strings.HasPrefix(m.Source, "/dev") && m.Source != "/" && !strings.HasSuffix(m.Source, ".sock") {
				e.mounts = append(e.mounts, m.Source)
			}
		}
		// The software official images name in their environment.
		seen := map[string]bool{}
		for _, sw := range known {
			if sw.env == "" || seen[sw.env] {
				continue
			}
			seen[sw.env] = true
			if v := cleanVersion(upstreamVersion(env[sw.env])); v != "" {
				swName := sw.name
				if swName == "php-fpm" {
					swName = "php" // the image tells the version, not whether it is FPM
				}
				r.Components = append(r.Components, Component{Kind: KindService, Name: swName, Version: v, Container: name, Image: image, Source: "env",
					State: cont.State, Project: cont.Project})
			}
		}
	}
	return nil
}

// containerPorts are the ports a container publishes on the host.
func containerPorts(s dockerSummary) []Port {
	var out []Port
	seen := map[Port]bool{}
	for _, p := range s.Ports {
		if p.PublicPort <= 0 || len(out) >= maxPorts {
			continue
		}
		proto := p.Type
		if proto != "udp" && proto != "sctp" {
			proto = "tcp"
		}
		pt := Port{Proto: proto, Addr: clean(p.IP, 45), Port: p.PublicPort, Target: p.PrivatePort}
		if !seen[pt] {
			seen[pt] = true
			out = append(out, pt)
		}
	}
	sortPorts(out)
	return out
}

func dockerGet(ctx context.Context, c *http.Client, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker %s: %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(v)
}

// imageTag is the tag of an image reference: "php:8.3-fpm" → "8.3-fpm",
// "registry:5000/app" → "", "app@sha256:…" → "".
// Only a tag that looks like a version counts: "latest" or "alpine" says
// nothing about what runs.
func imageTag(ref string) string {
	if strings.Contains(ref, "@") || strings.HasPrefix(ref, "sha256:") {
		return ""
	}
	last := ref[strings.LastIndexByte(ref, '/')+1:]
	_, tag, ok := strings.Cut(last, ":")
	if !ok {
		return ""
	}
	if t := strings.TrimPrefix(tag, "v"); t == "" || t[0] < '0' || t[0] > '9' {
		return ""
	}
	return tag
}
