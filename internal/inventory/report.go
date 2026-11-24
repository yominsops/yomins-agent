// Package inventory lists the software on a server: the OS packages, the
// services that run and their versions, containers, programs installed outside
// the package manager and the web applications (CMS and frameworks) in the
// sites' directories.
//
// Reading other users' site directories, other processes' executables and the
// Docker socket needs root, which the agent does not have, so
// `yomins-agent inventory-scan` runs once a day from its own root timer
// (yomins-agent-inventory.timer), writes a report next to the agent's state,
// and the unprivileged agent sends it (Sender). Each part of the scan is a
// Detector; a new kind of software is one more detector.
package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ReportVersion changes when the report format does.
const ReportVersion = 1

// DefaultReportPath is where the timer writes the report.
const DefaultReportPath = "/var/lib/yomins/agent/inventory.json"

// Kinds of Component.
const (
	KindService   = "service"   // a running program: nginx, php-fpm, mariadb…
	KindContainer = "container" // a running container
	KindBinary    = "binary"    // a program installed outside the package manager
	KindWebApp    = "webapp"    // a CMS or a web application in a site directory
	KindFramework = "framework" // a framework a site is built on (composer.lock)
)

// Report is one scan.
type Report struct {
	Version int       `json:"version"`
	Time    time.Time `json:"time"`
	OS      OS        `json:"os"`
	// Packages are all installed OS packages, sorted by name.
	Packages []Package `json:"packages"`
	// Components are the software worth showing: services, containers,
	// programs outside the package manager, web applications.
	Components []Component `json:"components"`
	// Updates are the packages with a newer version in the repositories
	// (security ones marked), as the package manager sees them at the scan.
	Updates []Update `json:"updates,omitempty"`
	// Errors has one entry per detector that failed; the others still report.
	Errors map[string]string `json:"errors,omitempty"`
}

// Update is one package with a newer version available.
type Update struct {
	Name    string `json:"name"`
	Version string `json:"version"` // the version it would be updated to
	// Security: the update comes from the distribution's security
	// repository or an advisory of the security kind.
	Security bool `json:"security,omitempty"`
	// Origin is the repository it comes from (Debian-Security, sury.org…).
	Origin string `json:"origin,omitempty"`
}

// States of a Component.
const (
	StateRunning = "running"
	StateStopped = "stopped" // an enabled service that does not run
	StateFailed  = "failed"  // a service systemd marks failed
)

// Port is one port a component listens on.
type Port struct {
	Proto string `json:"proto"`          // tcp | udp
	Addr  string `json:"addr,omitempty"` // 0.0.0.0, ::, 127.0.0.1
	Port  int    `json:"port"`           // on the host
	// Target is the container's port a published port leads to.
	Target int `json:"target,omitempty"`
}

// OS is the distribution, from /etc/os-release.
type OS struct {
	ID        string `json:"id"`                 // debian, ubuntu, almalinux…
	VersionID string `json:"version_id"`         // 12, 22.04, 9.4
	Codename  string `json:"codename,omitempty"` // bookworm, jammy
	Name      string `json:"name,omitempty"`     // "Debian GNU/Linux 12 (bookworm)"
}

// Package is one installed OS package.
type Package struct {
	Manager string `json:"manager"` // dpkg | rpm
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
	// Source is the source package (Debian) or source RPM name: security
	// trackers list vulnerabilities by it.
	Source        string `json:"source,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// Component is one piece of software found on the server.
type Component struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`              // nginx, php-fpm, wordpress, laravel
	Version string `json:"version,omitempty"` // "" when it could not be read
	// Package is the OS package it comes from, "" when it is not from one.
	Package string `json:"package,omitempty"`
	// Path is where it is: the executable, the site directory.
	Path string `json:"path,omitempty"`
	// Unit is the systemd service it runs in.
	Unit string `json:"unit,omitempty"`
	// Container: the container's name and image (KindContainer, and
	// software found inside one).
	Container string `json:"container,omitempty"`
	Image     string `json:"image,omitempty"`
	// Source tells how the version was found: package, env, file, command.
	Source string `json:"source,omitempty"`
	// Detail is a short note: the distribution inside a container.
	Detail string `json:"detail,omitempty"`

	// State is running, stopped or failed for services; a container's
	// Docker state (running, exited, paused, restarting…). "" when unknown.
	State string `json:"state,omitempty"`
	// Health is a container's health check status (healthy, unhealthy).
	Health string `json:"health,omitempty"`
	// StartedAt is when the service's main process or the container started.
	StartedAt *time.Time `json:"started_at,omitempty"`
	// Ports it listens on (services) or publishes (containers).
	Ports []Port `json:"ports,omitempty"`
	// Project is a container's Docker Compose project.
	Project string `json:"project,omitempty"`
	// Domains are the site's names from the web server's configuration,
	// the hosting panel's directory or the CMS settings (webapp, framework).
	Domains []string `json:"domains,omitempty"`
}

var safeValue = regexp.MustCompile(`[^0-9A-Za-z.+:~_@/ ()-]`)

// clean keeps a value read from a file or a command short and plain: it ends
// up in a report other people read.
func clean(s string, max int) string {
	s = strings.TrimSpace(safeValue.ReplaceAllString(s, ""))
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// version keeps a version string to its usual characters.
var versionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+:~_-]{0,63}$`)

func cleanVersion(s string) string {
	s = strings.TrimSpace(s)
	if !versionRe.MatchString(s) {
		return ""
	}
	return s
}

// Write saves the report atomically, readable by the agent.
func Write(path string, r Report) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".inventory-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// MaxReportSize bounds what Read and the agent accept.
const MaxReportSize = 16 << 20

// Read loads a report.
func Read(path string) (Report, []byte, error) {
	var r Report
	f, err := os.Open(path)
	if err != nil {
		return r, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return r, nil, err
	}
	if st.Size() > MaxReportSize {
		return r, nil, fmt.Errorf("inventory report is %d bytes, over %d", st.Size(), MaxReportSize)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxReportSize))
	if err != nil {
		return r, nil, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, nil, err
	}
	if r.Version != ReportVersion {
		return r, nil, fmt.Errorf("inventory report version %d, want %d", r.Version, ReportVersion)
	}
	return r, b, nil
}
