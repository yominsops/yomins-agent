package inventory

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"strings"
)

// dpkgPackages reads the dpkg database (/var/lib/dpkg/status) directly:
// no command, and the same on every Debian and Ubuntu release.
type dpkgPackages struct{}

func (dpkgPackages) Name() string { return "dpkg" }

func (dpkgPackages) Detect(_ context.Context, e *Env, r *Report) error {
	b, err := e.ReadFile("/var/lib/dpkg/status", 64<<20)
	if os.IsNotExist(err) {
		return errNotHere
	}
	if err != nil {
		return err
	}
	r.Packages = append(r.Packages, parseDpkgStatus(b)...)
	return nil
}

// parseDpkgStatus returns the installed packages of a dpkg status file.
func parseDpkgStatus(b []byte) []Package {
	var out []Package
	for _, stanza := range bytes.Split(b, []byte("\n\n")) {
		f := map[string]string{}
		sc := bufio.NewScanner(bytes.NewReader(stanza))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue // a continuation line (Description, Conffiles)
			}
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			switch k {
			case "Package", "Status", "Version", "Source", "Architecture":
				f[k] = strings.TrimSpace(v)
			}
		}
		// "install ok installed"; "deinstall ok config-files" is removed.
		if f["Package"] == "" || !strings.HasSuffix(f["Status"], " installed") {
			continue
		}
		p := Package{Manager: "dpkg", Name: clean(f["Package"], 100), Version: cleanVersion(f["Version"]), Arch: clean(f["Architecture"], 20)}
		// "Source: openssl" or "Source: linux-signed-amd64 (6.1.115+1)";
		// without the field the source is the package itself.
		src, ver := f["Source"], ""
		if i := strings.IndexByte(src, '('); i > 0 {
			src, ver = strings.TrimSpace(src[:i]), strings.Trim(src[i:], "() ")
		}
		if src == "" {
			src = f["Package"]
		}
		if ver == "" {
			ver = f["Version"]
		}
		p.Source, p.SourceVersion = clean(src, 100), cleanVersion(ver)
		out = append(out, p)
	}
	return out
}

// rpmPackages asks rpm (RHEL, Alma, Rocky, CloudLinux).
type rpmPackages struct{}

func (rpmPackages) Name() string { return "rpm" }

func (rpmPackages) Detect(ctx context.Context, e *Env, r *Report) error {
	if !e.Exists("/var/lib/rpm") && !e.Exists("/usr/lib/sysimage/rpm") {
		return errNotHere
	}
	out, err := e.Run(ctx, false, "rpm", "-qa", "--qf", `%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`)
	if err != nil {
		return err
	}
	r.Packages = append(r.Packages, parseRPMList(out)...)
	return nil
}

func parseRPMList(b []byte) []Package {
	var out []Package
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || f[0] == "" || f[0] == "gpg-pubkey" {
			continue
		}
		ver := strings.TrimPrefix(f[1], "0:")
		p := Package{Manager: "rpm", Name: clean(f[0], 100), Version: cleanVersion(ver), Arch: clean(f[2], 20)}
		// SOURCERPM is "openssl-3.0.7-27.el9.src.rpm": name is up to the
		// second dash from the end.
		if s := strings.TrimSuffix(f[3], ".src.rpm"); s != f[3] {
			if i := strings.LastIndexByte(s, '-'); i > 0 {
				if j := strings.LastIndexByte(s[:i], '-'); j > 0 {
					p.Source, p.SourceVersion = clean(s[:j], 100), cleanVersion(s[j+1:])
				}
			}
		}
		out = append(out, p)
	}
	return out
}

// packageIndex finds packages by name.
type packageIndex map[string]Package

func indexPackages(ps []Package) packageIndex {
	ix := packageIndex{}
	for _, p := range ps {
		if _, ok := ix[p.Name]; !ok {
			ix[p.Name] = p
		}
	}
	return ix
}
