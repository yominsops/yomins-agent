package inventory

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
)

// localBinaries lists the programs installed outside the package manager:
// compiled by hand or copied in (/usr/local, /opt). Scripts are left out;
// a known program also gets its version.
type localBinaries struct{}

func (localBinaries) Name() string { return "binaries" }

// maxBinaries bounds the list.
const maxBinaries = 150

var binaryDirs = []string{"/usr/local/bin", "/usr/local/sbin", "/opt/*/bin", "/opt/*/sbin", "/opt/*/*/bin", "/opt/*/*/sbin"}

func (localBinaries) Detect(ctx context.Context, e *Env, r *Report) error {
	var files []string
	for _, pattern := range binaryDirs {
		dirs, _ := filepath.Glob(e.Path(pattern))
		for _, d := range dirs {
			entries, err := os.ReadDir(d)
			if err != nil {
				continue
			}
			for _, f := range entries {
				p := filepath.Join(d, f.Name())
				if !isELF(p) {
					continue
				}
				rel := p
				if e.Root != "" && e.Root != "/" {
					rel, _ = filepath.Rel(e.Root, p)
					rel = "/" + rel
				}
				files = append(files, rel)
			}
		}
	}
	sort.Strings(files)
	own := owners(ctx, e, files)
	n := 0
	for _, f := range files {
		if own[f] != "" || n >= maxBinaries {
			continue
		}
		base := filepath.Base(f)
		if base == "yomins-agent" {
			continue
		}
		c := Component{Kind: KindBinary, Name: clean(base, 60), Path: clean(f, 200)}
		if s, ok := lookupKnown(base); ok {
			c.Name = s.name
			if v := probeVersion(ctx, e, s, f); v != "" {
				c.Version, c.Source = v, "command"
			}
		}
		r.Components = append(r.Components, c)
		n++
	}
	return nil
}

// isELF: a regular executable file starting with the ELF magic.
func isELF(p string) bool {
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() || st.Mode()&0o111 == 0 {
		return false
	}
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4)
	if _, err := f.Read(head); err != nil {
		return false
	}
	return bytes.Equal(head, []byte("\x7fELF"))
}
