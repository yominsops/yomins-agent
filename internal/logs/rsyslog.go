package logs

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// facilityFiles are the per-facility files rsyslog setups usually write.
var facilityFiles = map[string][]string{
	"auth":   {"/var/log/auth.log", "/var/log/secure"},
	"cron":   {"/var/log/cron.log", "/var/log/cron"},
	"kern":   {"/var/log/kern.log"},
	"mail":   {"/var/log/mail.log", "/var/log/maillog", "/var/log/mail.err"},
	"user":   {"/var/log/user.log"},
	"daemon": {"/var/log/daemon.log"},
}

// syslogCopies returns the per-facility files whose lines rsyslog also writes
// to the catch-all file (/var/log/syslog or /var/log/messages): reading both
// would ship every such line twice. A facility the catch-all excludes
// ("mail.none") keeps its own file. Without a readable rsyslog configuration
// nothing is skipped.
func syslogCopies(confs []string) map[string]bool {
	var excluded map[string]bool
	found := false
	for _, conf := range confs {
		f, err := os.Open(conf)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			action := strings.TrimPrefix(fields[len(fields)-1], "-")
			if action != "/var/log/syslog" && action != "/var/log/messages" {
				continue
			}
			sel := strings.Join(fields[:len(fields)-1], "")
			if !strings.Contains(sel, "*.") {
				continue // not a catch-all selector
			}
			found = true
			excluded = map[string]bool{}
			for _, part := range strings.Split(sel, ";") {
				facs, prio, ok := strings.Cut(part, ".")
				if !ok || prio != "none" {
					continue
				}
				for _, fac := range strings.Split(facs, ",") {
					excluded[strings.TrimSpace(fac)] = true
				}
			}
		}
		f.Close()
		if found {
			break
		}
	}
	copies := map[string]bool{}
	if !found {
		return copies
	}
	for fac, files := range facilityFiles {
		if excluded[fac] || (fac == "auth" && excluded["authpriv"]) {
			continue
		}
		for _, p := range files {
			copies[p] = true
		}
	}
	return copies
}

// rsyslogConfs lists the rsyslog configuration files, main file first.
func rsyslogConfs() []string {
	confs := []string{"/etc/rsyslog.conf"}
	more, _ := filepath.Glob("/etc/rsyslog.d/*.conf")
	return append(confs, more...)
}
