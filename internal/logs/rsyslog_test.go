package logs

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rsyslog.conf")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSyslogCopies_Debian(t *testing.T) {
	c := syslogCopies([]string{writeConf(t, `
# comment
*.*;auth,authpriv.none		-/var/log/syslog
auth,authpriv.*			/var/log/auth.log
cron.*				-/var/log/cron.log
`)})
	for _, p := range []string{"/var/log/cron.log", "/var/log/kern.log", "/var/log/mail.log", "/var/log/user.log"} {
		if !c[p] {
			t.Errorf("%s should be a copy of syslog", p)
		}
	}
	if c["/var/log/auth.log"] {
		t.Error("auth is excluded from syslog: auth.log must be read")
	}
}

func TestSyslogCopies_RHEL(t *testing.T) {
	c := syslogCopies([]string{writeConf(t, `*.info;mail.none;authpriv.none;cron.none                /var/log/messages`)})
	if c["/var/log/maillog"] || c["/var/log/cron"] || c["/var/log/secure"] {
		t.Errorf("excluded facilities keep their files: %v", c)
	}
	if !c["/var/log/kern.log"] {
		t.Error("kern goes to messages")
	}
}

func TestSyslogCopies_NoConfig(t *testing.T) {
	if c := syslogCopies([]string{"/nonexistent"}); len(c) != 0 {
		t.Errorf("without a config nothing is skipped: %v", c)
	}
}
