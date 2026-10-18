package logs

import (
	"os"
	"path/filepath"
)

// Plan is what to collect on this host.
type Plan struct {
	Files   []FileSpec
	Journal bool // follow the journal (no syslog daemon writes it to files)
}

// knownLogs are the log files of common software, by source. A spec is used
// only when one of its globs matches something, so the plan describes this
// host and nothing else.
var knownLogs = []FileSpec{
	// system (rsyslog / syslog-ng)
	{Source: "syslog", Parser: ParserSyslog, Globs: []string{"/var/log/syslog", "/var/log/messages", "/var/log/daemon.log", "/var/log/user.log"}},
	{Source: "auth", Parser: ParserSyslog, Globs: []string{"/var/log/auth.log", "/var/log/secure"}},
	{Source: "kernel", Parser: ParserSyslog, Globs: []string{"/var/log/kern.log"}},
	{Source: "cron", Parser: ParserSyslog, Globs: []string{"/var/log/cron.log", "/var/log/cron"}},
	{Source: "packages", Parser: ParserPlain, Globs: []string{"/var/log/dpkg.log", "/var/log/dnf.log", "/var/log/yum.log", "/var/log/apt/history.log", "/var/log/unattended-upgrades/unattended-upgrades.log"}},

	// web
	{Source: "nginx", Parser: ParserNginxAccess, Globs: []string{"/var/log/nginx/*access*.log", "/var/log/nginx/*analytics*.log"}},
	{Source: "nginx", Parser: ParserNginxError, Globs: []string{"/var/log/nginx/*error*.log"}},
	{Source: "apache", Parser: ParserNginxAccess, Globs: []string{"/var/log/apache2/*access*.log", "/var/log/httpd/*access*_log", "/var/log/httpd/*access*.log"}},
	{Source: "apache", Parser: ParserPlain, Globs: []string{"/var/log/apache2/*error*.log", "/var/log/httpd/*error*_log", "/var/log/httpd/*error*.log"}},
	{Source: "php-fpm", Parser: ParserPHPFPM, Globs: []string{"/var/log/php*-fpm.log", "/var/log/php-fpm/*.log", "/var/log/php-fpm*/*error*.log", "/var/log/php-fpm*/*slow*.log", "/var/log/php*/*error*.log"}},
	{Source: "php-fpm", Parser: ParserPlain, Globs: []string{"/var/log/php-fpm*/*access*.log"}},

	// databases
	{Source: "mysql", Parser: ParserMySQL, Globs: []string{"/var/log/mysql/*.log", "/var/log/mariadb/*.log", "/var/log/mysqld.log", "/var/lib/mysql/*.err", "/var/lib/mysql/*slow*.log"}},
	{Source: "postgresql", Parser: ParserAuto, Globs: []string{"/var/log/postgresql/*.log"}},
	{Source: "redis", Parser: ParserPlain, Globs: []string{"/var/log/redis/*.log"}},
	{Source: "mongodb", Parser: ParserJSON, Globs: []string{"/var/log/mongodb/*.log"}},

	// mail
	{Source: "mail", Parser: ParserSyslog, Globs: []string{"/var/log/mail.log", "/var/log/maillog", "/var/log/mail.err"}},
	{Source: "exim", Parser: ParserPlain, Globs: []string{"/var/log/exim4/mainlog", "/var/log/exim4/rejectlog", "/var/log/exim4/paniclog", "/var/log/exim/main.log", "/var/log/exim/reject.log", "/var/log/exim/panic.log"}},
	{Source: "dovecot", Parser: ParserSyslog, Globs: []string{"/var/log/dovecot*.log"}},

	// other services
	{Source: "ftp", Parser: ParserPlain, Globs: []string{"/var/log/vsftpd.log", "/var/log/xferlog", "/var/log/proftpd/*.log"}},
	{Source: "fail2ban", Parser: ParserPlain, Globs: []string{"/var/log/fail2ban.log"}},
	{Source: "clamav", Parser: ParserPlain, Globs: []string{"/var/log/clamav/*.log"}},
	{Source: "docker", Parser: ParserDockerJSON, Globs: []string{"/var/lib/docker/containers/*/*-json.log"}},
	{Source: "app", Parser: ParserAuto, Globs: []string{"/home/*/logs/*.log", "/home/*/logs/*/*.log", "/var/www/*/logs/*.log", "/var/www/*/log/*.log", "/var/log/yomins/*.log"}},
}

// Discover builds the plan for this host from knownLogs, plus extra globs
// (read with the auto parser as source "custom") and minus exclude globs.
func Discover(extra, exclude []string) Plan {
	var plan Plan
	for _, spec := range knownLogs {
		if anyMatch(spec.Globs) {
			spec.Exclude = exclude
			plan.Files = append(plan.Files, spec)
		}
	}
	if len(extra) > 0 {
		plan.Files = append(plan.Files, FileSpec{Source: "custom", Parser: ParserAuto, Globs: extra, Exclude: exclude})
	}
	// Without a syslog daemon the journal is the only place system logs live.
	plan.Journal = !exists("/var/log/syslog") && !exists("/var/log/messages") && exists("/run/systemd/journal")
	return plan
}

func anyMatch(globs []string) bool {
	for _, g := range globs {
		if m, _ := filepath.Glob(g); len(m) > 0 {
			return true
		}
	}
	return false
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
