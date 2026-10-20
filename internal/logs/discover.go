package logs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Plan is what to collect on this host.
type Plan struct {
	Files   []FileSpec
	Journal bool // follow the journal (no syslog daemon writes it to files)
	// ContainerAllow are the host globs of logs found through container
	// mounts. They come from the host's own Docker configuration, so they
	// extend the default allow list (an explicit YOMINS_LOG_ALLOW stays as is).
	ContainerAllow []string
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

// Discover builds the plan for this host from knownLogs, the logs of
// software in Docker containers found through their mounts, plus extra globs
// and minus exclude globs. An extra glob may name what it is,
// "nginx:/srv/site/logs/*.log", to be parsed as such; a bare one is read with
// the auto parser as source "custom".
func Discover(extra, exclude []string) Plan {
	var plan Plan
	// Per-facility files rsyslog also writes into /var/log/syslog are copies.
	copies := syslogCopies(rsyslogConfs())
	for _, spec := range knownLogs {
		spec.Globs = withoutCopies(spec.Globs, copies)
		if anyMatch(spec.Globs) {
			spec.Exclude = exclude
			plan.Files = append(plan.Files, spec)
		}
	}
	for _, spec := range containerLogSpecs(dockerContainers()) {
		spec.Exclude = exclude
		plan.Files = append(plan.Files, spec)
		plan.ContainerAllow = append(plan.ContainerAllow, spec.Globs...)
	}
	plan.Files = append(plan.Files, extraSpecs(extra, exclude)...)
	// Without a syslog daemon the journal is the only place system logs live.
	plan.Journal = !exists("/var/log/syslog") && !exists("/var/log/messages") && exists("/run/systemd/journal")
	return plan
}

var reSourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// SplitTyped splits "nginx:/var/www/x/*.log" into its source and glob; a glob
// without a source returns "".
func SplitTyped(g string) (source, glob string) {
	if name, rest, ok := strings.Cut(g, ":"); ok && strings.HasPrefix(rest, "/") && reSourceName.MatchString(name) {
		return name, rest
	}
	return "", g
}

// sourceParsers are the parsers of the sources an extra glob may name; other
// names are read with the auto parser under that name.
var sourceParsers = map[string]string{
	"nginx": ParserNginxAny, "apache": ParserApacheAny, "php-fpm": ParserPHPFPM, "mysql": ParserMySQL,
	"syslog": ParserSyslog, "auth": ParserSyslog, "kernel": ParserSyslog, "cron": ParserSyslog, "mail": ParserSyslog,
	"json": ParserJSON, "docker": ParserDockerJSON, "plain": ParserPlain,
}

// sourceAliases are other names people use for a source.
var sourceAliases = map[string]string{"mariadb": "mysql", "php": "php-fpm", "apache2": "apache", "httpd": "apache"}

func extraSpecs(extra, exclude []string) []FileSpec {
	var out []FileSpec
	bySource := map[string]int{}
	for _, g := range extra {
		source, glob := SplitTyped(g)
		if a, ok := sourceAliases[source]; ok {
			source = a
		}
		parser := ParserAuto
		if source == "" {
			source = "custom"
		} else if p, ok := sourceParsers[source]; ok {
			parser = p
		}
		if i, ok := bySource[source]; ok {
			out[i].Globs = append(out[i].Globs, glob)
			continue
		}
		bySource[source] = len(out)
		out = append(out, FileSpec{Source: source, Parser: parser, Globs: []string{glob}, Exclude: exclude})
	}
	return out
}

func withoutCopies(globs []string, copies map[string]bool) []string {
	out := make([]string, 0, len(globs))
	for _, g := range globs {
		if !copies[g] {
			out = append(out, g)
		}
	}
	return out
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
