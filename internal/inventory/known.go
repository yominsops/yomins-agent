package inventory

import (
	"context"
	"os"
	"regexp"
	"strings"
)

// software is a program the inventory names and can ask for its version.
type software struct {
	name string         // the component name: nginx, php-fpm, mariadb
	exe  *regexp.Regexp // the executable's file name
	args []string       // the arguments that print the version
	ver  *regexp.Regexp // the version in what it prints (group 1)
	// env is the variable official container images set to the version
	// (PHP_VERSION), "" when there is none.
	env string
}

var known = []software{
	{name: "nginx", exe: regexp.MustCompile(`^nginx$`), args: []string{"-v"}, ver: regexp.MustCompile(`nginx/([0-9][0-9.]*)`), env: "NGINX_VERSION"},
	{name: "angie", exe: regexp.MustCompile(`^angie$`), args: []string{"-v"}, ver: regexp.MustCompile(`Angie/([0-9][0-9.]*)`)},
	{name: "openresty", exe: regexp.MustCompile(`^openresty$`), args: []string{"-v"}, ver: regexp.MustCompile(`openresty/([0-9][0-9.]*)`)},
	{name: "apache", exe: regexp.MustCompile(`^(apache2|httpd)$`), args: []string{"-v"}, ver: regexp.MustCompile(`Apache/([0-9][0-9.]*)`), env: "HTTPD_VERSION"},
	{name: "litespeed", exe: regexp.MustCompile(`^(litespeed|lshttpd|openlitespeed)$`), args: []string{"-v"}, ver: regexp.MustCompile(`LiteSpeed/([0-9][0-9.]*)`)},
	{name: "caddy", exe: regexp.MustCompile(`^caddy$`), args: []string{"version"}, ver: regexp.MustCompile(`v([0-9][0-9.]*)`)},
	{name: "haproxy", exe: regexp.MustCompile(`^haproxy$`), args: []string{"-v"}, ver: regexp.MustCompile(`version ([0-9][0-9.]*)`)},
	{name: "varnish", exe: regexp.MustCompile(`^varnishd$`), args: []string{"-V"}, ver: regexp.MustCompile(`varnish-([0-9][0-9.]*)`)},
	{name: "traefik", exe: regexp.MustCompile(`^traefik$`), args: []string{"version"}, ver: regexp.MustCompile(`Version:\s+v?([0-9][0-9.]*)`)},
	{name: "php-fpm", exe: regexp.MustCompile(`^php-fpm[0-9.]*$|^php[0-9.]*-fpm$`), args: []string{"-v"}, ver: regexp.MustCompile(`PHP ([0-9][0-9.]*)`), env: "PHP_VERSION"},
	{name: "php", exe: regexp.MustCompile(`^(php[0-9.]*|lsphp[0-9.]*)$`), args: []string{"-v"}, ver: regexp.MustCompile(`PHP ([0-9][0-9.]*)`), env: "PHP_VERSION"},
	{name: "mariadb", exe: regexp.MustCompile(`^mariadbd$`), args: []string{"--version"}, ver: regexp.MustCompile(`Ver ([0-9][0-9.]*)`), env: "MARIADB_VERSION"},
	// mysqld is MySQL or, on older systems, MariaDB: the version tells.
	{name: "mysql", exe: regexp.MustCompile(`^mysqld$`), args: []string{"--version"}, ver: regexp.MustCompile(`Ver ([0-9][0-9.]*(-MariaDB)?)`), env: "MYSQL_VERSION"},
	{name: "postgresql", exe: regexp.MustCompile(`^(postgres|postmaster)$`), args: []string{"--version"}, ver: regexp.MustCompile(`\(PostgreSQL\) ([0-9][0-9.]*)`), env: "PG_VERSION"},
	{name: "mongodb", exe: regexp.MustCompile(`^mongod$`), args: []string{"--version"}, ver: regexp.MustCompile(`db version v([0-9][0-9.]*)`), env: "MONGO_VERSION"},
	{name: "redis", exe: regexp.MustCompile(`^redis-server$`), args: []string{"--version"}, ver: regexp.MustCompile(`v=([0-9][0-9.]*)`), env: "REDIS_VERSION"},
	{name: "valkey", exe: regexp.MustCompile(`^valkey-server$`), args: []string{"--version"}, ver: regexp.MustCompile(`v=([0-9][0-9.]*)`), env: "VALKEY_VERSION"},
	{name: "memcached", exe: regexp.MustCompile(`^memcached$`), args: []string{"-V"}, ver: regexp.MustCompile(`memcached ([0-9][0-9.]*)`), env: "MEMCACHED_VERSION"},
	{name: "elasticsearch", exe: regexp.MustCompile(`^elasticsearch$`), env: "ELASTIC_VERSION"},
	{name: "rabbitmq", exe: regexp.MustCompile(`^beam\.smp$`), env: "RABBITMQ_VERSION"},
	{name: "exim", exe: regexp.MustCompile(`^exim4?$`), args: []string{"-bV"}, ver: regexp.MustCompile(`Exim version ([0-9][0-9.]*)`)},
	{name: "postfix", exe: regexp.MustCompile(`^master$`)},
	{name: "dovecot", exe: regexp.MustCompile(`^dovecot$`), args: []string{"--version"}, ver: regexp.MustCompile(`^([0-9][0-9.]*)`)},
	{name: "opendkim", exe: regexp.MustCompile(`^opendkim$`), args: []string{"-V"}, ver: regexp.MustCompile(`v([0-9][0-9.]*)`)},
	{name: "rspamd", exe: regexp.MustCompile(`^rspamd$`), args: []string{"--version"}, ver: regexp.MustCompile(`([0-9]+\.[0-9.]+)`)},
	{name: "clamav", exe: regexp.MustCompile(`^clamd$`), args: []string{"--version"}, ver: regexp.MustCompile(`ClamAV ([0-9][0-9.]*)`)},
	{name: "openssh", exe: regexp.MustCompile(`^sshd$`), args: []string{"-V"}, ver: regexp.MustCompile(`OpenSSH_([0-9][0-9.p]*)`)},
	{name: "bind", exe: regexp.MustCompile(`^named$`), args: []string{"-v"}, ver: regexp.MustCompile(`BIND ([0-9][0-9.]*)`)},
	{name: "pure-ftpd", exe: regexp.MustCompile(`^pure-ftpd$`)},
	{name: "proftpd", exe: regexp.MustCompile(`^proftpd$`), args: []string{"-v"}, ver: regexp.MustCompile(`ProFTPD Version ([0-9][0-9.a-z]*)`)},
	{name: "vsftpd", exe: regexp.MustCompile(`^vsftpd$`)},
	{name: "squid", exe: regexp.MustCompile(`^squid$`), args: []string{"-v"}, ver: regexp.MustCompile(`Version ([0-9][0-9.]*)`)},
	{name: "openvpn", exe: regexp.MustCompile(`^openvpn$`), args: []string{"--version"}, ver: regexp.MustCompile(`OpenVPN ([0-9][0-9.]*)`)},
	{name: "docker", exe: regexp.MustCompile(`^dockerd$`), args: []string{"--version"}, ver: regexp.MustCompile(`version ([0-9][0-9.]*)`)},
	{name: "containerd", exe: regexp.MustCompile(`^containerd$`), args: []string{"--version"}, ver: regexp.MustCompile(` v?([0-9]+\.[0-9.]+)`)},
	{name: "node", exe: regexp.MustCompile(`^(node|nodejs)$`), args: []string{"--version"}, ver: regexp.MustCompile(`v([0-9][0-9.]*)`), env: "NODE_VERSION"},
	{name: "python", exe: regexp.MustCompile(`^python[0-9.]*$`), args: []string{"--version"}, ver: regexp.MustCompile(`Python ([0-9][0-9.]*)`), env: "PYTHON_VERSION"},
	{name: "java", exe: regexp.MustCompile(`^java$`), env: "JAVA_VERSION"},
	{name: "gitlab-runner", exe: regexp.MustCompile(`^gitlab-runner$`), args: []string{"--version"}, ver: regexp.MustCompile(`Version:\s+([0-9][0-9.]*)`)},
	{name: "fail2ban", exe: regexp.MustCompile(`^fail2ban-server$`)},
	{name: "crowdsec", exe: regexp.MustCompile(`^crowdsec$`)},
	{name: "cpanel", exe: regexp.MustCompile(`^cpsrvd$`)},
	{name: "plesk", exe: regexp.MustCompile(`^sw-engine$`)},
	{name: "ispmanager", exe: regexp.MustCompile(`^ispmgr$`)},
	{name: "vestacp", exe: regexp.MustCompile(`^vesta-nginx$`)},
	{name: "hestiacp", exe: regexp.MustCompile(`^hestia-nginx$`)},
}

// lookupKnown finds the program by its executable's file name.
func lookupKnown(base string) (software, bool) {
	for _, s := range known {
		if s.exe.MatchString(base) {
			return s, true
		}
	}
	return software{}, false
}

// boring are system programs every server runs: not worth listing.
var boringNames = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`agetty login polkitd udisksd multipathd cron crond atd rsyslogd
		irqbalance accounts-daemon networkd-dispatcher unattended-upgr packagekitd upowerd thermald
		ModemManager wpa_supplicant qemu-ga chronyd lvmetad dhclient auditd tuned gssproxy rngd rpcbind
		snapd lxcfs iscsid smartd sssd yomins-agent containerd-shim containerd-shim-runc-v2 docker-proxy runc
		sleep bash sh dash sudo su sshd-session`) {
		boringNames[n] = true
	}
}

func boring(base string) bool {
	return boringNames[base] || strings.HasPrefix(base, "systemd") || strings.HasPrefix(base, "(sd-") ||
		strings.HasPrefix(base, "dbus-") || strings.HasPrefix(base, "rpc.") || strings.HasPrefix(base, "kworker")
}

// probeVersion asks a program for its version, as nobody. Only a program
// that root owns and only root can change is run: a file a site user could
// have replaced is never started by the root scan.
func probeVersion(ctx context.Context, e *Env, s software, exe string) string {
	if len(s.args) == 0 || s.ver == nil {
		return ""
	}
	st, err := os.Stat(e.Path(exe))
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o022 != 0 || st.Mode()&0o111 == 0 {
		return ""
	}
	if !rootOwned(st) {
		return ""
	}
	out, _ := e.Run(ctx, true, e.Path(exe), s.args...)
	return matchVersion(s.ver, out)
}

func matchVersion(re *regexp.Regexp, out []byte) string {
	m := re.FindSubmatch(out)
	if len(m) < 2 {
		return ""
	}
	return cleanVersion(string(m[1]))
}

// upstreamVersion strips a package version to the program's own:
// "1:2.4.62-1~deb12u2" → "2.4.62", "8.3.37-1+0~20261121.62+debian12~1.gbp" → "8.3.37".
func upstreamVersion(v string) string {
	if _, rest, ok := strings.Cut(v, ":"); ok {
		v = rest
	}
	if i := strings.IndexAny(v, "-+~"); i > 0 {
		v = v[:i]
	}
	return v
}
