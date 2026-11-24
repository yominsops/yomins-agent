package inventory

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// webApps finds the sites' directories (the web servers' document roots and
// the usual places of hosting panels) and the CMS or framework in each, by
// the file that carries its version. Only the core is reported, no plugins
// or extensions.
type webApps struct{}

func (webApps) Name() string { return "webapps" }

// cms is one application and how to read its version in its directory.
type cms struct {
	name string
	file string // relative to the site directory
	// re finds the version (group 1); with several groups (Joomla), they
	// are joined with dots.
	re *regexp.Regexp
	// also must exist next to file, to tell apart applications that share
	// a file name (index.php).
	also string
}

var cmsList = []cms{
	{name: "wordpress", file: "wp-includes/version.php", re: regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)},
	{name: "joomla", file: "libraries/src/Version.php", re: regexp.MustCompile(`(?s)MAJOR_VERSION\s*=\s*(\d+);.*?MINOR_VERSION\s*=\s*(\d+);.*?PATCH_VERSION\s*=\s*(\d+);`)},
	{name: "joomla", file: "libraries/cms/version/version.php", re: regexp.MustCompile(`(?s)RELEASE\s*=\s*'([0-9.]+)';.*?DEV_LEVEL\s*=\s*'([0-9]+)';`)},
	{name: "drupal", file: "core/lib/Drupal.php", re: regexp.MustCompile(`const VERSION\s*=\s*'([^']+)'`)},
	{name: "drupal", file: "includes/bootstrap.inc", re: regexp.MustCompile(`define\('VERSION',\s*'([^']+)'\)`)},
	{name: "magento", file: "vendor/magento/magento2-base/composer.json", re: regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)},
	{name: "magento", file: "app/Mage.php", re: regexp.MustCompile(`(?s)'major'\s*=>\s*'(\d+)'.*?'minor'\s*=>\s*'(\d+)'.*?'revision'\s*=>\s*'(\d+)'.*?'patch'\s*=>\s*'(\d+)'`)},
	{name: "bitrix", file: "bitrix/modules/main/classes/general/version.php", re: regexp.MustCompile(`SM_VERSION["']\s*,\s*["']([^"']+)`)},
	{name: "opencart", file: "index.php", also: "catalog/controller", re: regexp.MustCompile(`define\('VERSION',\s*'([^']+)'\)`)},
	{name: "prestashop", file: "app/AppKernel.php", re: regexp.MustCompile(`const VERSION\s*=\s*'([^']+)'`)},
	{name: "prestashop", file: "config/settings.inc.php", re: regexp.MustCompile(`_PS_VERSION_['"]\s*,\s*'([^']+)'`)},
	{name: "nextcloud", file: "version.php", also: "occ", re: regexp.MustCompile(`\$OC_VersionString\s*=\s*'([^']+)'`)},
	{name: "phpmyadmin", file: "libraries/classes/Version.php", re: regexp.MustCompile(`VERSION\s*=\s*'([^']+)'`)},
	{name: "phpmyadmin", file: "src/Version.php", also: "libraries/constants.php", re: regexp.MustCompile(`VERSION\s*=\s*'([^']+)'`)},
	{name: "roundcube", file: "program/include/iniset.php", re: regexp.MustCompile(`RCMAIL_VERSION['"]\s*,\s*'([^']+)'`)},
	{name: "mediawiki", file: "includes/Defines.php", re: regexp.MustCompile(`MW_VERSION['"]\s*,\s*'([^']+)'`)},
	{name: "moodle", file: "version.php", also: "lib/moodlelib.php", re: regexp.MustCompile(`\$release\s*=\s*'([0-9][0-9.]*)`)},
	{name: "typo3", file: "typo3/sysext/core/Classes/Information/Typo3Version.php", re: regexp.MustCompile(`VERSION\s*=\s*'([^']+)'`)},
	{name: "dle", file: "engine/data/config.php", re: regexp.MustCompile(`'version_id'\s*=>\s*['"]?([0-9.]+)`)},
}

// frameworks are read from composer.lock.
var frameworks = map[string]string{
	"laravel/framework":      "laravel",
	"symfony/http-kernel":    "symfony",
	"yiisoft/yii2":           "yii",
	"codeigniter4/framework": "codeigniter",
	"cakephp/cakephp":        "cakephp",
	"laminas/laminas-mvc":    "laminas",
	"slim/slim":              "slim",
	"drupal/core":            "drupal",
	"magento/framework":      "magento-framework",
}

// siteBases are where hosting panels and admins usually put sites.
var siteBases = []string{
	"/var/www", "/var/www/html", "/var/www/*", "/var/www/*/*", "/var/www/*/public_html",
	"/var/www/vhosts/*/httpdocs", "/var/www/*/data/www/*", // Plesk, ISPmanager
	"/srv/www/*", "/srv/http/*", "/usr/share/nginx/html",
	"/home/*/public_html", "/home/*/www", "/home/*/www/*", "/home/*/htdocs",
	"/home/*/web/*/public_html", "/home/*/domains/*/public_html", // Vesta/Hestia, DirectAdmin
	"/usr/share/phpmyadmin", "/usr/share/roundcube",
}

// web server configurations to read document roots from.
var webConfigs = []string{
	"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*", "/etc/nginx/vhosts/*/*",
	"/etc/angie/angie.conf", "/etc/angie/http.d/*.conf", "/usr/local/nginx/conf/*.conf",
	"/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/*", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf",
	"/usr/local/apache/conf/httpd.conf", "/usr/local/lsws/conf/vhosts/*/*.conf",
}

var (
	nginxRoot   = regexp.MustCompile(`(?m)^\s*root\s+["']?([^;"'\s]+)`)
	apacheRoot  = regexp.MustCompile(`(?mi)^\s*DocumentRoot\s+["']?([^"'\s]+)`)
	lswsRoot    = regexp.MustCompile(`(?m)^\s*docRoot\s+(\S+)`)
	maxSiteDirs = 3000
)

func (webApps) Detect(_ context.Context, e *Env, r *Report) error {
	dirs, names := siteDirs(e)
	for _, d := range dirs {
		var found []Component
		if c, ok := detectCMS(e, d); ok {
			found = append(found, c)
		}
		found = append(found, composerFrameworks(e, d)...)
		if len(found) == 0 {
			continue
		}
		domains := siteDomains(e, d, names)
		for i := range found {
			found[i].Domains = domains
		}
		r.Components = append(r.Components, found...)
	}
	return nil
}

// siteDirs: the document roots, their parents (a framework's composer.lock
// sits above public/), the usual site places and one level under each
// document root (phpMyAdmin in /var/www/html/phpmyadmin).
//
// names maps a document root to the site names the configuration gives it.
func siteDirs(e *Env) ([]string, map[string][]string) {
	var roots []string
	names := map[string][]string{}
	for _, pattern := range webConfigs {
		files, _ := filepath.Glob(e.Path(pattern))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil || len(b) > maxFile {
				continue
			}
			for _, v := range vhosts(b) {
				for _, root := range v.roots {
					names[root] = append(names[root], v.names...)
				}
			}
			for _, re := range []*regexp.Regexp{nginxRoot, apacheRoot, lswsRoot} {
				for _, m := range re.FindAllSubmatch(b, -1) {
					p := string(m[1])
					// $document_root, ${VAR}, $VH_ROOT: unknown here.
					if strings.ContainsAny(p, "$%{") || !strings.HasPrefix(p, "/") {
						continue
					}
					roots = append(roots, filepath.Clean(p))
				}
			}
		}
	}
	for _, c := range e.containers {
		for _, pattern := range webConfigs {
			files, _ := filepath.Glob(filepath.Join(e.Path(c.root), pattern))
			for _, f := range files {
				b, err := os.ReadFile(f)
				if err != nil || len(b) > maxFile {
					continue
				}
				for _, v := range vhosts(b) {
					for _, root := range v.roots {
						if host := c.hostPath(root); host != "" {
							names[host] = append(names[host], v.names...)
						}
					}
				}
			}
		}
	}
	roots = append(roots, e.mounts...)
	for _, pattern := range siteBases {
		matches, _ := filepath.Glob(e.Path(pattern))
		for _, m := range matches {
			roots = append(roots, unroot(e, m))
		}
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if len(out) >= maxSiteDirs || p == "/" || p == "" {
			return
		}
		real, err := filepath.EvalSymlinks(e.Path(p))
		if err != nil {
			return
		}
		if seen[real] {
			return
		}
		st, err := os.Stat(real)
		if err != nil || !st.IsDir() {
			return
		}
		seen[real] = true
		out = append(out, p)
	}
	for _, p := range roots {
		add(p)
		if parent := filepath.Dir(p); parent != "/" && parent != "/var/www" && parent != "/home" && parent != "/srv" {
			add(parent)
		}
	}
	for _, p := range append([]string(nil), out...) {
		entries, err := os.ReadDir(e.Path(p))
		if err != nil {
			continue
		}
		n := 0
		for _, d := range entries {
			if d.IsDir() && n < 50 && !strings.HasPrefix(d.Name(), ".") {
				add(filepath.Join(p, d.Name()))
				n++
			}
		}
	}
	sort.Strings(out)
	return out, names
}

// vhost is one virtual host of a web server configuration.
type vhost struct {
	names []string // server_name, ServerName, ServerAlias
	roots []string // root, DocumentRoot
}

var (
	nginxServer     = regexp.MustCompile(`(?m)(?:^|[\s;{}])server\s*\{`)
	nginxServerName = regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
	apacheVHost     = regexp.MustCompile(`(?is)<VirtualHost[^>]*>(.*?)</VirtualHost>`)
	apacheName      = regexp.MustCompile(`(?mi)^\s*Server(?:Name|Alias)\s+(.+)$`)
	confComment     = regexp.MustCompile(`(?m)#.*$`)
)

// vhosts finds the virtual hosts of an nginx or Apache configuration file:
// nginx server { } blocks (with their location blocks) and Apache
// <VirtualHost> sections.
func vhosts(b []byte) []vhost {
	text := confComment.ReplaceAllString(string(b), "")
	var out []vhost
	roots := func(body string, res ...*regexp.Regexp) []string {
		var rs []string
		for _, re := range res {
			for _, m := range re.FindAllStringSubmatch(body, -1) {
				if p := m[1]; !strings.ContainsAny(p, "$%{") && strings.HasPrefix(p, "/") {
					rs = append(rs, filepath.Clean(p))
				}
			}
		}
		return rs
	}
	for _, loc := range nginxServer.FindAllStringIndex(text, -1) {
		start := loc[1] // just after "{"
		depth, end := 1, -1
		for i := start; i < len(text) && end < 0; i++ {
			switch text[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i
				}
			}
		}
		if end < 0 {
			continue
		}
		body := text[start:end]
		var v vhost
		for _, m := range nginxServerName.FindAllStringSubmatch(body, -1) {
			v.names = append(v.names, strings.Fields(m[1])...)
		}
		v.roots = roots(body, nginxRoot)
		if len(v.names) > 0 && len(v.roots) > 0 {
			out = append(out, v)
		}
	}
	for _, m := range apacheVHost.FindAllStringSubmatch(text, -1) {
		var v vhost
		for _, n := range apacheName.FindAllStringSubmatch(m[1], -1) {
			v.names = append(v.names, strings.Fields(n[1])...)
		}
		v.roots = roots(m[1], apacheRoot)
		if len(v.names) > 0 && len(v.roots) > 0 {
			out = append(out, v)
		}
	}
	return out
}

// panelSite finds the site name in the directories hosting panels make.
var panelSite = []*regexp.Regexp{
	regexp.MustCompile(`^/var/www/vhosts/([^/]+)/httpdocs(/|$)`),        // Plesk
	regexp.MustCompile(`^/home/[^/]+/web/([^/]+)/public_html(/|$)`),     // Vesta, Hestia
	regexp.MustCompile(`^/home/[^/]+/domains/([^/]+)/public_html(/|$)`), // DirectAdmin
	regexp.MustCompile(`^/var/www/[^/]+/data/www/([^/]+)(/|$)`),         // ISPmanager
}

var wpURL = regexp.MustCompile(`define\(\s*['"](?:WP_HOME|WP_SITEURL)['"]\s*,\s*['"](https?://[^'"]+)['"]`)

var domainRe = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z][a-z0-9-]{0,62}$`)

// maxDomains bounds the names listed for one site.
const maxDomains = 20

// siteDomains are the names a site directory is served under: from the web
// server's virtual hosts whose root is the directory or one directly in it
// (a framework's public/), from the hosting panel's directory layout and
// from WordPress's WP_HOME / WP_SITEURL.
func siteDomains(e *Env, dir string, names map[string][]string) []string {
	var all []string
	for root, ns := range names {
		if root == dir || filepath.Dir(root) == dir {
			all = append(all, ns...)
		}
	}
	for _, re := range panelSite {
		if m := re.FindStringSubmatch(dir); m != nil {
			all = append(all, m[1])
		}
	}
	for _, f := range []string{filepath.Join(dir, "wp-config.php"), filepath.Join(filepath.Dir(dir), "wp-config.php")} {
		if b, err := e.ReadFile(f, 1<<20); err == nil {
			for _, m := range wpURL.FindAllStringSubmatch(string(b), -1) {
				if u, err := url.Parse(m[1]); err == nil {
					all = append(all, u.Hostname())
				}
			}
			break
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range all {
		n = strings.ToLower(strings.TrimSuffix(strings.Trim(n, `"'`), "."))
		if seen[n] || !domainRe.MatchString(n) || len(out) >= maxDomains {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// unroot turns a path of the test root back into the server's.
func unroot(e *Env, p string) string {
	if e.Root == "" || e.Root == "/" {
		return p
	}
	rel, err := filepath.Rel(e.Root, p)
	if err != nil {
		return p
	}
	return "/" + rel
}

func detectCMS(e *Env, dir string) (Component, bool) {
	for _, c := range cmsList {
		if c.also != "" && !e.Exists(filepath.Join(dir, c.also)) {
			continue
		}
		b, err := e.ReadFile(filepath.Join(dir, c.file), 1<<20)
		if err != nil {
			continue
		}
		m := c.re.FindSubmatch(b)
		if m == nil {
			continue
		}
		parts := make([]string, 0, len(m)-1)
		for _, g := range m[1:] {
			parts = append(parts, string(g))
		}
		return Component{Kind: KindWebApp, Name: c.name, Version: cleanVersion(strings.Join(parts, ".")), Path: clean(dir, 200), Source: "file"}, true
	}
	return Component{}, false
}

type composerLock struct {
	Packages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages"`
}

func composerFrameworks(e *Env, dir string) []Component {
	b, err := e.ReadFile(filepath.Join(dir, "composer.lock"), 16<<20)
	if err != nil {
		return nil
	}
	var lock composerLock
	if json.Unmarshal(b, &lock) != nil {
		return nil
	}
	var out []Component
	for _, p := range lock.Packages {
		if name, ok := frameworks[p.Name]; ok {
			out = append(out, Component{Kind: KindFramework, Name: name, Version: cleanVersion(strings.TrimPrefix(p.Version, "v")), Path: clean(dir, 200), Source: "composer.lock"})
		}
	}
	return out
}
