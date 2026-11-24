package inventory

import (
	"context"
	"encoding/json"
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
	dirs := siteDirs(e)
	for _, d := range dirs {
		if c, ok := detectCMS(e, d); ok {
			r.Components = append(r.Components, c)
		}
		r.Components = append(r.Components, composerFrameworks(e, d)...)
	}
	return nil
}

// siteDirs: the document roots, their parents (a framework's composer.lock
// sits above public/), the usual site places and one level under each
// document root (phpMyAdmin in /var/www/html/phpmyadmin).
func siteDirs(e *Env) []string {
	var roots []string
	for _, pattern := range webConfigs {
		files, _ := filepath.Glob(e.Path(pattern))
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil || len(b) > maxFile {
				continue
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
