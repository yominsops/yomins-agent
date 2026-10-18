package collector

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// CertsCollector reports the expiry of the TLS certificates the web and
// mail servers on the host are configured with, read from disk. A renewal
// that failed shows here weeks before a browser complains, including for
// names no external probe checks (mail, internal vhosts).
type CertsCollector struct {
	paths HostPaths
	globs []string
}

// DefaultCertGlobs are where server configurations and certbot keep certificates.
var DefaultCertGlobs = []string{"/etc/letsencrypt/live/*/cert.pem"}

// configGlobs are server configurations whose certificate directives are followed.
var configGlobs = []string{
	"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*",
	"/etc/apache2/sites-enabled/*", "/etc/httpd/conf.d/*.conf",
	"/etc/dovecot/conf.d/10-ssl.conf", "/etc/exim4/conf.d/main/*", "/etc/postfix/main.cf",
}

var reCertDirective = regexp.MustCompile(`(?im)^\s*(?:ssl_certificate|SSLCertificateFile|ssl_cert\s*=\s*<|smtpd_tls_cert_file\s*=|MAIN_TLS_CERTIFICATE\s*=)\s*([^\s;]+)`)

// NewCertsCollector creates the collector; extra globs add certificate files.
func NewCertsCollector(paths HostPaths, extra []string) *CertsCollector {
	return &CertsCollector{paths: paths, globs: append(append([]string{}, DefaultCertGlobs...), extra...)}
}

func (c *CertsCollector) Name() string { return "certs" }

func (c *CertsCollector) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	files := map[string]bool{}
	for _, g := range c.globs {
		m, _ := filepath.Glob(c.paths.root(g))
		for _, f := range m {
			files[f] = true
		}
	}
	for _, g := range configGlobs {
		m, _ := filepath.Glob(c.paths.root(g))
		for _, conf := range m {
			b, err := os.ReadFile(conf)
			if err != nil {
				continue
			}
			for _, sm := range reCertDirective.FindAllStringSubmatch(string(b), -1) {
				p := strings.Trim(sm[1], `"'<`)
				if filepath.IsAbs(p) && !strings.Contains(p, "$") {
					files[c.paths.root(p)] = true
				}
			}
		}
	}
	var pts []metrics.MetricPoint
	seen := map[string]bool{}
	for f := range files {
		real, err := filepath.EvalSymlinks(f)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		cert := firstCert(real)
		if cert == nil {
			continue
		}
		cn := cert.Subject.CommonName
		if cn == "" && len(cert.DNSNames) > 0 {
			cn = cert.DNSNames[0]
		}
		pts = append(pts, gauge("tls_certificate_expiry_timestamp_seconds", "When the certificate expires (Unix time)", float64(cert.NotAfter.Unix()),
			map[string]string{"path": strings.TrimPrefix(f, strings.TrimSuffix(c.paths.Root, "/")), "subject": cn, "issuer": cert.Issuer.CommonName}))
	}
	return pts, nil
}

// firstCert parses the first certificate in a PEM file (the leaf, in a chain).
func firstCert(path string) *x509.Certificate {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 1<<20 {
		return nil
	}
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil
			}
			return cert
		}
	}
}
