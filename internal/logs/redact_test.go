package logs

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	r, err := NewRedactor([]string{`secret-\d+`})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"POST: login=bob&password=hunter2&remember=1":         "POST: login=bob&password=***&remember=1",
		`{"user":"bob","pass": "hunter2"}`:                    `{"user":"bob","pass": "***"}`,
		"GET /api?access_token=abc.def.ghi HTTP/1.1":          "GET /api?access_token=*** HTTP/1.1",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.x.y":      "Authorization: Bearer ***",
		"dsn mysql://app:s3cr3t@db:3306/x":                    "dsn mysql://app:***@db:3306/x",
		"card 4111 1111 1111 1111 paid":                       "card *** paid",
		"order 1234567890123 at 1792322383736":                "order 1234567890123 at 1792322383736",
		"custom secret-42 rule":                               "custom *** rule",
		"pam_unix(sshd:auth): authentication failure; rhost=": "pam_unix(sshd:auth): authentication failure; rhost=",
	}
	for in, want := range cases {
		if got := r.Redact(in); got != want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	if _, err := NewRedactor([]string{"("}); err == nil {
		t.Error("invalid pattern accepted")
	}
	if strings.Contains(r.Redact("password=x"), "x") {
		t.Error("leading key not masked")
	}
}

func TestAllowed(t *testing.T) {
	cases := map[string]bool{
		"/var/log/nginx/a.log":                   true,
		"/var/log/../../etc/shadow":              false,
		"/etc/shadow":                            false,
		"/home/kostyuk/logs/wp-cron/x.log":       true,
		"/home/kostyuk/.ssh/id_rsa":              false,
		"/var/www/site/storage/logs/laravel.log": true,
		"/var/lib/mysql/metro.err":               true,
		"/var/lib/mysql/ibdata1":                 false,
	}
	for p, want := range cases {
		if got := Allowed(p, DefaultAllow); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestIsRotatedName(t *testing.T) {
	for p, want := range map[string]bool{
		"/var/log/syslog": false, "/var/log/syslog.1": true, "/var/log/syslog.2.gz": true,
		"/var/log/x.log-20261018": true, "/var/log/php8.3-fpm.log": false, "/var/log/exim4/mainlog": false,
	} {
		if got := isRotatedName(p); got != want {
			t.Errorf("isRotatedName(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestHasDigitRun(t *testing.T) {
	for in, want := range map[string]bool{
		"4111 1111 1111 1111":  true,
		"4111-1111-1111-1111":  true,
		"id 123456789012 done": false,
		"12 34  56 78 90 12 3": false,
		"order 1234567890123":  true,
	} {
		if got := hasDigitRun(in, 13); got != want {
			t.Errorf("%q: %v", in, got)
		}
	}
}
