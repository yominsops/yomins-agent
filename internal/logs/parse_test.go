package logs

import (
	"testing"
	"time"
)

func TestParseSyslog(t *testing.T) {
	now = func() time.Time { return time.Date(2026, 10, 18, 12, 0, 0, 0, time.Local) }
	defer func() { now = time.Now }()

	e := parseSyslog("2026-10-18T13:44:01.123456+03:00 metro sshd[1234]: error: kex_exchange_identification: Connection closed")
	if e.Fields["program"] != "sshd" || e.Fields["pid"] != "1234" || e.Level != LevelError {
		t.Errorf("rfc3339: %+v", e)
	}
	if e.Time.UTC() != time.Date(2026, 10, 18, 10, 44, 1, 123456000, time.UTC) {
		t.Errorf("time = %v", e.Time)
	}

	e = parseSyslog("Oct 18 13:44:01 metro CRON[99]: (root) CMD (run-parts /etc/cron.hourly)")
	if e.Fields["program"] != "CRON" || e.Time.Year() != 2026 || e.Level != "" {
		t.Errorf("traditional: %+v", e)
	}
	// A December line read in January belongs to last year.
	now = func() time.Time { return time.Date(2027, 1, 2, 0, 0, 0, 0, time.Local) }
	if y := parseSyslog("Dec 31 23:59:59 h p: m").Time.Year(); y != 2026 {
		t.Errorf("year = %d, want 2026", y)
	}

	e = parseSyslog("Oct 18 13:44:01 imap-login: Info: Login: user=<a@b.c>")
	if e.Fields["program"] != "imap-login" || e.Level != LevelInfo {
		t.Errorf("dovecot style: %+v", e)
	}
	if e := parseSyslog("not syslog at all, failed"); e.Level != LevelWarn || e.Fields != nil {
		t.Errorf("fallback: %+v", e)
	}
}

func TestParseNginxAccess(t *testing.T) {
	full := `51.178.38.160 [18/Oct/2026:00:00:01 +0300] | STREAM: metro.dp.ua -> unix:/var/run/php/php7.4-fpm.sock | REQ: GET /forum/?a=1 HTTP/1.1 | STATUS: f: 502 b: 502 | SIZE: 57109/(text/html; charset=UTF-8) | TIME: f: 0.137 b: 0.136 | UA: <x> | REFERER: - | LENGTH: [12]`
	e := parseNginxAccess(full)
	want := map[string]string{"client_ip": "51.178.38.160", "vhost": "metro.dp.ua", "status": "502", "method": "GET", "path": "/forum/",
		"bytes": "57109", "request_time": "0.137", "upstream_time": "0.136", "upstream_status": "502"}
	for k, v := range want {
		if e.Fields[k] != v {
			t.Errorf("full %s = %q, want %q", k, e.Fields[k], v)
		}
	}
	if e.Level != LevelError || e.Time.IsZero() {
		t.Errorf("full: level %q time %v", e.Level, e.Time)
	}

	e = parseNginxAccess(`1.2.3.4 - - [18/Oct/2026:13:00:00 +0000] "POST /login HTTP/1.1" 404 12 "-" "curl"`)
	if e.Fields["status"] != "404" || e.Fields["path"] != "/login" || e.Fields["method"] != "POST" || e.Level != LevelWarn {
		t.Errorf("combined: %+v", e)
	}
	e = parseNginxAccess(`1.2.3.4 [18/Oct/2026:13:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "ua" 0.01 0.01 200 "x.com"`)
	if e.Fields["status"] != "200" || e.Level != LevelInfo {
		t.Errorf("prom: %+v", e)
	}

	e = parseNginxAccess(`{"msec": "1792322383.736", "remote_addr": "1.1.1.1", "status": "200", "request_uri": "/a?b", "http_host": "oldmaps.com.ua", "request_time": "0.005"}`)
	if e.Fields["path"] != "/a" || e.Fields["vhost"] != "oldmaps.com.ua" || e.Time.Unix() != 1792322383 {
		t.Errorf("json: %+v", e)
	}
}

func TestParseNginxError(t *testing.T) {
	e := parseNginxError(`2026/10/18 13:43:01 [crit] 123#123: *45 connect() to unix:/run/php.sock failed`)
	if e.Level != LevelError || e.Fields["pid"] != "123" || e.Time.Hour() != 13 {
		t.Errorf("%+v", e)
	}
}

func TestParsePHPFPM(t *testing.T) {
	cases := map[string]string{
		"[18-Oct-2026 13:00:01] WARNING: [pool www] server reached pm.max_children setting (10)": LevelWarn,
		"[18-Oct-2026 13:00:01 Europe/Kyiv] PHP Fatal error:  Uncaught Error in /x.php:3":      LevelError,
		"[18-Oct-2026 13:00:01 UTC] PHP Deprecated:  Function x() is deprecated":               LevelWarn,
		"[18-Oct-2026 13:00:01] NOTICE: fpm is running, pid 1":                                 LevelInfo,
	}
	for line, want := range cases {
		e := parsePHPFPM(line)
		if e.Level != want || e.Time.IsZero() {
			t.Errorf("%q: level %q time %v, want %q", line, e.Level, e.Time, want)
		}
	}
}

func TestParseMySQL(t *testing.T) {
	e := parseMySQL("2026-10-18 13:00:00 0 [Warning] Aborted connection 12 to db: 'x'")
	if e.Level != LevelWarn || e.Time.Minute() != 0 || e.Time.Year() != 2026 {
		t.Errorf("mariadb: %+v", e)
	}
	e = parseMySQL("2026-10-18T10:00:00.123456Z 0 [ERROR] [MY-010119] [Server] Aborting")
	if e.Level != LevelError || e.Time.UTC().Hour() != 10 {
		t.Errorf("mysql8: %+v", e)
	}
}

func TestParseJSONAndDocker(t *testing.T) {
	e := parseJSON(`{"level":"warn","msg":"slow query","ts":"2026-10-18T10:00:00Z","duration_ms":1200,"ok":true,"nested":{"a":1}}`)
	if e.Msg != "slow query" || e.Level != LevelWarn || e.Fields["duration_ms"] != "1200" || e.Fields["ok"] != "true" {
		t.Errorf("json: %+v", e)
	}
	if _, ok := e.Fields["nested"]; ok {
		t.Error("nested objects are not fields")
	}
	e = parseDockerJSON(`{"log":"panic: boom\n","stream":"stderr","time":"2026-10-18T10:00:00.5Z"}`)
	if e.Msg != "panic: boom" || e.Fields["stream"] != "stderr" || e.Level != LevelError || e.Time.IsZero() {
		t.Errorf("docker: %+v", e)
	}
}

func TestParseJournalJSON(t *testing.T) {
	e, cursor, ok := parseJournalJSON([]byte(`{"__CURSOR":"s=1;i=2","__REALTIME_TIMESTAMP":"1792322383000000","MESSAGE":"Started x","PRIORITY":"6","_SYSTEMD_UNIT":"x.service","SYSLOG_IDENTIFIER":"systemd","_PID":"1"}`))
	if !ok || cursor != "s=1;i=2" || e.Unit != "x.service" || e.Level != LevelInfo || e.Time.Unix() != 1792322383 || e.Fields["program"] != "systemd" {
		t.Errorf("%+v %q %v", e, cursor, ok)
	}
	e, _, ok = parseJournalJSON([]byte(`{"__CURSOR":"c","MESSAGE":[104,105],"PRIORITY":"3"}`))
	if !ok || e.Msg != "hi" || e.Level != LevelError {
		t.Errorf("binary message: %+v", e)
	}
	if _, _, ok := parseJournalJSON([]byte(`{"MESSAGE":"no cursor"}`)); ok {
		t.Error("an entry without a cursor cannot be acknowledged")
	}
}

func TestParseAuto(t *testing.T) {
	if e := parseAuto(`{"message":"m","level":"error"}`); e.Msg != "m" || e.Level != LevelError {
		t.Errorf("json: %+v", e)
	}
	if e := parseAuto("Oct 18 13:44:01 h app[1]: hi"); e.Fields["program"] != "app" {
		t.Errorf("syslog: %+v", e)
	}
	if e := parseAuto("plain text"); e.Msg != "plain text" {
		t.Errorf("plain: %+v", e)
	}
}
