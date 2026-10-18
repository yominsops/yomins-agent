package logs

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Parser turns one raw line into an entry: the message, and where it can
// tell, the time, the level and a few fields worth filtering on. A parser
// never fails: what it cannot read stays in the message.
type Parser func(line string) Entry

// Parser names, as used in specs and configuration.
const (
	ParserPlain       = "plain"
	ParserSyslog      = "syslog"
	ParserNginxAccess = "nginx_access"
	ParserNginxError  = "nginx_error"
	ParserPHPFPM      = "php_fpm"
	ParserMySQL       = "mysql"
	ParserJSON        = "json"
	ParserDockerJSON  = "docker_json"
	// ParserAuto picks JSON, syslog or plain per line; for files of unknown shape.
	ParserAuto = "auto"
)

// ParserFor returns the named parser; unknown names get the plain one.
func ParserFor(name string) Parser {
	switch name {
	case ParserSyslog:
		return parseSyslog
	case ParserNginxAccess:
		return parseNginxAccess
	case ParserNginxError:
		return parseNginxError
	case ParserPHPFPM:
		return parsePHPFPM
	case ParserMySQL:
		return parseMySQL
	case ParserJSON:
		return parseJSON
	case ParserDockerJSON:
		return parseDockerJSON
	case ParserAuto:
		return parseAuto
	default:
		return parsePlain
	}
}

// now is the clock parsers resolve year-less timestamps against.
var now = time.Now

var (
	reLevelError = regexp.MustCompile(`(?i)\b(fatal|panic|emerg(ency)?|alert|crit(ical)?|err(or)?|exception|segfault)\b`)
	reLevelWarn  = regexp.MustCompile(`(?i)\b(warn(ing)?|deprecated|failed|failure|timeout|timed out|refused|denied)\b`)
)

// guessLevel reads the level from the words of a message without one.
func guessLevel(msg string) string {
	switch {
	case reLevelError.MatchString(msg):
		return LevelError
	case reLevelWarn.MatchString(msg):
		return LevelWarn
	}
	return ""
}

// normLevel maps the level words software writes to ours.
func normLevel(s string) string {
	switch strings.ToLower(strings.Trim(s, "[]: ")) {
	case "emerg", "emergency", "alert", "crit", "critical", "fatal", "panic", "error", "err", "severe":
		return LevelError
	case "warn", "warning":
		return LevelWarn
	case "notice", "info", "information", "note", "system":
		return LevelInfo
	case "debug", "trace":
		return LevelDebug
	}
	return ""
}

func parseAuto(line string) Entry {
	switch {
	case strings.HasPrefix(line, "{"):
		return parseJSON(line)
	case reSyslog.MatchString(line), reSyslogNoHost.MatchString(line):
		return parseSyslog(line)
	}
	return parsePlain(line)
}

func parsePlain(line string) Entry {
	return Entry{Msg: line, Level: guessLevel(line)}
}

// ── syslog ───────────────────────────────────────────────────────────────────

// RFC 3339 (rsyslog's default on Debian 12+) or the traditional
// "Oct 18 13:44:01", then host, then "program[pid]: message".
var reSyslog = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)|[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (\S+) ([^:\[\s]+)(?:\[(\d+)\])?: (.*)$`)

// The same without the host, as programs write their own files
// ("Oct 18 13:44:01 imap-login: Info: …", dovecot).
var reSyslogNoHost = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)|[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) ()([^:\[\s]+)(?:\[(\d+)\])?: (.*)$`)

func parseSyslog(line string) Entry {
	m := reSyslog.FindStringSubmatch(line)
	if m == nil || strings.HasSuffix(m[2], ":") {
		m = reSyslogNoHost.FindStringSubmatch(line)
	}
	if m == nil {
		return parsePlain(line)
	}
	e := Entry{Msg: line, Time: syslogTime(m[1]), Fields: map[string]string{"program": m[3]}}
	if m[4] != "" {
		e.Fields["pid"] = m[4]
	}
	e.Level = levelFromPrefix(m[5])
	if e.Level == "" {
		e.Level = guessLevel(m[5])
	}
	return e
}

// levelFromPrefix reads "Error: …" / "<warning> …" style prefixes (dovecot, postfix).
func levelFromPrefix(msg string) string {
	head, _, ok := strings.Cut(msg, ":")
	if !ok || len(head) > 12 {
		return ""
	}
	if i := strings.LastIndexByte(head, ' '); i >= 0 {
		head = head[i+1:]
	}
	return normLevel(head)
}

func syslogTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return yearless("Jan _2 15:04:05", s)
}

// yearless parses a timestamp without a year in local time, in the current
// year unless that puts it more than a day in the future (a line from
// December read in January).
func yearless(layout, s string) time.Time {
	t, err := time.ParseInLocation(layout, s, time.Local)
	if err != nil {
		return time.Time{}
	}
	n := now()
	t = t.AddDate(n.Year(), 0, 0)
	if t.After(n.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}

// ── nginx ────────────────────────────────────────────────────────────────────

// Matches "combined" and the variants that drop "- $remote_user": client,
// time, request, status, bytes; the rest of the line is kept in the message.
var reNginxAccess = regexp.MustCompile(`^(\S+) (?:\S+ \S+ )?\[([^\]]+)\] "([^"]*)" (\d{3}) (\d+|-)`)

// The yomins "full" format: "$remote_addr [$time_local] | STREAM: $host ->
// $upstream_addr | REQ: $request | STATUS: f: $status b: $upstream_status |
// SIZE: $bytes_sent/(…) | TIME: f: $request_time b: $upstream_response_time | …"
var reNginxFull = regexp.MustCompile(`^(\S+) \[([^\]]+)\] \| STREAM: (\S+) -> (\S*) \| REQ: (.*?) \| STATUS: f: (\d{3}) b: (\S*) \| SIZE: (\d+)/[^|]*\| TIME: f: ([\d.]+) b: (\S*)`)

func parseNginxAccess(line string) Entry {
	if strings.HasPrefix(line, "{") {
		return parseNginxJSON(line)
	}
	if m := reNginxFull.FindStringSubmatch(line); m != nil {
		return nginxFull(line, m)
	}
	m := reNginxAccess.FindStringSubmatch(line)
	if m == nil {
		return parsePlain(line)
	}
	e := Entry{Msg: line, Fields: map[string]string{"client_ip": m[1], "status": m[4]}}
	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2]); err == nil {
		e.Time = t
	}
	if method, rest, ok := strings.Cut(m[3], " "); ok {
		e.Fields["method"] = method
		uri, _, _ := strings.Cut(rest, " ")
		e.Fields["path"], _, _ = strings.Cut(uri, "?")
	}
	if m[5] != "-" {
		e.Fields["bytes"] = m[5]
	}
	e.Level = statusLevel(m[4])
	return e
}

func nginxFull(line string, m []string) Entry {
	e := Entry{Msg: line, Fields: map[string]string{
		"client_ip": m[1], "vhost": m[3], "status": m[6], "bytes": m[8], "request_time": m[9],
	}}
	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2]); err == nil {
		e.Time = t
	}
	for k, v := range map[string]string{"upstream": m[4], "upstream_status": m[7], "upstream_time": m[10]} {
		if v != "" && v != "-" {
			e.Fields[k] = v
		}
	}
	if method, rest, ok := strings.Cut(m[5], " "); ok {
		e.Fields["method"] = method
		uri, _, _ := strings.Cut(rest, " ")
		e.Fields["path"], _, _ = strings.Cut(uri, "?")
	}
	e.Level = statusLevel(m[6])
	return e
}

// nginxJSONFields are the keys of a JSON access log kept as fields, mapped to
// the names the text format uses.
var nginxJSONFields = map[string]string{
	"remote_addr": "client_ip", "status": "status", "request_method": "method",
	"request_uri": "path", "uri": "path", "host": "vhost", "http_host": "vhost", "server_name": "vhost",
	"request_time": "request_time", "upstream_response_time": "upstream_time",
	"upstream_status": "upstream_status", "body_bytes_sent": "bytes",
	"http_user_agent": "user_agent", "request_id": "request_id",
}

func parseNginxJSON(line string) Entry {
	var obj map[string]any
	if err := json.Unmarshal([]byte(line), &obj); err != nil {
		return parsePlain(line)
	}
	e := Entry{Msg: line, Fields: map[string]string{}}
	for k, v := range obj {
		if name, ok := nginxJSONFields[k]; ok {
			if s := fmt.Sprint(v); s != "" && s != "-" {
				e.Fields[name] = s
			}
		}
	}
	if p := e.Fields["path"]; p != "" {
		e.Fields["path"], _, _ = strings.Cut(p, "?")
	}
	if ms, ok := obj["msec"]; ok {
		if f, err := strconv.ParseFloat(fmt.Sprint(ms), 64); err == nil {
			e.Time = time.Unix(0, int64(f*1e9))
		}
	} else if ts, ok := obj["time_iso8601"].(string); ok {
		e.Time, _ = time.Parse(time.RFC3339, ts)
	}
	e.Level = statusLevel(e.Fields["status"])
	return e
}

func statusLevel(status string) string {
	switch {
	case strings.HasPrefix(status, "5"):
		return LevelError
	case strings.HasPrefix(status, "4"):
		return LevelWarn
	case status != "":
		return LevelInfo
	}
	return ""
}

// "2026/10/18 13:43:01 [error] 123#123: *45 message"
var reNginxError = regexp.MustCompile(`^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(\w+)\] (\d+)#\d+: (.*)$`)

func parseNginxError(line string) Entry {
	m := reNginxError.FindStringSubmatch(line)
	if m == nil {
		return parsePlain(line)
	}
	e := Entry{Msg: line, Level: normLevel(m[2]), Fields: map[string]string{"pid": m[3]}}
	e.Time, _ = time.ParseInLocation("2006/01/02 15:04:05", m[1], time.Local)
	return e
}

// ── PHP ──────────────────────────────────────────────────────────────────────

// php-fpm: "[18-Oct-2026 13:00:01] WARNING: [pool www] child 123 …"
// PHP errors: "[18-Oct-2026 13:00:01 Europe/Kyiv] PHP Fatal error: …"
var rePHP = regexp.MustCompile(`^\[(\d\d-[A-Z][a-z]{2}-\d{4} \d\d:\d\d:\d\d)(?: ([^\]]+))?\] (?:PHP )?([A-Za-z ]+?)(?: error)?: (.*)$`)

func parsePHPFPM(line string) Entry {
	m := rePHP.FindStringSubmatch(line)
	if m == nil {
		return parsePlain(line)
	}
	loc := time.Local
	if m[2] != "" {
		if l, err := time.LoadLocation(m[2]); err == nil {
			loc = l
		} else if m[2] == "UTC" {
			loc = time.UTC
		}
	}
	e := Entry{Msg: line}
	e.Time, _ = time.ParseInLocation("02-Jan-2006 15:04:05", m[1], loc)
	switch kind := strings.ToLower(m[3]); kind {
	case "fatal", "parse", "catchable fatal", "recoverable fatal":
		e.Level = LevelError
	case "deprecated", "strict standards":
		e.Level = LevelWarn
	default:
		e.Level = normLevel(kind)
	}
	if e.Level == "" {
		e.Level = guessLevel(m[4])
	}
	return e
}

// ── MySQL / MariaDB ──────────────────────────────────────────────────────────

// "2026-10-18 13:00:00 0 [Warning] …" (MariaDB) or
// "2026-10-18T10:00:00.123456Z 0 [Warning] [MY-010055] [Server] …" (MySQL 8).
var reMySQL = regexp.MustCompile(`^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?Z?)\s+\d+ \[(\w+)\] (.*)$`)

func parseMySQL(line string) Entry {
	m := reMySQL.FindStringSubmatch(line)
	if m == nil {
		return parsePlain(line)
	}
	e := Entry{Msg: line, Level: normLevel(m[2])}
	if strings.HasSuffix(m[1], "Z") {
		e.Time, _ = time.Parse("2006-01-02T15:04:05.999999Z", m[1])
	} else {
		e.Time, _ = time.ParseInLocation("2006-01-02 15:04:05.999999", strings.Replace(m[1], "T", " ", 1), time.Local)
	}
	return e
}

// ── JSON ─────────────────────────────────────────────────────────────────────

// parseJSON reads structured application logs: the usual keys for the
// message, time and level; other top-level scalars become fields.
func parseJSON(line string) Entry {
	var obj map[string]any
	if !strings.HasPrefix(line, "{") || json.Unmarshal([]byte(line), &obj) != nil {
		return parsePlain(line)
	}
	e := Entry{Msg: line, Fields: map[string]string{}}
	for _, k := range []string{"msg", "message", "@message", "log"} {
		if v, ok := obj[k].(string); ok {
			e.Msg = v
			delete(obj, k)
			break
		}
	}
	for _, k := range []string{"time", "ts", "timestamp", "@timestamp"} {
		if v, ok := obj[k].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
				e.Time = t
				delete(obj, k)
				break
			}
		}
	}
	for _, k := range []string{"level", "severity", "lvl", "log.level"} {
		if v, ok := obj[k].(string); ok {
			e.Level = normLevel(v)
			delete(obj, k)
			break
		}
	}
	for k, v := range obj {
		switch v := v.(type) {
		case string:
			e.Fields[k] = v
		case float64, bool:
			e.Fields[k] = fmt.Sprint(v)
		}
	}
	if e.Level == "" {
		e.Level = guessLevel(e.Msg)
	}
	return e
}

// parseDockerJSON reads Docker's json-file driver: {"log":"…\n","stream":"stderr","time":"…"}.
// The application line inside is parsed as JSON when it is JSON.
func parseDockerJSON(line string) Entry {
	var d struct {
		Log    string    `json:"log"`
		Stream string    `json:"stream"`
		Time   time.Time `json:"time"`
	}
	if json.Unmarshal([]byte(line), &d) != nil {
		return parsePlain(line)
	}
	inner := strings.TrimRight(d.Log, "\r\n")
	e := parseJSON(inner)
	if e.Time.IsZero() {
		e.Time = d.Time
	}
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	e.Fields["stream"] = d.Stream
	if e.Level == "" && d.Stream == "stderr" {
		e.Level = guessLevel(e.Msg)
	}
	return e
}
