// Package logs ships log lines to the ingest server.
//
// Sources (files, the systemd journal) read lines and hand them to the
// shipper as Entries. Files are the buffer: a source only moves its saved
// position past a line once the shipper reports it delivered, so an outage
// or a restart loses nothing that is still on disk.
package logs

import "time"

// Entry is one log line on its way to the server.
type Entry struct {
	Time   time.Time         `json:"_time"`
	Msg    string            `json:"_msg"`
	Source string            `json:"source"` // what produced it: nginx, php-fpm, mysql, syslog…
	Path   string            `json:"path,omitempty"`
	Unit   string            `json:"unit,omitempty"`
	Level  string            `json:"level,omitempty"`
	Fields map[string]string `json:"-"` // parser output, flattened into the JSON object

	// ack is called once the entry has been delivered (or dropped for good),
	// so the source can save its position. Not sent.
	ack func()
}

// Levels a parser may assign. Anything else is left empty.
const (
	LevelError = "error"
	LevelWarn  = "warn"
	LevelInfo  = "info"
	LevelDebug = "debug"
)
