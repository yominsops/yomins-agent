package logs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"time"
)

// JournalSource follows the systemd journal through journalctl, resuming
// after the cursor of the last delivered entry. It is used where no syslog
// daemon writes the journal to files (the files are read instead there).
type JournalSource struct {
	units     []string // empty: the whole journal
	positions *Positions
	command   string
}

// NewJournalSource creates a journal source; units limits it to those units.
func NewJournalSource(units []string, positions *Positions) *JournalSource {
	return &JournalSource{units: units, positions: positions, command: "journalctl"}
}

// Name identifies the source in logs.
func (j *JournalSource) Name() string { return "journal" }

// Run follows the journal until ctx is done, restarting journalctl if it exits.
func (j *JournalSource) Run(ctx context.Context, out chan<- Entry) error {
	if _, err := exec.LookPath(j.command); err != nil {
		slog.Warn("logs: journalctl not found, journal not collected")
		return nil
	}
	wait := time.Second
	for {
		started := time.Now()
		err := j.follow(ctx, out)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) > time.Minute {
			wait = time.Second
		}
		slog.Warn("logs: journalctl exited, restarting", "error", err, "retry_in", wait)
		if !sleepCtx(ctx, wait) {
			return nil
		}
		wait = min(wait*2, 5*time.Minute)
	}
}

func (j *JournalSource) args() []string {
	args := []string{"--follow", "--output=json", "--no-pager", "--quiet"}
	if c := j.positions.JournalCursor(); c != "" {
		args = append(args, "--after-cursor="+c)
	} else {
		args = append(args, "--lines=0") // first run: from now on, not the history
	}
	for _, u := range j.units {
		args = append(args, "--unit="+u)
	}
	return args
}

func (j *JournalSource) follow(ctx context.Context, out chan<- Entry) error {
	cmd := exec.CommandContext(ctx, j.command, j.args()...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), 4*MaxLineBytes)
	for sc.Scan() {
		e, cursor, ok := parseJournalJSON(sc.Bytes())
		if !ok {
			continue
		}
		positions := j.positions
		e.ack = func() { positions.SetJournalCursor(cursor) }
		select {
		case out <- e:
		case <-ctx.Done():
			_ = cmd.Wait()
			return nil
		}
	}
	err = sc.Err()
	if werr := cmd.Wait(); err == nil {
		err = werr
	}
	return err
}

// parseJournalJSON reads one `journalctl -o json` line.
func parseJournalJSON(b []byte) (Entry, string, bool) {
	var raw map[string]any
	if json.Unmarshal(b, &raw) != nil {
		return Entry{}, "", false
	}
	cursor, _ := raw["__CURSOR"].(string)
	msg := journalString(raw["MESSAGE"])
	if cursor == "" || msg == "" {
		return Entry{}, "", false
	}
	if len(msg) > MaxLineBytes {
		msg = msg[:MaxLineBytes] + "…[truncated]"
	}
	e := Entry{Msg: msg, Source: "journal", Fields: map[string]string{}}
	if us, err := strconv.ParseInt(journalString(raw["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
		e.Time = time.UnixMicro(us)
	}
	e.Unit = journalString(raw["_SYSTEMD_UNIT"])
	if id := journalString(raw["SYSLOG_IDENTIFIER"]); id != "" {
		e.Fields["program"] = id
	}
	if pid := journalString(raw["_PID"]); pid != "" {
		e.Fields["pid"] = pid
	}
	switch journalString(raw["PRIORITY"]) {
	case "0", "1", "2", "3":
		e.Level = LevelError
	case "4":
		e.Level = LevelWarn
	case "5", "6":
		e.Level = LevelInfo
	case "7":
		e.Level = LevelDebug
	default:
		e.Level = guessLevel(msg)
	}
	return e, cursor, true
}

// journalString reads a journal field: a string, or an array of bytes for
// binary-safe values.
func journalString(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case []any:
		b := make([]byte, 0, len(v))
		for _, x := range v {
			if f, ok := x.(float64); ok {
				b = append(b, byte(f))
			}
		}
		return string(b)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}
