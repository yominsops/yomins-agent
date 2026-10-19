package logs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// harness runs a FileSource over dir/*.log and collects what it sends,
// acknowledging each entry as a shipper would after delivery.
type harness struct {
	t         *testing.T
	dir       string
	positions *Positions
	src       *FileSource
	out       chan Entry
}

func newHarness(t *testing.T, positions *Positions) *harness {
	dir := t.TempDir()
	if positions == nil {
		positions = LoadPositions(dir)
	}
	src := NewFileSource([]FileSpec{{Source: "test", Parser: ParserPlain, Globs: []string{filepath.Join(dir, "*.log")}}}, []string{dir + "/**"}, positions)
	src.started = time.Now()
	return &harness{t: t, dir: dir, positions: positions, src: src, out: make(chan Entry, 100)}
}

// round runs one scan+read pass and returns the messages sent, acked.
func (h *harness) round() []string {
	h.t.Helper()
	h.src.scan()
	for _, tf := range h.src.sorted() {
		if err := h.src.read(context.Background(), tf, h.out); err != nil {
			h.t.Fatal(err)
		}
	}
	var msgs []string
	for {
		select {
		case e := <-h.out:
			e.ack()
			msgs = append(msgs, e.Msg)
		default:
			return msgs
		}
	}
}

func (h *harness) write(name, s string) {
	h.t.Helper()
	f, err := os.OpenFile(filepath.Join(h.dir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		h.t.Fatal(err)
	}
}

func eq(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestTail_StartsAtEndOfExistingFiles(t *testing.T) {
	h := newHarness(t, nil)
	h.write("a.log", "history\n")
	eq(t, h.round()) // first sight at startup: history is not shipped
	h.write("a.log", "one\ntwo\n")
	eq(t, h.round(), "one", "two")
}

func TestTail_NewFileWhileRunningIsReadFromStart(t *testing.T) {
	h := newHarness(t, nil)
	h.src.started = time.Now().Add(-time.Minute)
	h.write("new.log", "first\n")
	eq(t, h.round(), "first")
}

func TestTail_Rotation(t *testing.T) {
	h := newHarness(t, nil)
	h.write("a.log", "")
	h.round()
	h.write("a.log", "before\n")
	if err := os.Rename(filepath.Join(h.dir, "a.log"), filepath.Join(h.dir, "a.log.1")); err != nil {
		t.Fatal(err)
	}
	h.write("a.log", "after\n")
	h.src.started = time.Now().Add(-time.Minute)
	// The old file is drained under its open descriptor, then the new one is read from 0.
	got := append(h.round(), h.round()...)
	eq(t, got, "before", "after")
}

func TestTail_NewFilesFoundOnDiscovery(t *testing.T) {
	h := newHarness(t, nil)
	h.write("a.log", "")
	h.round()
	h.src.started = time.Now().Add(-time.Minute)
	h.write("b.log", "late\n")
	eq(t, h.round()) // no glob until the discovery interval passes
	h.src.lastFound = time.Now().Add(-discoverEvery)
	eq(t, h.round(), "late")
}

func TestTail_Truncation(t *testing.T) {
	h := newHarness(t, nil)
	h.write("a.log", "")
	h.round()
	h.write("a.log", "long line one\n")
	eq(t, h.round(), "long line one")
	if err := os.Truncate(filepath.Join(h.dir, "a.log"), 0); err != nil {
		t.Fatal(err)
	}
	h.write("a.log", "x\n")
	eq(t, h.round(), "x")
}

func TestTail_PartialLineWaitsForNewline(t *testing.T) {
	h := newHarness(t, nil)
	h.write("a.log", "")
	h.round()
	h.write("a.log", "hal")
	eq(t, h.round())
	h.write("a.log", "f\n")
	eq(t, h.round(), "half")
}

func TestTail_ResumesAtDeliveredPosition(t *testing.T) {
	h := newHarness(t, nil)
	h.write("a.log", "")
	h.round()
	h.write("a.log", "delivered\n")
	eq(t, h.round(), "delivered")
	if err := h.positions.Save(); err != nil {
		t.Fatal(err)
	}
	h.write("a.log", "while down\n")

	// A new agent process over the same state dir.
	h2 := &harness{t: t, dir: h.dir, positions: LoadPositions(h.dir), out: make(chan Entry, 100)}
	h2.src = NewFileSource(h.src.specs, h.src.allow, h2.positions)
	h2.src.started = time.Now()
	eq(t, h2.round(), "while down")
}

func TestTail_UnacknowledgedLinesAreReadAgainAfterRestart(t *testing.T) {
	h := newHarness(t, nil)
	h.write("a.log", "")
	h.round()
	h.write("a.log", "lost in flight\n")
	h.src.scan()
	for _, tf := range h.src.sorted() {
		_ = h.src.read(context.Background(), tf, h.out)
	}
	<-h.out // sent, never acknowledged
	_ = h.positions.Save()

	h2 := &harness{t: t, dir: h.dir, positions: LoadPositions(h.dir), out: make(chan Entry, 100)}
	h2.src = NewFileSource(h.src.specs, h.src.allow, h2.positions)
	h2.src.started = time.Now()
	eq(t, h2.round(), "lost in flight")
}

func TestTail_SkipsPathsOutsideAllowList(t *testing.T) {
	h := newHarness(t, nil)
	h.src.allow = []string{"/nowhere/**"}
	h.write("a.log", "")
	h.round()
	h.write("a.log", "secret\n")
	eq(t, h.round())
}

func TestTail_ParserAndSourceApplied(t *testing.T) {
	h := newHarness(t, nil)
	h.src.specs[0].Parser = ParserNginxError
	h.write("a.log", "")
	h.round()
	h.write("a.log", "2026/10/18 13:43:01 [error] 1#1: boom\n")
	h.src.scan()
	for _, tf := range h.src.sorted() {
		_ = h.src.read(context.Background(), tf, h.out)
	}
	e := <-h.out
	if e.Source != "test" || e.Level != LevelError || !strings.HasSuffix(e.Path, "a.log") {
		t.Errorf("%+v", e)
	}
}
