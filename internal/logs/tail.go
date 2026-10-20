package logs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// MaxLineBytes caps one log line; a longer one is cut and marked.
	MaxLineBytes = 64 << 10
	// readChunk is how much one file may read per round, so a busy file
	// cannot starve the others.
	readChunk = 256 << 10
	// maxFiles bounds how many files one agent follows.
	maxFiles = 500
	// partialFlush is how long an unterminated last line waits for its newline.
	partialFlush = 5 * time.Second
	// discoverEvery spaces the glob searches for new files. Between them only
	// the followed files are checked (rotation, removal), every pass: a log
	// directory with hundreds of rotated files made the every-second globbing
	// the agent's largest cost.
	discoverEvery = 10 * time.Second
)

// FileSpec describes a group of files read the same way.
type FileSpec struct {
	Source  string   // the "source" field of every entry, e.g. "nginx"
	Globs   []string // shell globs; ** is not supported, use one level per glob
	Exclude []string // globs matched against the full path
	Parser  string   // parser name, see ParserFor
	// Container is the Docker container writing these files, when they were
	// found through its mounts.
	Container string
}

// FileSource follows the files of its specs, tail -F style: rotation (a new
// file at the same path) and truncation are handled, and reading resumes at
// the delivered position after a restart.
type FileSource struct {
	specs     []FileSpec
	allow     []string
	positions *Positions
	interval  time.Duration
	discovery time.Duration
	lastFound time.Time
	files     map[string]*tailedFile
	buf       []byte // one read buffer for all files; lines are copied out of it
	started   time.Time
	warned    map[string]bool
	denied    atomic.Int64 // files found at the last discovery that may not be read
	outside   atomic.Int64 // files found at the last discovery outside the allow list
}

type tailedFile struct {
	path    string
	spec    FileSpec
	parse   Parser
	f       *os.File
	inode   uint64
	offset  int64 // bytes read so far (start of the partial line)
	partial []byte
	partAt  time.Time
	gone    bool   // path vanished or was rotated away; drain then close
	ctr     string // the container writing it
	image   string
}

// NewFileSource builds a source over specs. allow limits which paths may be
// read at all (globs; empty allows nothing).
func NewFileSource(specs []FileSpec, allow []string, positions *Positions) *FileSource {
	return &FileSource{
		specs:     specs,
		allow:     allow,
		positions: positions,
		interval:  time.Second,
		discovery: discoverEvery,
		files:     map[string]*tailedFile{},
		warned:    map[string]bool{},
	}
}

// Name identifies the source in logs.
func (s *FileSource) Name() string { return "files" }

// Run follows the files until ctx is done, sending entries to out.
func (s *FileSource) Run(ctx context.Context, out chan<- Entry) error {
	s.started = time.Now()
	defer s.closeAll()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		s.scan()
		for _, tf := range s.sorted() {
			if err := s.read(ctx, tf, out); err != nil {
				return nil // ctx done
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Watched returns how many files are followed now.
func (s *FileSource) Watched() int { return len(s.files) }

// Denied returns how many matching files the agent may not read: a service unit
// from before v1.2.0 lacks the capability to read logs (re-run the installer).
func (s *FileSource) Denied() int { return int(s.denied.Load()) }

// Outside returns how many matching files lie outside the allow list: a path
// set in the portal that the host's YOMINS_LOG_ALLOW does not cover.
func (s *FileSource) Outside() int { return int(s.outside.Load()) }

func (s *FileSource) sorted() []*tailedFile {
	out := make([]*tailedFile, 0, len(s.files))
	for _, tf := range s.files {
		out = append(out, tf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// scan notices rotated or vanished files and, every discovery interval,
// finds the files the specs match now and opens the new ones.
func (s *FileSource) scan() {
	if time.Since(s.lastFound) >= s.discovery {
		s.lastFound = time.Now()
		s.discover()
	}
	for p, tf := range s.files {
		fi, err := os.Stat(p)
		if err != nil {
			tf.gone = true
			continue
		}
		if inodeOf(fi) != tf.inode {
			// Rotated: finish the old file, the new one is picked up by discovery.
			tf.gone = true
		}
	}
}

// discover globs the specs: new files are opened, followed ones that no
// longer match are marked gone.
func (s *FileSource) discover() {
	seen := map[string]bool{}
	denied, outside := 0, 0
	for _, spec := range s.specs {
		for _, g := range spec.Globs {
			matches, _ := filepath.Glob(g)
			for _, p := range matches {
				if seen[p] {
					continue
				}
				if _, ok := s.files[p]; ok {
					seen[p] = true
					continue
				}
				switch s.wanted(p, spec) {
				case verdictSkip:
					continue
				case verdictOutside:
					outside++
					continue
				}
				seen[p] = true
				if len(s.files) >= maxFiles {
					s.warnOnce("max-files", "logs: too many files, not following more", "limit", maxFiles)
					continue
				}
				tf, err := s.open(p, spec)
				if tf != nil {
					s.files[p] = tf
				} else if errors.Is(err, fs.ErrPermission) {
					denied++
				}
			}
		}
	}
	s.denied.Store(int64(denied))
	s.outside.Store(int64(outside))
	for p, tf := range s.files {
		if !seen[p] {
			tf.gone = true
		}
	}
}

type verdict int

const (
	verdictRead verdict = iota
	verdictSkip
	verdictOutside
)

func (s *FileSource) wanted(p string, spec FileSpec) verdict {
	if isRotatedName(p) {
		return verdictSkip
	}
	for _, ex := range spec.Exclude {
		if ok, _ := filepath.Match(ex, p); ok {
			return verdictSkip
		}
	}
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
		return verdictSkip
	}
	if !Allowed(p, s.allow) {
		s.warnOnce("allow:"+p, "logs: path not in the allowed list, skipped", "path", p)
		return verdictOutside
	}
	return verdictRead
}

func (s *FileSource) open(p string, spec FileSpec) (*tailedFile, error) {
	f, err := os.Open(p)
	if err != nil {
		s.warnOnce("open:"+p, "logs: cannot read file", "path", p, "error", err)
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	tf := &tailedFile{path: p, spec: spec, parse: parserForFile(spec.Parser, p), f: f, inode: inodeOf(fi), ctr: spec.Container}
	if spec.Parser == ParserDockerJSON {
		if c, ok := containerOfLog(p); ok {
			tf.ctr, tf.image = c.Name, c.Image
		}
	}
	switch pos, ok := s.positions.File(p); {
	case ok && pos.Inode == tf.inode && pos.Offset <= fi.Size():
		tf.offset = pos.Offset // resume
	case ok, time.Since(s.started) > 2*s.interval:
		// Rotated while we were down, or created while we run: read it all.
		tf.offset = 0
	default:
		// First sight at startup: ship what comes from now on, not the history.
		tf.offset = fi.Size()
	}
	if _, err := f.Seek(tf.offset, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	s.positions.SetFile(p, Position{Inode: tf.inode, Offset: tf.offset})
	return tf, nil
}

// read sends the complete lines added to tf since the last round. It returns
// an error only when ctx is done.
func (s *FileSource) read(ctx context.Context, tf *tailedFile, out chan<- Entry) error {
	if fi, err := tf.f.Stat(); err == nil && fi.Size() < tf.offset+int64(len(tf.partial)) {
		// Truncated in place (copytruncate): start over.
		tf.offset, tf.partial = 0, nil
		if _, err := tf.f.Seek(0, io.SeekStart); err != nil {
			return nil
		}
	}
	if s.buf == nil {
		s.buf = make([]byte, readChunk)
	}
	n, _ := io.ReadFull(tf.f, s.buf)
	data := s.buf[:n]
	if tf.partial != nil {
		data = append(tf.partial, data...)
	}
	tf.partial = nil

	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		if err := s.emit(ctx, tf, data[:i], int64(i+1), out); err != nil {
			return err
		}
		data = data[i+1:]
	}
	switch {
	case len(data) >= MaxLineBytes:
		if err := s.emit(ctx, tf, data, int64(len(data)), out); err != nil {
			return err
		}
	case len(data) > 0 && (tf.gone || (!tf.partAt.IsZero() && time.Since(tf.partAt) > partialFlush)):
		// A last line without a newline: send it once the writer is done.
		if err := s.emit(ctx, tf, data, int64(len(data)), out); err != nil {
			return err
		}
		tf.partAt = time.Time{}
	case len(data) > 0:
		// Kept across rounds, so it must not point into the shared buffer.
		tf.partial = append([]byte(nil), data...)
		if tf.partAt.IsZero() {
			tf.partAt = time.Now()
		}
	default:
		tf.partAt = time.Time{}
	}

	if tf.gone && n < readChunk && len(tf.partial) == 0 {
		tf.f.Close()
		delete(s.files, tf.path)
		// A rotated file's successor is looked for on the next pass.
		s.lastFound = time.Time{}
		if _, err := os.Stat(tf.path); err != nil {
			s.positions.Forget(tf.path)
		}
	}
	return nil
}

func (s *FileSource) emit(ctx context.Context, tf *tailedFile, line []byte, consumed int64, out chan<- Entry) error {
	tf.offset += consumed
	line = bytes.TrimRight(line, "\r")
	if len(bytes.TrimSpace(line)) == 0 {
		return nil // the next delivered line's position covers it
	}
	msg := string(line)
	if len(msg) > MaxLineBytes {
		msg = msg[:MaxLineBytes] + "…[truncated]"
	}
	e := tf.parse(msg)
	e.Source = tf.spec.Source
	e.Path = tf.path
	if tf.ctr != "" {
		if e.Fields == nil {
			e.Fields = map[string]string{}
		}
		e.Fields["container"] = tf.ctr
		if tf.image != "" {
			e.Fields["image"] = tf.image
		}
	}
	pos := Position{Inode: tf.inode, Offset: tf.offset}
	path, positions := tf.path, s.positions
	e.ack = func() { positions.SetFile(path, pos) }
	select {
	case out <- e:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *FileSource) closeAll() {
	for _, tf := range s.files {
		tf.f.Close()
	}
}

func (s *FileSource) warnOnce(key, msg string, args ...any) {
	if s.warned[key] {
		return
	}
	s.warned[key] = true
	slog.Warn(msg, args...)
}

// isRotatedName reports names logrotate leaves behind: x.log.1, x.log.2.gz,
// x.log-20261018, x.gz… They were read under their old name already.
func isRotatedName(p string) bool {
	base := filepath.Base(p)
	for _, ext := range []string{".gz", ".xz", ".bz2", ".zst", ".zip", ".old", ".bak"} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	ext := filepath.Ext(base)
	if len(ext) > 1 && isDigits(ext[1:]) {
		return true // x.log.1
	}
	if i := strings.LastIndexByte(base, '-'); i >= 0 && len(base)-i-1 == 8 && isDigits(base[i+1:]) {
		return true // x.log-20261018
	}
	return false
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
