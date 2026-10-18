package logs

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Position is how far a file has been delivered.
type Position struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// Positions remembers per file (and the journal cursor) what has been
// delivered, and persists it in the state directory so a restart resumes
// where the last run stopped.
type Positions struct {
	mu      sync.Mutex
	path    string
	Files   map[string]Position `json:"files"`
	Journal string              `json:"journal_cursor,omitempty"`
	dirty   bool
}

// LoadPositions reads the saved positions; a missing or broken file starts empty.
func LoadPositions(stateDir string) *Positions {
	p := &Positions{Files: map[string]Position{}}
	if stateDir == "" {
		return p
	}
	p.path = filepath.Join(stateDir, "log_positions.json")
	b, err := os.ReadFile(p.path)
	if err != nil {
		return p
	}
	if err := json.Unmarshal(b, p); err != nil {
		slog.Warn("logs: saved positions unreadable, starting from the end of each file", "error", err)
		p.Files = map[string]Position{}
		p.Journal = ""
	}
	if p.Files == nil {
		p.Files = map[string]Position{}
	}
	return p
}

// File returns the delivered position of path, if any.
func (p *Positions) File(path string) (Position, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pos, ok := p.Files[path]
	return pos, ok
}

// SetFile records the delivered position of path.
func (p *Positions) SetFile(path string, pos Position) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Files[path] != pos {
		p.Files[path] = pos
		p.dirty = true
	}
}

// Forget drops a file that no longer exists.
func (p *Positions) Forget(path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.Files[path]; ok {
		delete(p.Files, path)
		p.dirty = true
	}
}

// JournalCursor returns the cursor of the last delivered journal entry.
func (p *Positions) JournalCursor() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Journal
}

// SetJournalCursor records the cursor of the last delivered journal entry.
func (p *Positions) SetJournalCursor(c string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Journal != c {
		p.Journal = c
		p.dirty = true
	}
}

// Save writes the positions if they changed, atomically.
func (p *Positions) Save() error {
	p.mu.Lock()
	if !p.dirty || p.path == "" {
		p.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(p)
	p.dirty = false
	p.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}
