package identity

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const agentIDFilename = "agent_id"

// Identity holds the persistent agent identifier.
type Identity struct {
	AgentID string
}

// Load reads the agent_id from stateDir/agent_id. If the file does not exist
// or is invalid, a new UUID is generated and written. If the write fails
// (e.g. read-only filesystem), the in-memory UUID is returned with a warning —
// startup is never blocked.
func Load(stateDir string) Identity {
	path := filepath.Join(stateDir, agentIDFilename)

	if id, err := readID(path); err == nil {
		return Identity{AgentID: id}
	}

	id := uuid.New().String()

	if err := writeID(path, id); err != nil {
		slog.Warn("could not persist agent_id; using ephemeral identity",
			"path", path, "error", err)
	}

	return Identity{AgentID: id}
}

// readID reads and validates the UUID from the given file path.
func readID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if _, err := uuid.Parse(id); err != nil {
		return "", errors.New("invalid UUID in agent_id file")
	}
	return id, nil
}

// writeID writes a UUID to the given path, creating parent directories as needed.
func writeID(path, id string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(id+"\n"), 0600)
}
