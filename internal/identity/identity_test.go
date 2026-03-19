package identity_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/yominsops/yomins-agent/internal/identity"
)

func TestLoad_GeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	id1 := identity.Load(dir)

	if _, err := uuid.Parse(id1.AgentID); err != nil {
		t.Fatalf("generated agent_id is not a valid UUID: %q", id1.AgentID)
	}

	// Second call must return the same ID (read from file).
	id2 := identity.Load(dir)
	if id1.AgentID != id2.AgentID {
		t.Errorf("agent_id changed across calls: %q vs %q", id1.AgentID, id2.AgentID)
	}
}

func TestLoad_ReadsExistingValidUUID(t *testing.T) {
	dir := t.TempDir()
	want := uuid.New().String()
	if err := os.WriteFile(filepath.Join(dir, "agent_id"), []byte(want+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	id := identity.Load(dir)
	if id.AgentID != want {
		t.Errorf("AgentID = %q, want %q", id.AgentID, want)
	}
}

func TestLoad_CorruptedFileRegenerates(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent_id"), []byte("not-a-uuid\n"), 0600); err != nil {
		t.Fatal(err)
	}

	id := identity.Load(dir)
	if _, err := uuid.Parse(id.AgentID); err != nil {
		t.Errorf("regenerated agent_id is not a valid UUID: %q", id.AgentID)
	}
}

func TestLoad_UnwritableDirectoryFallsBack(t *testing.T) {
	// Use a path that cannot be created (file used as directory).
	f, err := os.CreateTemp("", "yomins-test-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	// Pass the temp file as the state directory — MkdirAll will fail.
	id := identity.Load(f.Name())
	if _, err := uuid.Parse(id.AgentID); err != nil {
		t.Errorf("fallback agent_id is not a valid UUID: %q", id.AgentID)
	}
}
