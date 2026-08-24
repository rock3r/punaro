//go:build !windows

package canopi

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedStateStoreReclaimsCrashTemporary(t *testing.T) {
	directory := t.TempDir()
	temporary := filepath.Join(directory, ".canopi-state-00112233445566778899aabb.tmp")
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	handle, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()
	fd, err := stateFileDescriptor(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := reclaimPinnedStateTemporaries(handle, fd); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crash temporary remains: %v", err)
	}
}
