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
	targetName := "state.json"
	temporary := filepath.Join(directory, pinnedStateTemporaryPrefix(targetName)+"00112233445566778899aabb.tmp")
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	handle, err := os.Open(directory) // #nosec G304 -- test directory is created by t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()
	fd, err := stateFileDescriptor(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := reclaimPinnedStateTemporaries(handle, fd, targetName); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crash temporary remains: %v", err)
	}
}

func TestPinnedStateStoreReclaimsOnlyMatchingTargetTemporaries(t *testing.T) {
	directory := t.TempDir()
	firstTarget := "first.json"
	secondTarget := "second.json"
	firstTemporary := filepath.Join(directory, pinnedStateTemporaryPrefix(firstTarget)+"00112233445566778899aabb.tmp")
	secondTemporary := filepath.Join(directory, pinnedStateTemporaryPrefix(secondTarget)+"00112233445566778899aabb.tmp")
	for _, temporary := range []string{firstTemporary, secondTemporary} {
		if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	handle, err := os.Open(directory) // #nosec G304 -- test directory is created by t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()
	fd, err := stateFileDescriptor(handle)
	if err != nil {
		t.Fatal(err)
	}
	if err := reclaimPinnedStateTemporaries(handle, fd, firstTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(firstTemporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("matching crash temporary remains: %v", err)
	}
	if _, err := os.Lstat(secondTemporary); err != nil {
		t.Fatalf("other target temporary was removed: %v", err)
	}
}
