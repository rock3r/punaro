//go:build !windows

package canopi

import (
	"os"
	"path/filepath"
	"testing"
)

const emptyPersistedState = `{"revision":0,"records":[],"seen_event_ids":[]}`

func TestOpenStoreRejectsUnprotectedAndLinkedStateFiles(t *testing.T) {
	unsafePath := filepath.Join(t.TempDir(), "state.json")
	// #nosec G306 -- deliberately shared permissions verify fail-closed loading.
	if err := os.WriteFile(unsafePath, []byte(emptyPersistedState), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafePath, 0o644); err != nil { // #nosec G302 -- deliberately unsafe test fixture.
		t.Fatal(err)
	}
	if _, err := OpenStore(unsafePath, DefaultConfig()); err == nil {
		t.Fatal("OpenStore() accepted a world-readable state file")
	}

	privatePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(privatePath, []byte(emptyPersistedState), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(t.TempDir(), "state-link.json")
	if err := os.Symlink(privatePath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(linkPath, DefaultConfig()); err == nil {
		t.Fatal("OpenStore() accepted a symlinked state file")
	}

	hardlinkPath := filepath.Join(t.TempDir(), "state-hardlink.json")
	if err := os.Link(privatePath, hardlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(privatePath, DefaultConfig()); err == nil {
		t.Fatal("OpenStore() accepted a multiply-linked state file")
	}
}

func TestOpenStoreRequiresAbsoluteCleanStatePath(t *testing.T) {
	if _, err := OpenStore("relative-state.json", DefaultConfig()); err == nil {
		t.Fatal("OpenStore() accepted a relative state path")
	}
}
