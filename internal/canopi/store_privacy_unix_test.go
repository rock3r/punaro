//go:build !windows

package canopi

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

func TestStateRepairLockSerializesConcurrentRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".canopi-lock-test")
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- withStateRepairLock(path, func() error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()
	<-firstEntered
	secondEntered := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- withStateRepairLock(path, func() error {
			close(secondEntered)
			return nil
		})
	}()
	select {
	case <-secondEntered:
		t.Fatal("second state-lock repair entered while the first held the directory repair lock")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second state-lock repair did not enter after the first released")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

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

func TestOpenStoreExcludesWriterThroughSymlinkedParentAlias(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	stateDirectory := filepath.Join(realDirectory, "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasDirectory := filepath.Join(root, "alias")
	if err := os.Symlink(realDirectory, aliasDirectory); err != nil {
		t.Fatal(err)
	}
	first, err := OpenStore(filepath.Join(stateDirectory, "state.json"), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := OpenStore(filepath.Join(aliasDirectory, "state", "state.json"), DefaultConfig())
	if !errors.Is(err, ErrStateStoreLocked) || second != nil {
		t.Fatalf("OpenStore() through parent alias = %#v, %v; want ErrStateStoreLocked", second, err)
	}
}

func TestOpenStorePinsPersistenceAcrossParentAliasRetarget(t *testing.T) {
	root := t.TempDir()
	firstRoot := filepath.Join(root, "first")
	secondRoot := filepath.Join(root, "second")
	for _, directory := range []string{
		filepath.Join(firstRoot, "state"),
		filepath.Join(secondRoot, "state"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "current")
	if err := os.Symlink(firstRoot, alias); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(alias, "state", "state.json"), DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if result, err := store.Apply(event("event-1", "agent", protocol.StateWorking, now)); err != nil || !result.Applied {
		t.Fatalf("first Apply() = %+v, %v", result, err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secondRoot, alias); err != nil {
		t.Fatal(err)
	}
	if result, err := store.Apply(event("event-2", "agent", protocol.StateDone, now.Add(time.Second))); err != nil || !result.Applied {
		t.Fatalf("second Apply() = %+v, %v", result, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	pinnedPath := filepath.Join(firstRoot, "state", "state.json")
	reopened, err := OpenStore(pinnedPath, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	snapshot := reopened.Snapshot(now.Add(time.Second))
	if snapshot.Revision != 2 || len(snapshot.Agents) != 1 || snapshot.Agents[0].EventID != "event-2" {
		t.Fatalf("pinned snapshot = %#v, want revision 2 with event-2", snapshot)
	}
	if _, err := os.Stat(filepath.Join(secondRoot, "state", "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retargeted state path was written: %v", err)
	}
}

func TestOpenStoreRecoversPreexistingStateLockSymlink(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	lockPath, err := stateStoreLockPath(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(lockPath), lockPath); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(statePath, DefaultConfig())
	if err != nil {
		t.Fatalf("OpenStore() did not recover planted state lock: %v", err)
	}
	defer func() { _ = store.Close() }()
	info, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !privateStateFile(lockPath, info) {
		t.Fatal("recovered state lock is not a private current-user file")
	}
}
