//go:build windows

package canopi

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"golang.org/x/sys/windows"
)

const emptyWindowsPersistedState = `{"revision":0,"records":[],"seen_event_ids":[]}`

func TestWindowsPersistedStateGetsExclusiveCurrentUserACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	if _, err := store.Apply(event("event", "agent", protocol.StateWorking, now)); err != nil {
		t.Fatal(err)
	}
	if !privateStateWindowsACL(path) {
		t.Fatal("persisted state does not have a protected current-user-only ACL")
	}
}

func TestWindowsPinnedWriterStaysInRenamedStateDirectory(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.json")
	store, err := OpenStore(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	renamed := filepath.Join(root, "renamed-state")
	if err := os.Rename(directory, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	if _, err := store.Apply(event("event", "agent", protocol.StateWorking, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(renamed, "state.json")); err != nil {
		t.Fatalf("persisted state was not written through the retained directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("replacement directory received persisted state: %v", err)
	}
}

func TestWindowsOpenStoreRejectsSharedStateACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(emptyWindowsPersistedState), 0o600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		t.Fatalf("current user: %v", err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("shared DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path, DefaultConfig()); err == nil {
		t.Fatal("OpenStore() accepted a state file without an exclusive current-user ACL")
	}
}

func TestWindowsOpenStoreRecoversInterruptedStateReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	if _, err := store.Apply(event("event", "agent", protocol.StateWorking, now)); err != nil {
		t.Fatal(err)
	}
	backup := stateReplacementBackup(path)
	if err := os.Link(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenStore(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if agents := recovered.Snapshot(now).Agents; len(agents) != 1 || agents[0].EventID != "event" {
		t.Fatalf("recovered agents = %#v", agents)
	}
}

func TestWindowsStateReplacementSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	for _, input := range []protocol.Event{
		event("event-a", "agent-a", protocol.StateWorking, now),
		event("event-b", "agent-b", protocol.StateDone, now.Add(time.Second)),
	} {
		if _, err := store.Apply(input); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if agents := reopened.Snapshot(now.Add(time.Second)).Agents; len(agents) != 2 {
		t.Fatalf("reopened agents = %#v", agents)
	}
}
