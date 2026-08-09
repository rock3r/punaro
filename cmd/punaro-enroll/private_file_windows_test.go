//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectWindowsPath(path); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("DACL is not one exclusive ACE: %v", err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil {
		t.Fatalf("private ACE is unavailable: %v", err)
	}
	if !privateWindowsACL(path) {
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- SidStart is the documented flexible-array start of this test ACE's SID.
		t.Fatalf("private DACL rejected: control=%#x type=%d flags=%d mask=%#x sid=%s", control, ace.Header.AceType, ace.Header.AceFlags, ace.Mask, aceSID.String())
	}
	file := filepath.Join(path, "credential")
	if _, err := readPrivate(file, 64); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing private file error=%v", err)
	}
	if err := writePrivateNew(file, []byte("private\n")); err != nil {
		t.Fatal(err)
	}
	raw, err := readPrivate(file, 64)
	if err != nil || string(raw) != "private\n" {
		t.Fatalf("private file round trip failed: %v %q", err, raw)
	}
}

func TestReservedStateFileNameRejectsWindowsAliases(t *testing.T) {
	for _, name := range []string{redemptionJournalName, strings.ToUpper(redemptionJournalName), redemptionJournalName + ".", redemptionJournalName + " "} {
		if !reservedStateFileName(name) {
			t.Fatalf("reserved journal alias was accepted: %q", name)
		}
	}
}

func TestSafeStateChildRejectsAlternateDataStreams(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if safeStateChild(directory, filepath.Join(directory, "credential:stream")) {
		t.Fatal("alternate-data-stream credential path was accepted")
	}
}

func TestEnsurePrivateDirRejectsExistingUnsafeDirectoryWithoutChangingIt(t *testing.T) {
	directory := t.TempDir()
	if privateWindowsACL(directory) {
		t.Skip("temporary directory is already private")
	}
	if err := ensurePrivateDir(directory); err == nil {
		t.Fatal("existing directory with inherited ACL was accepted")
	}
	if privateWindowsACL(directory) {
		t.Fatal("existing directory ACL was changed")
	}
}

func TestEnsurePrivateDirProtectsOnlyNewNestedDirectories(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "new", "nested", "state")
	if err := ensurePrivateDir(directory); err != nil {
		t.Fatalf("ensure private state directory: %v", err)
	}
	if !privateWindowsACL(directory) {
		t.Fatal("new state directory is not private")
	}
}

func TestSyncPrivateDirectoryFlushesMetadata(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDir(directory); err != nil {
		t.Fatal(err)
	}
	if err := syncPrivateDirectory(directory); err != nil {
		t.Fatalf("flush private directory metadata: %v", err)
	}
}

func TestRemovePrivateDoesNotReportFailureAfterSuccessfulUnlink(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "recovery")
	if err := writePrivateNew(path, []byte("journal")); err != nil {
		t.Fatal(err)
	}
	original := syncPrivateDirectory
	syncPrivateDirectory = func(string) error { return errors.New("directory sync failed") }
	t.Cleanup(func() { syncPrivateDirectory = original })
	if err := removePrivate(path); err != nil {
		t.Fatalf("successful unlink reported as failure: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery file remains after unlink: %v", err)
	}
}

func TestEnsurePrivateDirRemovesNewDirectoryWhenACLProtectionFails(t *testing.T) {
	original := protectWindowsPath
	protectWindowsPath = func(string) error { return errors.New("ACL failure") }
	t.Cleanup(func() { protectWindowsPath = original })
	directory := filepath.Join(t.TempDir(), "new-state")
	if err := ensurePrivateDir(directory); err == nil {
		t.Fatal("ACL protection failure was accepted")
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed directory remains: %v", err)
	}
}
