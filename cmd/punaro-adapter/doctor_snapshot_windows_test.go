//go:build windows

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectMailboxDoctorSnapshotMakesPrivateDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "snapshot")
	if err := protectMailboxDoctorSnapshot(directory); err == nil {
		t.Fatal("missing snapshot directory was protected")
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectMailboxDoctorSnapshot(directory); err != nil {
		t.Fatal(err)
	}
	if !privateDoctorDirectory(directory) {
		t.Fatal("protected snapshot directory was rejected")
	}
}

func TestMailboxDoctorReadOnlyURIUsesWindowsSlashes(t *testing.T) {
	got := mailboxDoctorReadOnlyURI(`C:\Users\operator\AppData\Local\waypost\waypost.db`)
	want := "file:///C:/Users/operator/AppData/Local/waypost/waypost.db?mode=ro"
	if got != want {
		t.Fatalf("mailboxDoctorReadOnlyURI() = %q, want %q", got, want)
	}
}

func TestMailboxDoctorSnapshotIsPrivateOnWindows(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := protectMailboxDoctorSnapshot(state); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", filepath.Join(state, "waypost.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), `CREATE TABLE mailbox_fixture (value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	snapshot, err := mailboxDoctorSnapshot(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(snapshot) })
	if !privateDoctorDirectory(snapshot) {
		t.Fatal("mailbox snapshot directory is not private")
	}
	if _, err := os.Stat(filepath.Join(snapshot, "waypost.db")); err != nil {
		t.Fatal(err)
	}
}
