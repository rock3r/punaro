//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadPrivateRejectsFIFOWithoutOpeningIt(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "material")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(path, 64); err == nil {
		t.Fatal("FIFO was accepted as a private file")
	}
}

func TestRemovePrivateDoesNotPoisonACompletedEnrollmentWhenDirectorySyncFails(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "recovery")
	if err := os.WriteFile(path, []byte("journal"), 0o600); err != nil {
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

func TestWritePrivateAtomicNewDoesNotReplaceExistingDestination(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDir(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "credential")
	if err := writePrivateNew(path, []byte("original\n")); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateAtomicNew(path, []byte("replacement\n")); err == nil {
		t.Fatal("atomic new publication replaced an existing destination")
	}
	raw, err := readPrivate(path, 64)
	if err != nil || string(raw) != "original\n" {
		t.Fatalf("destination err=%v raw=%q", err, raw)
	}
}
