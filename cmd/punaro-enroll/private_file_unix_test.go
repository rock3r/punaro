//go:build !windows

package main

import (
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
