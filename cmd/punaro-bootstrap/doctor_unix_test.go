//go:build !windows

package main

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBootstrapDoctorKeysRejectFIFOBeforeOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDoctorKeys(t.Context(), path); err == nil {
		t.Fatal("FIFO doctor key set was accepted")
	}
}
