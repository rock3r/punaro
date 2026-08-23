//go:build !windows

package bootstrap

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDoctorRunPIDRejectsFIFOBeforeOpening(t *testing.T) {
	directory := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(directory, runPIDFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := doctorLoadRunPID(t.Context(), directory); err == nil {
		t.Fatal("FIFO run PID record was accepted")
	}
}
