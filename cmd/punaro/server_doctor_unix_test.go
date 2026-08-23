//go:build !windows

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFileDigestMatchesRejectsFIFOBeforeOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compose.operator.yaml")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := fileDigestMatches(t.Context(), path, strings.Repeat("a", 64))
	if !result.Known || result.OK {
		t.Fatalf("FIFO compose binding=%#v", result)
	}
}
