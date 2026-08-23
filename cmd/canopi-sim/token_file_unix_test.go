//go:build !windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRejectsSharedTokenFileBeforeSending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	// #nosec G306 -- deliberately unsafe permissions verify fail-closed loading.
	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"--token-file", path, "--once"}, io.Discard); got != 1 {
		t.Fatalf("run() = %d, want protected-token failure 1", got)
	}
}
