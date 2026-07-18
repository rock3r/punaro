//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsX25519KeyGuardsAcceptInstallerACLManagedPath(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "recipient.key")
	if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !safeX25519KeyParent(dirInfo) || !safeX25519KeyFile(fileInfo) {
		t.Fatal("installer ACL-managed X25519 key path was rejected")
	}
}
