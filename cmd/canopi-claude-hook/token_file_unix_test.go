//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadProtectedTokenRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if token, err := readProtectedToken(tokenPath); err != nil || string(token) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("readProtectedToken(private) = %q, %v", token, err)
	}
	// #nosec G302 -- the test deliberately creates an unsafe credential.
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedToken(tokenPath); err == nil {
		t.Fatal("readProtectedToken() accepted a shared token")
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "token-link")
	if err := os.Symlink(tokenPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedToken(linkPath); err == nil {
		t.Fatal("readProtectedToken() followed a symlink")
	}
}
