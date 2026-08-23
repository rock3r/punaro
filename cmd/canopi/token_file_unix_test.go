//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTokenRequiresPrivateRegularFile(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if token, err := loadToken(tokenPath); err != nil || token != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("loadToken(private) = %q, %v", token, err)
	}
	// #nosec G302 -- the test deliberately creates an unsafe token to verify rejection.
	if err := os.Chmod(tokenPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadToken(tokenPath); err == nil {
		t.Fatal("loadToken() accepted a group/world-readable token")
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "token-link")
	if err := os.Symlink(tokenPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadToken(linkPath); err == nil {
		t.Fatal("loadToken() followed a symlink")
	}
}
