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

func TestLoadTLSKeyRequiresPrivateRegularFile(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "server.key")
	if err := os.WriteFile(keyPath, []byte("private-key-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	if payload, err := loadTLSKey(keyPath); err != nil || string(payload) != "private-key-material" {
		t.Fatalf("loadTLSKey(private) = %q, %v", payload, err)
	}
	// #nosec G302 -- deliberately unsafe permissions verify rejection.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTLSKey(keyPath); err == nil {
		t.Fatal("loadTLSKey() accepted a group/world-readable key")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "server-link.key")
	if err := os.Symlink(keyPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTLSKey(linkPath); err == nil {
		t.Fatal("loadTLSKey() followed a symlink")
	}
}
