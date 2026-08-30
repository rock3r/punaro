//go:build !windows

package operator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedAncestorOwnershipPolicy(t *testing.T) {
	if !trustedAncestorUID(0) || !trustedAncestorUID(os.Getuid()) {
		t.Fatal("root or current user was rejected")
	}
	foreign := os.Getuid() + 1
	if foreign == 0 {
		foreign++
	}
	if trustedAncestorUID(foreign) {
		t.Fatal("foreign-owned ancestor was accepted")
	}
}

func TestTrustedProtectedFileOwnershipPolicy(t *testing.T) {
	if !trustedProtectedFileUID(os.Getuid()) {
		t.Fatal("current user was rejected")
	}
	foreign := os.Getuid() + 1
	if foreign == os.Getuid() {
		foreign++
	}
	if trustedProtectedFileUID(foreign) {
		t.Fatal("foreign-owned protected file was accepted")
	}
}

func TestTrustedProtectedFileAllowsCrashPublishedSecondLink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "published")
	if err := os.WriteFile(path, []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(directory, ".published.tmp-crash")); err != nil {
		t.Fatal(err)
	}
	if err := requireTrustedProtectedFile(path, 64); err != nil {
		t.Fatalf("complete crash-published state was rejected: %v", err)
	}
}
