//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsClientComponentLaunchersMustBeIdenticalRegularExecutables(t *testing.T) {
	root := t.TempDir()
	for _, component := range []string{"punaro-adapter.exe", "punaro-enroll.exe", "punaro-memory.exe", "punaro-trusted-attachment.exe"} {
		if err := os.WriteFile(filepath.Join(root, component), []byte("stable-launcher"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !clientComponentLaunchersMatch(t.Context(), root) {
		t.Fatal("matching Windows client component launchers rejected")
	}
	if err := os.WriteFile(filepath.Join(root, "punaro-enroll.exe"), []byte("stale-enroll"), 0o600); err != nil {
		t.Fatal(err)
	}
	if clientComponentLaunchersMatch(t.Context(), root) {
		t.Fatal("mixed Windows client component launchers accepted")
	}
}
