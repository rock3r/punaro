package main

import (
	"path/filepath"
	"testing"
)

func TestSelectedComponentPathUsesOnlyKnownCommandsAndPlatformSlot(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "operator")
	path, err := selectedComponentPath("darwin", "arm64", home, "", "punaro-enroll")
	want := filepath.Join(home, ".local", "state", "punaro-bootstrap", "current", "punaro-enroll-darwin-arm64")
	if err != nil || path != want {
		t.Fatalf("path=%q want=%q err=%v", path, want, err)
	}
	localAppData := filepath.Join(string(filepath.Separator), "Users", "operator", "AppData", "Local")
	path, err = selectedComponentPath("windows", "amd64", home, localAppData, "punaro-memory.exe")
	want = filepath.Join(localAppData, "Punaro", "bootstrap", "current", "punaro-memory-windows-amd64.exe")
	if err != nil || path != want {
		t.Fatalf("path=%q want=%q err=%v", path, want, err)
	}
	for _, invoked := range []string{"punaro-bootstrap", "punaro-keygen", "punaro-enroll;touch", ""} {
		if _, err := selectedComponentPath("linux", "amd64", home, "", invoked); err == nil {
			t.Fatalf("unknown command %q accepted", invoked)
		}
	}
}
