//go:build darwin

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRejectsProfileWithMacOSACL(t *testing.T) {
	clearAdapterEnvironment(t)
	profile := writeInstallerProfile(t, "https://profile.example")
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))
	// #nosec G204 -- this Darwin-only test invokes the fixed system chmod path.
	command := exec.CommandContext(context.Background(), "chmod", "+a", "everyone allow read", profile)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("add ACL test fixture: %v (%s)", err, output)
	}

	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "adapter profile is unsafe") {
		t.Fatalf("ACL profile error=%v, want sanitized profile rejection", err)
	}
}
