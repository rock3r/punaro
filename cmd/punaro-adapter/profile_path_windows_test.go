//go:build windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsLoadConfigUsesInstalledProfile(t *testing.T) {
	clearAdapterEnvironment(t)
	setupWindowsProfile(t)

	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.machineID != "windows-profile-machine" {
		t.Fatalf("machine ID=%q, want Windows profile value", config.machineID)
	}
}

func TestWindowsLoadConfigRejectsSharedProfileACL(t *testing.T) {
	clearAdapterEnvironment(t)
	profile := setupWindowsProfile(t)
	setWindowsFixtureACL(t, profile, "(A;;FR;;;WD)")

	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "adapter profile is unsafe") {
		t.Fatalf("shared profile error=%v, want sanitized profile rejection", err)
	}
}

func TestWindowsLoadConfigAllowsEnvironmentWithoutProfileRoot(t *testing.T) {
	clearAdapterEnvironment(t)
	t.Setenv("LOCALAPPDATA", "")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "machine.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	protectWindowsFixture(t, keyFile)
	t.Setenv("PUNARO_ADAPTER_RELAY_URL", "https://relay.example")
	t.Setenv("PUNARO_MACHINE_ID", "environment-machine")
	t.Setenv("PUNARO_MACHINE_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("PUNARO_ATTACHED_GROUP", "group/punaro-attached")
	t.Setenv("PUNARO_ADAPTER_DATA_DIR", t.TempDir())

	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.machineID != "environment-machine" {
		t.Fatalf("machine ID=%q, want environment value", config.machineID)
	}
}

func setupWindowsProfile(t *testing.T) string {
	t.Helper()
	localAppData := t.TempDir()
	t.Setenv("LOCALAPPDATA", localAppData)
	configDir := filepath.Join(localAppData, "Punaro", "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(configDir, "machine.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(configDir, "adapter.env")
	contents := strings.Join([]string{
		"PUNARO_ADAPTER_RELAY_URL=https://relay.example",
		"PUNARO_MACHINE_ID=windows-profile-machine",
		"PUNARO_MACHINE_PRIVATE_KEY_FILE=" + keyFile,
		"PUNARO_ATTACHED_GROUP=group/punaro-attached",
		"PUNARO_ADAPTER_DATA_DIR=" + filepath.Join(localAppData, "Punaro", "state"),
		"",
	}, "\n")
	if err := os.WriteFile(profile, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	protectWindowsFixture(t, keyFile)
	protectWindowsFixture(t, profile)
	return profile
}

func protectWindowsFixture(t *testing.T, path string) {
	t.Helper()
	setWindowsFixtureACL(t, path, "")
}

func setWindowsFixtureACL(t *testing.T, path, additionalACE string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		t.Fatalf("current Windows user: %v", err)
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")" + additionalACE)
	if err != nil {
		t.Fatalf("build test ACL: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read test ACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, dacl, nil); err != nil {
		t.Fatalf("protect test fixture: %v", err)
	}
}
