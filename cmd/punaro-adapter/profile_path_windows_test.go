//go:build windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsLoadConfigUsesInstalledProfile(t *testing.T) {
	clearAdapterEnvironment(t)
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
	protectWindowsFixture(t, configDir)
	protectWindowsFixture(t, keyFile)
	protectWindowsFixture(t, profile)

	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.machineID != "windows-profile-machine" {
		t.Fatalf("machine ID=%q, want Windows profile value", config.machineID)
	}
}

func protectWindowsFixture(t *testing.T, path string) {
	t.Helper()
	user := os.Getenv("USERNAME")
	if user == "" {
		t.Fatal("Windows user name is unavailable")
	}
	command := exec.Command("icacls.exe", path, "/inheritance:r", "/grant:r", user+":(F)")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("protect test fixture: %v (%s)", err, output)
	}
}
