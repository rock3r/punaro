//go:build windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
	command := exec.Command("icacls.exe", profile, "/grant", "*S-1-1-0:(R)")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("share test fixture: %v (%s)", err, output)
	}

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
	protectWindowsFixture(t, keyFile, false)
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
	protectWindowsFixture(t, configDir, true)
	protectWindowsFixture(t, keyFile, false)
	protectWindowsFixture(t, profile, false)
	return profile
}

func protectWindowsFixture(t *testing.T, path string, directory bool) {
	t.Helper()
	// Keep the fixture ACL identical to Protect-PunaroPath in install-client.ps1.
	script := `$ErrorActionPreference = 'Stop'; $path = $args[0]; $directory = [bool]::Parse($args[1]); $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User; $acl = Get-Acl -LiteralPath $path; $acl.SetAccessRuleProtection($true, $false); $acl.SetOwner($sid); if ($directory) { $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit } else { $inheritance = [System.Security.AccessControl.InheritanceFlags]::None }; $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow); $acl.SetAccessRule($rule); Set-Acl -LiteralPath $path -AclObject $acl`
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script, path, strconv.FormatBool(directory))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("protect test fixture: %v (%s)", err, output)
	}
}
