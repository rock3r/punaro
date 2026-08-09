//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsProfileRequiresExclusiveDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory-profile.json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := protectWindowsPath(path); err != nil {
		t.Fatal(err)
	}
	if !privateProfilePath(path) || !privateProfileFilePath(path) {
		t.Fatal("exclusive profile was rejected")
	}
	setMemoryProfileACL(t, path, "(A;;FR;;;WD)")
	if privateProfileFilePath(path) {
		t.Fatal("shared profile ACL was accepted")
	}
}

func TestWindowsProfileWriteAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "memory-profile.json")
	value := profile{Origin: "https://memory.example.test", CredentialFile: filepath.Join(filepath.Dir(path), "device.credential")}
	if err := saveProfile(path, value); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadProfile(path)
	if err != nil || loaded.Origin != value.Origin || loaded.CredentialFile != value.CredentialFile {
		t.Fatalf("profile=%#v err=%v", loaded, err)
	}
}

func TestWindowsProfileRejectsCaseInsensitiveCredentialAlias(t *testing.T) {
	profile := `C:\Punaro\DEVICE.CREDENTIAL`
	credential := `c:\punaro\device.credential`
	if !sameCleanProfilePath(profile, credential) {
		t.Fatal("Windows case-insensitive credential alias was not detected")
	}
}

func setMemoryProfileACL(t *testing.T, path, additionalACE string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil {
		t.Fatalf("current user: %v", err)
	}
	sid := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")" + additionalACE)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, user.User.Sid, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}
