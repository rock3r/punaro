//go:build !windows

package memoryclient

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCredentialRequiresOwnerOnlyRegularSingleLinkFile(t *testing.T) {
	directory := secureTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- directory must be owner-only for this test.
		t.Fatal(err)
	}
	credential := filepath.Join(directory, "credential")
	if err := os.WriteFile(credential, []byte(testCredential+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := LoadCredential(credential)
	if err != nil || value != testCredential {
		t.Fatalf("value=%q err=%v", value, err)
	}

	if err := os.Chmod(credential, 0o640); err != nil { // #nosec G302 -- intentionally unsafe fixture verifies rejection.
		t.Fatal(err)
	}
	if _, err := LoadCredential(credential); err == nil {
		t.Fatal("group-readable credential accepted")
	}
	if err := os.Chmod(credential, 0o600); err != nil {
		t.Fatal(err)
	}

	hardlink := filepath.Join(directory, "credential-copy")
	if err := os.Link(credential, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(credential); err == nil {
		t.Fatal("multiply linked credential accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(directory, "credential-link")
	if err := os.Symlink(credential, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(symlink); err == nil {
		t.Fatal("symlink credential accepted")
	}
}

func TestLoadCredentialRejectsUnsafeParentAndMalformedValue(t *testing.T) {
	directory := secureTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- directory must be owner-only for this test.
		t.Fatal(err)
	}
	credential := filepath.Join(directory, "credential")
	if err := os.WriteFile(credential, []byte("two words"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredential(credential); err == nil {
		t.Fatal("credential whitespace accepted")
	}
	if err := os.WriteFile(credential, []byte(testCredential), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o770); err != nil { // #nosec G302 -- intentionally unsafe fixture verifies rejection.
		t.Fatal(err)
	}
	if _, err := LoadCredential(credential); err == nil {
		t.Fatal("credential beneath writable directory accepted")
	}
}

func TestLoadCredentialRejectsNoncanonicalDeviceCredential(t *testing.T) {
	directory := secureTempDir(t)
	credential := filepath.Join(directory, "credential")
	for _, value := range []string{
		"device-token",
		"11111111-1111-4111-8111-111111111111.short",
		"11111111-1111-4111-8111-111111111111." + strings.Repeat("A", 43) + "=",
		"11111111-1111-4111-8111-111111111111." + strings.Repeat("_", 43),
		"11111111-1111-4111-8111-111111111111." + strings.Repeat("A", 42) + "\x01",
	} {
		if err := os.WriteFile(credential, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCredential(credential); err == nil {
			t.Fatalf("credential %q accepted", value)
		}
	}
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- directory must be owner-only for this test.
		t.Fatal(err)
	}
	if privateCredentialPath(filepath.Join(directory, "credential")) {
		return directory
	}

	directory, err = os.MkdirTemp(".", ".memoryclient-credential-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Errorf("remove temporary credential directory: %v", err)
		}
	})
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	return directory
}
