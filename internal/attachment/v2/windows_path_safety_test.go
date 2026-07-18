//go:build windows

package v2

import (
	"os"
	"path/filepath"
	"testing"
)

// Installer ACLs are authoritative on Windows. This regression test ensures
// normal ACL-managed local paths are not rejected by Unix-only mode checks.
func TestWindowsAttachmentPathGuardsAcceptInstallerACLManagedPath(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state")
	if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !isPrivateStateParent(dirInfo) || !safePrivateKeyParent(dirInfo) || !safeDirectorySnapshotParent(dirInfo) {
		t.Fatal("installer ACL-managed directory was rejected")
	}
	if !isPrivateStateFile(fileInfo) || !safePrivateKeyFile(fileInfo) || !safeDirectorySnapshotFile(fileInfo) {
		t.Fatal("installer ACL-managed regular file was rejected")
	}
}
