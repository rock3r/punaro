//go:build windows

package adapter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsOfferOutboxPathGuardsAcceptInstallerACLManagedPath(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "outbox.db")
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
	if !isPrivateOfferOutboxParent(dirInfo) || !isPrivateOfferOutboxFile(fileInfo) {
		t.Fatal("installer ACL-managed outbox path was rejected")
	}
}
