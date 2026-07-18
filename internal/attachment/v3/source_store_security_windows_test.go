//go:build windows

package v3

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsSourceStoreGuardsAcceptInstallerACLManagedPath(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "source.db")
	if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateSourceStoreParent(directory); err != nil {
		t.Fatal(err)
	}
	if err := validateSourceStoreFile(path, "invalid source database"); err != nil {
		t.Fatal(err)
	}
}
