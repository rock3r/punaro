//go:build windows

package embeddingprovider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadAPIKeyFileFailsClosedOnWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider-key")
	if err := os.WriteFile(path, []byte("provider-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAPIKeyFile(path); err == nil {
		t.Fatal("provider key loading unexpectedly succeeded on Windows")
	}
}
