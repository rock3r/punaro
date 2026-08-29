package incrementalfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileIsBoundedAndContextAware(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service")
	if err := os.WriteFile(path, []byte("[Service]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := ReadFile(t.Context(), path, 64<<10)
	if err != nil || string(body) != "[Service]\n" {
		t.Fatalf("body=%q err=%v", body, err)
	}
	if err := os.WriteFile(path, make([]byte, (64<<10)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(t.Context(), path, 64<<10); err == nil {
		t.Fatal("oversized file accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ReadFile(ctx, path, 64<<10); err == nil {
		t.Fatal("canceled file read continued")
	}
}
