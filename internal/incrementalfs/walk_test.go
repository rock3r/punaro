package incrementalfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestWalkHonorsEntryBoundAndCancellation(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := range 64 {
		name := filepath.Join(nested, fmt.Sprintf("entry-%02d", index))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	visited := 0
	if err := Walk(t.Context(), root, 8, func(_ string, _ string, _ os.FileInfo) error {
		visited++
		return nil
	}); err == nil || visited != 8 {
		t.Fatalf("bounded walk visited=%d err=%v", visited, err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := Walk(ctx, root, 65, func(_ string, _ string, _ os.FileInfo) error { return nil }); err == nil {
		t.Fatal("canceled walk continued")
	}
}
