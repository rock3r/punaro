package fleetconfig

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPublishTreeIsAtomicAndKeepsLastKnownGood(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := PublishTree(root, map[string][]byte{"AGENTS.md": []byte("# v1\n")}, "d1"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")); err != nil || string(got) != "# v1\n" {
		t.Fatalf("live=%q err=%v", got, err)
	}
	if err := PublishTree(root, map[string][]byte{"AGENTS.md": []byte("# v2\n")}, "d2"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")); err != nil || string(got) != "# v2\n" {
		t.Fatalf("updated=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "last-good", "AGENTS.md")); err != nil || string(got) != "# v1\n" {
		t.Fatalf("last-good=%q err=%v", got, err)
	}
	if err := RestoreLastGood(root); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")); err != nil || string(got) != "# v1\n" {
		t.Fatalf("restored=%q err=%v", got, err)
	}
}

func TestPublishTreeSerializesConcurrentReconcile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			body := []byte{byte('A' + n), '\n'}
			errCh <- PublishTree(root, map[string][]byte{"AGENTS.md": body}, "d")
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
}

func TestPublishTreeRejectsLiveSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "other"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "other"), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := PublishTree(root, map[string][]byte{"AGENTS.md": []byte("# v1\n")}, "d1"); err == nil {
		t.Fatal("replaced a symlink live tree")
	}
}
