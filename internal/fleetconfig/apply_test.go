package fleetconfig

import (
	"encoding/json"
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
	if got, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")); err != nil || string(got) != "# v1\n" { //nolint:gosec // G304: test fixture under t.TempDir.
		t.Fatalf("live=%q err=%v", got, err)
	}
	if err := PublishTree(root, map[string][]byte{"AGENTS.md": []byte("# v2\n")}, "d2"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")); err != nil || string(got) != "# v2\n" { //nolint:gosec // G304: test fixture under t.TempDir.
		t.Fatalf("updated=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "last-good", "AGENTS.md")); err != nil || string(got) != "# v1\n" { //nolint:gosec // G304: test fixture under t.TempDir.
		t.Fatalf("last-good=%q err=%v", got, err)
	}
	if err := RestoreLastGood(root); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")); err != nil || string(got) != "# v1\n" { //nolint:gosec // G304: test fixture under t.TempDir.
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
			body := []byte("ABCDEFGH")[n : n+1]
			body = append(body, '\n')
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
	if _, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")); err != nil { //nolint:gosec // G304: test fixture under t.TempDir.
		t.Fatal(err)
	}
}

func TestPublishTreeRecoversDisplacedLiveFromNext(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := PublishTree(root, map[string][]byte{"AGENTS.md": []byte("# v1\n")}, "d1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "current"), filepath.Join(root, "last-good.next")); err != nil {
		t.Fatal(err)
	}
	if err := PublishTree(root, map[string][]byte{"AGENTS.md": []byte("# v2\n")}, "d2"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")); err != nil || string(got) != "# v2\n" { //nolint:gosec // G304: test fixture under t.TempDir.
		t.Fatalf("live=%q err=%v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "last-good", "AGENTS.md")); err != nil || string(got) != "# v1\n" { //nolint:gosec // G304: test fixture under t.TempDir.
		t.Fatalf("last-good=%q err=%v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "last-good.next")); !os.IsNotExist(err) {
		t.Fatal("left leftover last-good.next")
	}
}

func TestPublishTreePersistsPrefixDigests(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	body := ComposeAgents([]byte("# fleet v1\n"), []byte("\nkeep\n"))
	if err := PublishTree(root, map[string][]byte{"AGENTS.md": body}, "d1"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "applied.json")) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	var state ApplyState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if state.PrefixDigests["AGENTS.md"] != DigestBytes([]byte("# fleet v1")) {
		t.Fatalf("prefix digests=%#v", state.PrefixDigests)
	}
}

func TestPublishTreeCreatesExclusiveLockFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := PublishTree(root, map[string][]byte{"AGENTS.md": []byte("# v1\n")}, "d1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "reconcile.lock")); err != nil {
		t.Fatalf("missing reconcile.lock: %v", err)
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
