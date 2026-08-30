//go:build unix

package fleetconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRegularDestDoesNotFollowTmpSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "AGENTS.md")
	tmp := dest + ".punaro-tmp"
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}
	if err := writeRegularDest(dest, []byte("# fleet\n")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || string(got) != "keep\n" {
		t.Fatalf("followed tmp symlink: %q err=%v", got, err)
	}
	live, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || string(live) != "# fleet\n" {
		t.Fatalf("live=%q err=%v", live, err)
	}
}
