//go:build unix

package adapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/fleetconfig"
)

func TestWriteLiveFileDoesNotFollowTmpSymlink(t *testing.T) {
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
	if err := writeLiveFile(dest, []byte("# fleet\n")); err != nil {
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

func TestReconcileFleetStagingFailureKeepsLiveTree(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can write into a 0500 directory")
	}
	root := t.TempDir()
	first := fleetconfig.Tree{Files: []fleetconfig.File{{Path: "AGENTS.md", Data: []byte("# v1\n")}}}
	second := fleetconfig.Tree{Files: []fleetconfig.File{{Path: "AGENTS.md", Data: []byte("# v2\n")}}}
	if _, err := ReconcileFleet(root, first, nil, nil, "d1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReconcileFleet(root, second, nil, nil, "d2"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o500); err != nil { //nolint:gosec // G302: directory must be unwritable to fail staging.
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) }) //nolint:gosec // G302: restore directory perms after staging failure.
	third := fleetconfig.Tree{Files: []fleetconfig.File{{Path: "AGENTS.md", Data: []byte("# v3\n")}}}
	if _, err := ReconcileFleet(root, third, nil, nil, "d3"); err == nil {
		t.Fatal("staging failure was not reported")
	}
	got, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md")) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(got), "# v2") || strings.Contains(string(got), "# v3") {
		t.Fatalf("live tree was rolled back: %q err=%v", got, err)
	}
}
