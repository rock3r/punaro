//go:build unix

package adapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/fleetconfig"
)

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
