package adapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/fleetconfig"
)

func TestReconcileFleetAppliesAtomicallyAndPreservesTrailer(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	tree := fleetconfig.Tree{Files: []fleetconfig.File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "skills/demo/SKILL.md", Data: []byte("---\nname: demo\ndescription: Demo skill.\n---\n# demo\n")},
	}}
	existing := map[string][]byte{
		"AGENTS.md": fleetconfig.ComposeAgents([]byte("# old\n"), []byte("\nstay\n")),
	}
	trailers, err := ReconcileFleet(root, tree, existing, map[string]string{"AGENTS.md": fleetconfig.DigestBytes([]byte("# old"))}, "digest-1")
	if err != nil {
		t.Fatal(err)
	}
	if trailers["AGENTS.md"].Collision {
		t.Fatal("false collision")
	}
	got, err := os.ReadFile(filepath.Join(root, "current", "AGENTS.md"))
	if err != nil || !strings.Contains(string(got), "# fleet") || !strings.Contains(string(got), "stay") {
		t.Fatalf("applied=%q err=%v", got, err)
	}
}
