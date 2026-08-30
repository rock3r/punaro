package fleetconfig

import (
	"strings"
	"testing"
)

func TestPrepareApplyPreservesTrailerAndSkipsCollisions(t *testing.T) {
	t.Parallel()
	tree := Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# global\n")},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro\n")},
		{Path: "skills/demo/SKILL.md", Data: []byte(skillMarkdown("demo", "Demo skill."))},
	}}
	existing := map[string][]byte{
		"AGENTS.md":                 ComposeAgents([]byte("# global\n"), []byte("\nlocal trailer\n")),
		"projects/punaro/AGENTS.md": []byte("unmanaged"),
	}
	files, trailers, err := PrepareApply(tree, existing, map[string]string{"AGENTS.md": DigestBytes([]byte("# global"))})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(files["AGENTS.md"]), "local trailer") {
		t.Fatalf("global trailer lost: %s", files["AGENTS.md"])
	}
	if _, ok := files["projects/punaro/AGENTS.md"]; ok {
		t.Fatal("overwrote unmanaged project AGENTS.md")
	}
	if !trailers["projects/punaro/AGENTS.md"].Collision {
		t.Fatalf("collision=%#v", trailers)
	}
	if _, ok := files["skills/demo/SKILL.md"]; !ok {
		t.Fatal("skill data dropped")
	}
}
