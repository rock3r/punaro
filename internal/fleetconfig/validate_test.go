package fleetconfig

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestInspectRootAcceptsGlobalAgentsAndProjectSkills(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"AGENTS.md":                      "# fleet\n",
		"skills/demo/SKILL.md":           skillMarkdown("demo", "A bounded demo skill."),
		"skills/demo/scripts/run.sh":     "#!/bin/sh\necho unused\n",
		"projects/punaro/AGENTS.md":      "# punaro\n",
		"projects/canopi/AGENTS.md":      "# canopi\n",
		"projects/canopi/skills/x/SKILL.md": skillMarkdown("x", "Project skill."),
	})
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(tree); err != nil {
		t.Fatal(err)
	}
	if tree.SkillCount() != 2 {
		t.Fatalf("skill count=%d", tree.SkillCount())
	}
	if !tree.HasProject("punaro") || !tree.HasProject("canopi") {
		t.Fatalf("projects=%v", tree.Projects())
	}
	for _, file := range tree.Files {
		if strings.Contains(string(file.Data), TrailerStart) || strings.Contains(string(file.Data), TrailerEnd) {
			t.Fatal("trailer text entered the inspected source tree")
		}
	}
}

func TestInspectRootRejectsTrailerMarkersInSourceAgents(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"AGENTS.md": "# fleet\n" + TrailerStart + "\nlocal\n" + TrailerEnd + "\n",
	})
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(tree); err == nil {
		t.Fatal("accepted trailer markers in fleet source")
	}
}

func TestInspectRootRejectsUnsafeLayout(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"missing agents", map[string]string{"skills/demo/SKILL.md": skillMarkdown("demo", "Demo.")}},
		{"unknown top-level", map[string]string{"AGENTS.md": "# fleet\n", "README.md": "nope\n"}},
		{"malformed skill name", map[string]string{
			"AGENTS.md":            "# fleet\n",
			"skills/demo/SKILL.md": skillMarkdown("other", "Name mismatch."),
		}},
		{"missing skill description", map[string]string{
			"AGENTS.md":            "# fleet\n",
			"skills/demo/SKILL.md": "---\nname: demo\n---\n# Demo\n",
		}},
		{"nested project outside projects", map[string]string{
			"AGENTS.md":             "# fleet\n",
			"nested/punaro/AGENTS.md": "# nested\n",
		}},
		{"uppercase project", map[string]string{
			"AGENTS.md":                 "# fleet\n",
			"projects/Punaro/AGENTS.md": "# p\n",
		}},
		{"nul in agents", map[string]string{"AGENTS.md": "ok\x00nope"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := writeTree(t, tc.files)
			tree, err := InspectRoot(root)
			if err == nil {
				err = Validate(tree)
			}
			if err == nil {
				t.Fatal("accepted invalid tree")
			}
		})
	}
}

func TestInspectRootRejectsSymlinkAndTraversalNames(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "AGENTS.md"), []byte("# fleet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "skills", "demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "skills", "demo", "SKILL.md"), []byte(skillMarkdown("demo", "Demo.")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("SKILL.md", filepath.Join(root, "skills", "demo", "link.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRoot(root); err == nil {
		t.Fatal("accepted symlink")
	}

	escape := t.TempDir()
	if err := os.WriteFile(filepath.Join(escape, "AGENTS.md"), []byte("# fleet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(escape, "skills", "..", "outside"), 0o700); err != nil {
		t.Fatal(err)
	}
	tree, err := InspectRoot(escape)
	if err == nil {
		for _, file := range tree.Files {
			if strings.Contains(file.Path, "..") || strings.HasPrefix(file.Path, "/") {
				t.Fatalf("escaped path %q", file.Path)
			}
		}
	}
}

func TestValidateRejectsOversizedAndDuplicateCasePaths(t *testing.T) {
	t.Parallel()
	huge := strings.Repeat("a", MaxFileBytes+1)
	root := writeTree(t, map[string]string{
		"AGENTS.md": huge,
	})
	tree, err := InspectRoot(root)
	if err == nil {
		err = Validate(tree)
	}
	if err == nil {
		t.Fatal("accepted oversized file")
	}

	colliding := Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "skills/demo/SKILL.md", Data: []byte(skillMarkdown("demo", "Demo."))},
		{Path: "skills/Demo/SKILL.md", Data: []byte(skillMarkdown("Demo", "Collision."))},
	}}
	if err := Validate(colliding); err == nil {
		t.Fatal("accepted case-colliding paths")
	}
}

func TestValidateRejectsAbsoluteTraversalAndDuplicatePaths(t *testing.T) {
	t.Parallel()
	agents := File{Path: "AGENTS.md", Data: []byte("# fleet\n")}
	for _, tree := range []Tree{
		{Files: []File{{Path: "/AGENTS.md", Data: []byte("# fleet\n")}}},
		{Files: []File{agents, {Path: "skills/../secret/SKILL.md", Data: []byte(skillMarkdown("secret", "Escape."))}}},
		{Files: []File{agents, {Path: "skills/demo/SKILL.md", Data: []byte(skillMarkdown("demo", "Demo."))}, {Path: "skills/demo/SKILL.md", Data: []byte(skillMarkdown("demo", "Dup."))}}},
		{Files: []File{agents, {Path: "skills/demo/SKILL.md", Data: []byte("---\nname: demo\n---\n")}}},
	} {
		if err := Validate(tree); err == nil {
			t.Fatalf("accepted %#v", tree.Files)
		}
	}
}

func TestValidateRejectsExcessiveSkillCount(t *testing.T) {
	t.Parallel()
	files := []File{{Path: "AGENTS.md", Data: []byte("# fleet\n")}}
	for i := 0; i < MaxSkills+1; i++ {
		name := skillName(i)
		files = append(files, File{
			Path: "skills/" + name + "/SKILL.md",
			Data: []byte(skillMarkdown(name, "Skill "+name+".")),
		})
	}
	if err := Validate(Tree{Files: files}); err == nil {
		t.Fatal("accepted too many skills")
	}
}

func skillName(i int) string {
	return "skill-" + strconv.Itoa(i)
}

func skillMarkdown(name, description string) string {
	return "---\nname: " + name + "\ndescription: " + description + "\n---\n# " + name + "\n"
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for path, body := range files {
		full := filepath.Join(append([]string{root}, strings.Split(path, "/")...)...)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
