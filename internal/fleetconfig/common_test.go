package fleetconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsDanglingCOMMON(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"AGENTS.md":                            "# fleet\n",
		"projects/punaro/AGENTS.md":            "# punaro\n",
		"projects/punaro/skills/shared/COMMON": "shared\n",
	})
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(tree); err == nil {
		t.Fatal("accepted dangling COMMON with no common/shared tree")
	}
}

func TestValidateRejectsCOMMONNextToPrivateSkill(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"AGENTS.md":                              "# fleet\n",
		"common/shared/SKILL.md":                 skillMarkdown("shared", "Shared skill."),
		"projects/punaro/AGENTS.md":              "# punaro\n",
		"projects/punaro/skills/shared/COMMON":   "shared\n",
		"projects/punaro/skills/shared/SKILL.md": skillMarkdown("shared", "Private mix."),
	})
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(tree); err == nil {
		t.Fatal("accepted COMMON next to a private skill tree")
	}
}

func TestValidateRejectsCOMMONNextToPrivateSkillData(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"AGENTS.md":                               "# fleet\n",
		"common/shared/SKILL.md":                  skillMarkdown("shared", "Shared skill."),
		"projects/punaro/AGENTS.md":               "# punaro\n",
		"projects/punaro/skills/shared/COMMON":    "",
		"projects/punaro/skills/shared/notes.txt": "private notes\n",
	})
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(tree); err == nil {
		t.Fatal("accepted COMMON next to private skill data")
	}
}

func TestValidateAcceptsCommonSkillWithNoMembers(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"AGENTS.md":                    "# fleet\n",
		"common/shared/SKILL.md":       skillMarkdown("shared", "Shared skill."),
		"common/shared/scripts/run.sh": "#!/bin/sh\necho unused\n",
	})
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(tree); err != nil {
		t.Fatalf("rejected common skill with no members: %v", err)
	}
	if tree.SkillCount() != 1 {
		t.Fatalf("skill count=%d", tree.SkillCount())
	}
}

func TestValidateCountsCommonSkillOnceTowardCap(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"AGENTS.md":                "# fleet\n",
		"projects/alpha/AGENTS.md": "# alpha\n",
		"projects/beta/AGENTS.md":  "# beta\n",
	}
	for i := 0; i < MaxSkills; i++ {
		name := skillName(i)
		files["common/"+name+"/SKILL.md"] = skillMarkdown(name, "Shared "+name+".")
		files["projects/alpha/skills/"+name+"/COMMON"] = name + "\n"
		files["projects/beta/skills/"+name+"/COMMON"] = ""
	}
	root := writeTree(t, files)
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(tree); err != nil {
		t.Fatalf("rejected 64 common skills opted in by two members: %v", err)
	}
	if tree.SkillCount() != MaxSkills {
		t.Fatalf("common skills counted more than once: %d", tree.SkillCount())
	}

	over := Tree{Files: append(append([]File(nil), tree.Files...), File{
		Path: "skills/overflow/SKILL.md",
		Data: []byte(skillMarkdown("overflow", "One past the cap.")),
	})}
	if err := Validate(over); err == nil {
		t.Fatal("accepted more than 64 skills when common members were expanded")
	}
}

func TestValidateAcceptsEmptyOrNamedCOMMON(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"AGENTS.md":                            "# fleet\n",
		"common/shared/SKILL.md":               skillMarkdown("shared", "Shared skill."),
		"projects/punaro/AGENTS.md":            "# punaro\n",
		"projects/punaro/skills/shared/COMMON": "",
		"projects/canopi/AGENTS.md":            "# canopi\n",
		"projects/canopi/skills/shared/COMMON": "shared\n",
	})
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(tree); err != nil {
		t.Fatalf("rejected valid COMMON bodies: %v", err)
	}
}

func TestValidateRejectsCOMMONBodyThatIsNotSkillName(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"AGENTS.md":                            "# fleet\n",
		"common/shared/SKILL.md":               skillMarkdown("shared", "Shared skill."),
		"projects/punaro/AGENTS.md":            "# punaro\n",
		"projects/punaro/skills/shared/COMMON": "other\n",
	})
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(tree); err == nil {
		t.Fatal("accepted COMMON body that is not empty or the skill name")
	}
}

func TestInspectRootRejectsSymlinkInCommonSkill(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "AGENTS.md"), []byte("# fleet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "common", "shared"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "common", "shared", "SKILL.md"), []byte(skillMarkdown("shared", "Shared skill.")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("SKILL.md", filepath.Join(root, "common", "shared", "link.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectRoot(root); err == nil {
		t.Fatal("accepted symlink in common skill source")
	}
}

func TestValidateRejectsReservedLiveMarkersInSource(t *testing.T) {
	t.Parallel()
	for _, marker := range []string{UserStart, UserEnd, AddendumStart, AddendumEnd, ManagedMark, TrailerStart, TrailerEnd} {
		root := writeTree(t, map[string]string{
			"AGENTS.md": "# fleet\n" + marker + "\n",
		})
		tree, err := InspectRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate(tree); err == nil {
			t.Fatalf("accepted reserved marker %q in published AGENTS.md", marker)
		}
	}
}

func TestValidateErrorOmitsSkillBody(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"AGENTS.md":                             "# fleet\n",
		"common/shared/SKILL.md":                skillMarkdown("shared", skillBodyProbe),
		"projects/punaro/AGENTS.md":             "# punaro\n",
		"projects/punaro/skills/missing/COMMON": "",
	})
	tree, err := InspectRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	err = Validate(tree)
	if err == nil {
		t.Fatal("accepted dangling COMMON")
	}
	if strings.Contains(err.Error(), skillBodyProbe) {
		t.Fatalf("validation error logged skill body: %v", err)
	}
}
