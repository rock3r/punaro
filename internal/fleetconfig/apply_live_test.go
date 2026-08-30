package fleetconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	skillBodyProbe       = "unique-skill-body-probe"
	addendumBodyProbe    = "unique-addendum-body-probe"
	userBodyProbe        = "unique-user-body-probe"
	claudeAddendumProbe  = "unique-claude-addendum-probe"
	globalAddendumProbe  = "unique-global-addendum-probe"
	projectAddendumProbe = "unique-project-addendum-probe"
)

func TestApplyLiveSkipsCommonSkillWhenMemberProjectMissing(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	root := t.TempDir()
	tree := commonMemberTree(skillMarkdown("shared", skillBodyProbe), false)
	result, err := ApplyLive(ApplyLiveRequest{
		Tree:    tree,
		Root:    root,
		Home:    home,
		Matches: []ProjectMatch{{Name: "punaro", Kind: "unmatched"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Drift {
		t.Fatalf("missing member reported drift: %#v", result)
	}
	if _, err := os.Lstat(filepath.Join(home, "src", "punaro", ".agents", "skills", "shared", "SKILL.md")); !os.IsNotExist(err) {
		t.Fatal("copied common skill onto an absent member project")
	}
	assertCommonSkillAbsentFromHomeAgents(t, home)
}

func TestApplyLiveReportsUnmanagedDestCollisionWithoutOverwrite(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	project := filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	unmanaged := []byte("unmanaged-dest-bytes-keep\n")
	dest := filepath.Join(project, "AGENTS.md")
	if err := os.WriteFile(dest, unmanaged, 0o600); err != nil {
		t.Fatal(err)
	}
	skillDestDir := filepath.Join(project, ".agents", "skills", "shared")
	if err := os.MkdirAll(skillDestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	skillDest := filepath.Join(skillDestDir, "SKILL.md")
	if err := os.WriteFile(skillDest, []byte("unmanaged-skill-keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := commonMemberTree(skillMarkdown("shared", skillBodyProbe), false)
	result, err := ApplyLive(ApplyLiveRequest{
		Tree:    tree,
		Root:    t.TempDir(),
		Home:    home,
		Matches: []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Drift {
		t.Fatal("unmanaged dest collision did not report drift")
	}
	if !result.Collisions["projects/punaro/AGENTS.md"] {
		t.Fatalf("missing AGENTS collision: %#v", result.Collisions)
	}
	got, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !bytes.Equal(got, unmanaged) {
		t.Fatalf("overwrote unmanaged AGENTS.md: %q err=%v", got, err)
	}
	gotSkill, err := os.ReadFile(skillDest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || string(gotSkill) != "unmanaged-skill-keep\n" {
		t.Fatalf("overwrote unmanaged skill dest: %q err=%v", gotSkill, err)
	}
	if _, err := os.Lstat(filepath.Join(skillDestDir, "scripts", "run.sh")); !os.IsNotExist(err) {
		t.Fatal("copied nested skill file into an unmanaged skill tree")
	}
	if IsManagedDir(skillDestDir) {
		t.Fatal("marked an unmanaged skill directory as managed")
	}
	if result.Collisions["projects/punaro/skills/shared/scripts/run.sh"] != true {
		t.Fatalf("nested unmanaged skill file was not a collision: %#v", result.Collisions)
	}
}

func TestApplyLiveNestedSkillFileBeforeSkillMarkdownStillCopies(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	project := filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	tree := commonMemberTree(skillMarkdown("shared", skillBodyProbe), false)
	if _, err := ApplyLive(ApplyLiveRequest{
		Tree:    tree,
		Root:    t.TempDir(),
		Home:    home,
		Matches: []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}},
	}); err != nil {
		t.Fatal(err)
	}
	skillRoot := filepath.Join(project, ".agents", "skills", "shared")
	skillDest := filepath.Join(skillRoot, "SKILL.md")
	nested := filepath.Join(skillRoot, "scripts", "run.sh")
	assertRegularCopiedSkill(t, nested)
	assertRegularCopiedSkill(t, skillDest)
	if !IsManagedDir(skillRoot) {
		t.Fatal("skill root is not marked managed after nested-file-first copy")
	}
	if IsManagedDir(filepath.Join(skillRoot, "scripts")) {
		t.Fatal("marked nested parent instead of the skills/<name> root")
	}
	body, err := os.ReadFile(skillDest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(body), skillBodyProbe) {
		t.Fatalf("SKILL.md missing after nested copy: %q err=%v", body, err)
	}
}

func TestApplyLiveCopiesCommonSkillAsRegularFileOnPOSIX(t *testing.T) {
	t.Parallel()
	home, project, dest, _ := applyCopiedCommonSkill(t, skillMarkdown("shared", skillBodyProbe), nil)
	assertRegularCopiedSkill(t, dest)
	body, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(body), skillBodyProbe) {
		t.Fatalf("dest missing published common skill: %q err=%v", body, err)
	}
	if !IsManagedContent(body) {
		t.Fatal("copied skill file is not marked managed")
	}
	skillRoot := filepath.Dir(dest)
	if !IsManagedDir(skillRoot) {
		t.Fatal("copied skill directory is not marked managed")
	}
	assertRegularCopiedSkill(t, filepath.Join(skillRoot, "scripts", "run.sh"))
	agents, err := os.ReadFile(filepath.Join(project, "AGENTS.md")) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !IsManagedContent(agents) {
		t.Fatalf("project AGENTS.md unmanaged: %q err=%v", agents, err)
	}
	claude := filepath.Join(project, "CLAUDE.md")
	assertRegularCopiedSkill(t, claude)
	claudeBody, err := os.ReadFile(claude) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !IsManagedContent(claudeBody) {
		t.Fatalf("project CLAUDE.md unmanaged: %q err=%v", claudeBody, err)
	}
	assertCommonSkillAbsentFromHomeAgents(t, home)
	if _, err := os.Lstat(filepath.Join(home, ".agents", "skills", "global-demo", "SKILL.md")); err != nil {
		t.Fatalf("global skill missing from ~/.agents/skills: %v", err)
	}
}

func TestApplyLiveRollbackRestoresCopiedSkill(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	project := filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	matches := []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}}
	v1 := commonMemberTree(skillMarkdown("shared", "copied-skill-v1"), false)
	req := ApplyLiveRequest{Tree: v1, Root: root, Home: home, Matches: matches}
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	v2 := commonMemberTree(skillMarkdown("shared", "copied-skill-v2"), false)
	req.Tree = v2
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(project, ".agents", "skills", "shared", "SKILL.md")
	got, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(got), "copied-skill-v2") {
		t.Fatalf("expected v2 dest %q err=%v", got, err)
	}
	if err := RollbackLive(req); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(got), "copied-skill-v1") || strings.Contains(string(got), "copied-skill-v2") {
		t.Fatalf("rollback did not restore copied skill: %q err=%v", got, err)
	}
	assertRegularCopiedSkill(t, dest)
}

func TestApplyLiveUnchangedReapplyKeepsLastGood(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	project := filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	matches := []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}}
	v1 := commonMemberTree(skillMarkdown("shared", "copied-skill-v1"), false)
	req := ApplyLiveRequest{Tree: v1, Root: root, Home: home, Matches: matches}
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	v2 := commonMemberTree(skillMarkdown("shared", "copied-skill-v2"), false)
	req.Tree = v2
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	req.Tree = v2
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	if err := RollbackLive(req); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(project, ".agents", "skills", "shared", "SKILL.md")
	got, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(got), "copied-skill-v1") || strings.Contains(string(got), "copied-skill-v2") {
		t.Fatalf("unchanged reapply rotated last-good: %q err=%v", got, err)
	}
}

func TestApplyLiveRemovesDroppedManagedSkill(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	project := filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	matches := []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}}
	withSkill := commonMemberTree(skillMarkdown("shared", skillBodyProbe), false)
	req := ApplyLiveRequest{Tree: withSkill, Root: root, Home: home, Matches: matches}
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(project, ".agents", "skills", "shared", "SKILL.md")
	if _, err := os.Lstat(dest); err != nil {
		t.Fatal(err)
	}
	withoutSkill := Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro\n")},
	}}
	req.Tree = withoutSkill
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dest); !os.IsNotExist(err) {
		t.Fatal("left a dropped managed skill")
	}
}

func TestApplyLiveRetainsSkillWhenNestedFileDropped(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	project := filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	matches := []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}}
	req := ApplyLiveRequest{Tree: commonMemberTree(skillMarkdown("shared", skillBodyProbe), false), Root: root, Home: home, Matches: matches}
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	skillRoot := filepath.Join(project, ".agents", "skills", "shared")
	nested := filepath.Join(skillRoot, "scripts", "run.sh")
	if _, err := os.Lstat(nested); err != nil {
		t.Fatal(err)
	}
	req.Tree = Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "common/shared/SKILL.md", Data: []byte(skillMarkdown("shared", skillBodyProbe))},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro\n")},
		{Path: "projects/punaro/skills/shared/COMMON", Data: []byte("shared\n")},
	}}
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(nested); !os.IsNotExist(err) {
		t.Fatal("left a dropped nested skill file")
	}
	skillDest := filepath.Join(skillRoot, "SKILL.md")
	got, err := os.ReadFile(skillDest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(got), skillBodyProbe) {
		t.Fatalf("dropped retained skill while pruning nested file: %q err=%v", got, err)
	}
	if !IsManagedDir(skillRoot) {
		t.Fatal("unmarked retained skill directory while pruning nested file")
	}
}

func TestApplyLiveRemovesManagedDestsWhenProjectDropped(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	punaro := filepath.Join(home, "src", "punaro")
	other := filepath.Join(home, "src", "other")
	for _, dir := range []string{punaro, other} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	withBoth := Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "common/shared/SKILL.md", Data: []byte(skillMarkdown("shared", skillBodyProbe))},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro\n")},
		{Path: "projects/punaro/skills/shared/COMMON", Data: []byte("shared\n")},
		{Path: "projects/other/AGENTS.md", Data: []byte("# other\n")},
		{Path: "projects/other/skills/shared/COMMON", Data: []byte("shared\n")},
	}}
	req := ApplyLiveRequest{
		Tree:    withBoth,
		Root:    root,
		Home:    home,
		Matches: []ProjectMatch{{Name: "punaro", Path: punaro, Kind: "matched"}, {Name: "other", Path: other, Kind: "matched"}},
	}
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	otherAgents := filepath.Join(other, "AGENTS.md")
	otherClaude := filepath.Join(other, "CLAUDE.md")
	otherSkill := filepath.Join(other, ".agents", "skills", "shared", "SKILL.md")
	for _, path := range []string{otherAgents, otherClaude, otherSkill} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("missing first-apply dest %s: %v", path, err)
		}
	}
	req.Tree = Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "common/shared/SKILL.md", Data: []byte(skillMarkdown("shared", skillBodyProbe))},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro\n")},
		{Path: "projects/punaro/skills/shared/COMMON", Data: []byte("shared\n")},
	}}
	req.Matches = []ProjectMatch{{Name: "punaro", Path: punaro, Kind: "matched"}}
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{otherAgents, otherClaude, otherSkill} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("left managed dest after project drop: %s", path)
		}
	}
	punaroAgents, err := os.ReadFile(filepath.Join(punaro, "AGENTS.md")) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !IsManagedContent(punaroAgents) {
		t.Fatalf("dropped retained project dest: %q err=%v", punaroAgents, err)
	}
}

func TestApplyLiveRollbackRemovesDestsAbsentFromLastGood(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	project := filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	matches := []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}}
	v1 := commonMemberTree(skillMarkdown("shared", "copied-skill-v1"), false)
	req := ApplyLiveRequest{Tree: v1, Root: root, Home: home, Matches: matches}
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	v2 := commonMemberTree(skillMarkdown("shared", "copied-skill-v2"), true)
	req.Tree = v2
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(home, ".agents", "skills", "global-demo", "SKILL.md")
	if _, err := os.Lstat(extra); err != nil {
		t.Fatal(err)
	}
	if err := RollbackLive(req); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(extra); !os.IsNotExist(err) {
		t.Fatal("rollback left dests absent from last-good")
	}
	dest := filepath.Join(project, ".agents", "skills", "shared", "SKILL.md")
	got, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(got), "copied-skill-v1") || strings.Contains(string(got), "copied-skill-v2") {
		t.Fatalf("rollback did not restore copied skill: %q err=%v", got, err)
	}
}

func applyCopiedCommonSkill(t *testing.T, skillBody string, addendums map[string]string) (home, project, skillDest, addendumRoot string) {
	t.Helper()
	home = t.TempDir()
	project = filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	addendumRoot = filepath.Join(home, "punaro", "addendums")
	if len(addendums) > 0 {
		writeTreeAt(t, addendumRoot, addendums)
	}
	tree := commonMemberTree(skillBody, true)
	if _, err := ApplyLive(ApplyLiveRequest{
		Tree:         tree,
		Root:         t.TempDir(),
		Home:         home,
		AddendumRoot: addendumRoot,
		Matches:      []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}},
	}); err != nil {
		t.Fatal(err)
	}
	skillDest = filepath.Join(project, ".agents", "skills", "shared", "SKILL.md")
	return home, project, skillDest, addendumRoot
}

func assertRegularCopiedSkill(t *testing.T, dest string) {
	t.Helper()
	info, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("dest %s is not a regular file mode=%v", dest, info.Mode())
	}
	if info.Mode()&os.ModeSymlink != 0 || destIsJunctionOrReparse(info) {
		t.Fatalf("dest %s is a symlink, junction, or reparse point", dest)
	}
	if _, err := os.Readlink(dest); err == nil {
		t.Fatalf("dest %s is a symlink", dest)
	}
}

func assertCommonSkillAbsentFromHomeAgents(t *testing.T, home string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(home, ".agents", "skills", "shared")); !os.IsNotExist(err) {
		t.Fatal("wrote common skill to ~/.agents/skills")
	}
}

func commonMemberTree(skillBody string, includeGlobal bool) Tree {
	files := []File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "common/shared/SKILL.md", Data: []byte(skillBody)},
		{Path: "common/shared/scripts/run.sh", Data: []byte("#!/bin/sh\necho unused\n")},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro\n")},
		{Path: "projects/punaro/skills/shared/COMMON", Data: []byte("shared\n")},
	}
	if includeGlobal {
		files = append(files, File{
			Path: "skills/global-demo/SKILL.md",
			Data: []byte(skillMarkdown("global-demo", "Global demo skill.")),
		})
	}
	return Tree{Files: files}
}

func writeTreeAt(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for path, body := range files {
		full := filepath.Join(append([]string{root}, strings.Split(path, "/")...)...)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
