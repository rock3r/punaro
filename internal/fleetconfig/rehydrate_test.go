package fleetconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
)

func TestResolveAddendumProjectOverridesGlobal(t *testing.T) {
	t.Parallel()
	files := map[string][]byte{
		"AGENTS.md":                              []byte(globalAddendumProbe + "\n"),
		"projects/punaro/AGENTS.md":              []byte(projectAddendumProbe + "\n"),
		"common/shared/SKILL.md":                 []byte("global-skill-addendum\n"),
		"projects/punaro/skills/shared/SKILL.md": []byte("project-skill-addendum\n"),
	}
	got := ResolveAddendum(files, "projects/punaro/AGENTS.md")
	if !bytes.Contains(got, []byte(projectAddendumProbe)) {
		t.Fatalf("missing project addendum: %q", got)
	}
	if bytes.Contains(got, []byte(globalAddendumProbe)) {
		t.Fatalf("kept overridden global addendum: %q", got)
	}
	fallback := ResolveAddendum(files, "projects/other/AGENTS.md")
	if !bytes.Contains(fallback, []byte(globalAddendumProbe)) {
		t.Fatalf("missing global fallback addendum: %q", fallback)
	}
	skill := ResolveAddendum(files, "projects/punaro/skills/shared/SKILL.md")
	if !bytes.Contains(skill, []byte("project-skill-addendum")) || bytes.Contains(skill, []byte("global-skill-addendum")) {
		t.Fatalf("skill addendum override failed: %q", skill)
	}
	commonFallback := ResolveAddendum(files, "projects/other/skills/shared/SKILL.md")
	if !bytes.Contains(commonFallback, []byte("global-skill-addendum")) {
		t.Fatalf("missing common skill fallback addendum: %q", commonFallback)
	}
}

func TestRehydratePutsAddendumInMarkedNonUserBlock(t *testing.T) {
	t.Parallel()
	got := Rehydrate([]byte("# published\n"), []byte(projectAddendumProbe+"\n"), nil)
	text := string(got)
	if !strings.Contains(text, "# published") {
		t.Fatalf("missing published text: %s", text)
	}
	if !strings.Contains(text, projectAddendumProbe) {
		t.Fatalf("missing addendum text: %s", text)
	}
	if !strings.Contains(text, AddendumStart) || !strings.Contains(text, AddendumEnd) {
		t.Fatalf("addendum not in a marked block: %s", text)
	}
	if !strings.Contains(text, UserStart) || !strings.Contains(text, UserEnd) {
		t.Fatalf("missing user region: %s", text)
	}
	if !IsManagedContent(got) {
		t.Fatalf("missing managed mark: %s", text)
	}
	_, user, ok := SplitUser(got)
	if !ok {
		t.Fatal("composed file missing user markers")
	}
	if strings.Contains(string(user), projectAddendumProbe) {
		t.Fatal("addendum text landed in the user block")
	}
	if strings.Contains(string(user), AddendumStart) {
		t.Fatal("addendum markers nested in the user block")
	}
}

func TestComposeClaudeFileIsAgentsPlusClaudeAddendum(t *testing.T) {
	t.Parallel()
	got := ComposeClaudeFile([]byte("# punaro agents\n"), []byte("agents-addendum\n"), []byte(claudeAddendumProbe+"\n"), nil)
	text := string(got)
	if !strings.Contains(text, "# punaro agents") {
		t.Fatalf("CLAUDE.md missing AGENTS.md text: %s", text)
	}
	if !strings.Contains(text, claudeAddendumProbe) {
		t.Fatalf("CLAUDE.md missing Claude addendum: %s", text)
	}
	if !strings.Contains(text, AddendumStart) {
		t.Fatalf("CLAUDE.md addendum unmarked: %s", text)
	}
	if !IsManagedContent(got) {
		t.Fatal("CLAUDE.md missing managed mark")
	}
}

func TestApplyLiveClaudeFileIsAgentsPlusAddendumRegularFile(t *testing.T) {
	t.Parallel()
	_, project, _, _ := applyCopiedCommonSkill(t, skillMarkdown("shared", skillBodyProbe), map[string]string{
		"CLAUDE.md":                 claudeAddendumProbe + "\n",
		"projects/punaro/CLAUDE.md": "project-" + claudeAddendumProbe + "\n",
		"AGENTS.md":                 globalAddendumProbe + "\n",
		"projects/punaro/AGENTS.md": projectAddendumProbe + "\n",
	})
	dest := filepath.Join(project, "CLAUDE.md")
	assertRegularCopiedSkill(t, dest)
	body, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "# punaro") {
		t.Fatalf("CLAUDE.md missing project AGENTS.md: %s", text)
	}
	if !strings.Contains(text, "project-"+claudeAddendumProbe) {
		t.Fatalf("CLAUDE.md missing project Claude addendum: %s", text)
	}
	if strings.Contains(text, claudeAddendumProbe) && !strings.Contains(text, "project-"+claudeAddendumProbe) {
		t.Fatalf("CLAUDE.md used overridden global Claude addendum: %s", text)
	}
	if _, err := os.Readlink(dest); err == nil {
		t.Fatal("CLAUDE.md is a symlink alias of AGENTS.md")
	}
}

func TestApplyLiveUserSectionSurvivesReapply(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	project := filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	matches := []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}}
	v1 := Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet v1\n")},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro v1\n")},
	}}
	if _, err := ApplyLive(ApplyLiveRequest{Tree: v1, Root: root, Home: home, Matches: matches}); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(project, "AGENTS.md")
	live, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	prefix, _, ok := SplitUser(live)
	if !ok {
		t.Fatalf("first apply did not create user markers: %s", live)
	}
	edited := Rehydrate(prefix, nil, []byte("\n"+userBodyProbe+"\n"))
	if err := os.WriteFile(dest, edited, 0o600); err != nil { //nolint:gosec // G703: test fixture under t.TempDir.
		t.Fatal(err)
	}
	v2 := Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet v2\n")},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro v2\n")},
	}}
	if _, err := ApplyLive(ApplyLiveRequest{Tree: v2, Root: root, Home: home, Matches: matches}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "# punaro v2") {
		t.Fatalf("re-apply did not update published prefix: %s", got)
	}
	_, user, ok := SplitUser(got)
	if !ok || !strings.Contains(string(user), userBodyProbe) {
		t.Fatalf("user section did not survive re-apply: %s", got)
	}
}

func TestApplyLiveAddendumEditsAppearOnNextApply(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	project := filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	addendumRoot := filepath.Join(home, "punaro", "addendums")
	writeTreeAt(t, addendumRoot, map[string]string{
		"projects/punaro/AGENTS.md": "addendum-v1\n",
	})
	root := t.TempDir()
	matches := []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}}
	tree := Tree{Files: []File{
		{Path: "AGENTS.md", Data: []byte("# fleet\n")},
		{Path: "projects/punaro/AGENTS.md", Data: []byte("# punaro\n")},
	}}
	req := ApplyLiveRequest{Tree: tree, Root: root, Home: home, AddendumRoot: addendumRoot, Matches: matches}
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(project, "AGENTS.md")
	first, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil || !strings.Contains(string(first), "addendum-v1") {
		t.Fatalf("first apply missing addendum: %q err=%v", first, err)
	}
	writeTreeAt(t, addendumRoot, map[string]string{
		"projects/punaro/AGENTS.md": "addendum-v2\n",
	})
	if _, err := ApplyLive(req); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(dest) //nolint:gosec // G304: test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(second), "addendum-v2") {
		t.Fatalf("changed addendum did not appear: %s", second)
	}
	if strings.Contains(string(second), "addendum-v1") {
		t.Fatalf("stale addendum remained: %s", second)
	}
}

func TestApplyLiveAndStatusOmitSkillAndAddendumBodies(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	home := t.TempDir()
	project := filepath.Join(home, "src", "punaro")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	addendumRoot := filepath.Join(home, "punaro", "addendums")
	writeTreeAt(t, addendumRoot, map[string]string{
		"projects/punaro/skills/shared/SKILL.md": addendumBodyProbe + "\n",
		"CLAUDE.md":                              addendumBodyProbe + "-claude\n",
	})
	tree := commonMemberTree(skillMarkdown("shared", skillBodyProbe), false)
	result, err := ApplyLive(ApplyLiveRequest{
		Tree:         tree,
		Root:         t.TempDir(),
		Home:         home,
		AddendumRoot: addendumRoot,
		Matches:      []ProjectMatch{{Name: "punaro", Path: project, Kind: "matched"}},
		Logs:         &logs,
	})
	if err != nil {
		t.Fatal(err)
	}
	logLine := logs.String() + FormatApplyLog(result, tree.SkillCount())
	for _, token := range []string{skillBodyProbe, addendumBodyProbe, "# punaro"} {
		if strings.Contains(logLine, token) {
			t.Fatalf("apply log contained body token %q: %s", token, logLine)
		}
	}
	var checkBuf bytes.Buffer
	for _, check := range punarodiagnostic.FleetConfigChecks("digest", []string{"current", "drifted"}) {
		checkBuf.WriteString(check.Code)
		checkBuf.WriteString(string(check.Status))
		checkBuf.WriteString(check.Remediation)
	}
	if strings.Contains(checkBuf.String(), skillBodyProbe) || strings.Contains(checkBuf.String(), addendumBodyProbe) {
		t.Fatalf("doctor output contained bodies: %s", checkBuf.String())
	}
}
