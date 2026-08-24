package plugindiagnostic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSkillSetDigestContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := SkillSetDigestContext(ctx, filepath.Join(t.TempDir(), "skills")); err == nil {
		t.Fatal("canceled skill digest inspection continued")
	}
}

func TestRepositoryPluginHasOneVersionAndDeterministicSkillDigest(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	version, err := Version(root)
	if err != nil || version == "" {
		t.Fatalf("version unavailable: %v", err)
	}
	first, err := SkillSetDigest(filepath.Join(root, "skills"))
	if err != nil || len(first) != 64 {
		t.Fatalf("digest unavailable: %v", err)
	}
	second, err := SkillSetDigest(filepath.Join(root, "skills"))
	if err != nil || second != first {
		t.Fatalf("digest changed: %q %q %v", first, second, err)
	}
	runtimeFirst, err := RuntimeDigest(root)
	if err != nil || len(runtimeFirst) != 64 {
		t.Fatalf("runtime digest unavailable: %v", err)
	}
	runtimeSecond, err := RuntimeDigest(root)
	if err != nil || runtimeSecond != runtimeFirst {
		t.Fatalf("runtime digest changed: %q %q %v", runtimeFirst, runtimeSecond, err)
	}
}

func TestRuntimeDigestBindsLaunchersAndMCPRegistrations(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string]string{
		".mcp.json":                     "claude-registration",
		"mcp.json":                      "portable-registration",
		"scripts/punaro-plugin-mcp":     "posix-launcher",
		"scripts/punaro-plugin-mcp.cmd": "windows-launcher",
	} {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	baseline, err := RuntimeDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range runtimePaths {
		full := filepath.Join(root, filepath.FromSlash(path))
		original, err := os.ReadFile(full) // #nosec G304 -- fixed test-owned runtime path.
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, append(original, '!'), 0o600); err != nil { // #nosec G703 -- fixed test-owned runtime path.
			t.Fatal(err)
		}
		changed, err := RuntimeDigest(root)
		if err != nil || changed == baseline {
			t.Fatalf("runtime path %s was not bound: digest=%q err=%v", path, changed, err)
		}
		if err := os.WriteFile(full, original, 0o600); err != nil { // #nosec G703 -- fixed test-owned runtime path.
			t.Fatal(err)
		}
	}
}

func TestSkillSetDigestFramesNULContainingFilesUnambiguously(t *testing.T) {
	createRoot := func(t *testing.T, attachment, mailbox []byte) string {
		t.Helper()
		root := t.TempDir()
		for _, skill := range []string{"punaro-attachment", "punaro-mailbox", "punaro-reply"} {
			if err := os.Mkdir(filepath.Join(root, skill), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for path, body := range map[string][]byte{
			"punaro-attachment/SKILL.md": attachment,
			"punaro-mailbox/SKILL.md":    mailbox,
			"punaro-reply/SKILL.md":      []byte("reply"),
		} {
			if len(body) == 0 {
				continue
			}
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(path)), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	colliding := createRoot(t, []byte("attachment\x00punaro-mailbox/SKILL.md\x00mailbox"), nil)
	separate := createRoot(t, []byte("attachment"), []byte("mailbox"))
	first, err := SkillSetDigest(colliding)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SkillSetDigest(separate)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("distinct NUL-containing skill trees produced the same digest")
	}
}

func TestSkillSetDigestRejectsUnexpectedAndLinkedEntries(t *testing.T) {
	root := t.TempDir()
	for _, skill := range []string{"punaro-attachment", "punaro-mailbox", "punaro-reply"} {
		directory := filepath.Join(root, skill)
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(skill), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SkillSetDigest(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "punaro-mailbox", "SKILL.md"), filepath.Join(root, "punaro-reply", "linked.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := SkillSetDigest(root); err == nil {
		t.Fatal("linked skill entry accepted")
	}
}

func TestSkillSetDigestRejectsFourthRootEntry(t *testing.T) {
	root := t.TempDir()
	for _, skill := range []string{"punaro-attachment", "punaro-mailbox", "punaro-reply", "unexpected"} {
		if err := os.Mkdir(filepath.Join(root, skill), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SkillSetDigestContext(t.Context(), root); err == nil {
		t.Fatal("fourth skill root entry accepted")
	}
}

func TestSkillSetDigestBoundsNestedDirectoryEntries(t *testing.T) {
	root := t.TempDir()
	for _, skill := range []string{"punaro-attachment", "punaro-mailbox", "punaro-reply"} {
		directory := filepath.Join(root, skill)
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(skill), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for index := range maximumSkillEntries {
		if err := os.Mkdir(filepath.Join(root, "punaro-mailbox", fmt.Sprintf("nested-%02d", index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SkillSetDigestContext(t.Context(), root); err == nil {
		t.Fatal("oversized nested skill tree accepted")
	}
}
