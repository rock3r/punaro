package plugindiagnostic

import (
	"context"
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
