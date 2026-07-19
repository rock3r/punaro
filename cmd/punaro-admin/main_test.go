package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	postgres "github.com/rock3r/punaro/internal/postgres"
)

func TestClientAddPrintsExactPreviewBeforeOpeningAdministration(t *testing.T) {
	original := openAdminDatabase
	t.Cleanup(func() { openAdminDatabase = original })
	openAdminDatabase = func(_ context.Context, _ postgres.Config) (adminDatabase, error) {
		t.Fatal("administration opened before confirmation")
		return nil, nil
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"client", "add", "--actor-principal-id", "11111111-1111-4111-8111-111111111111", "--name", "laptop", "--client-binding", "22222222-2222-4222-8222-222222222222", "--all-projects"}, &stdout, &stderr)
	if code != 3 || !strings.Contains(stdout.String(), `"template": "trusted-agent"`) || !strings.Contains(stdout.String(), `"preview_hash"`) || !strings.Contains(stderr.String(), "rerun with --yes") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRotationCodeFileIsExclusiveAndProtected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode and symlink contract")
	}
	path := filepath.Join(t.TempDir(), "rotation.code")
	code := strings.Repeat("A", 43)
	if err := writeProtectedRotationCode(path, code); err != nil {
		t.Fatal(err)
	}
	if got, err := readProtectedRotationCode(path); err != nil || got != code {
		t.Fatalf("read code=%q err=%v", got, err)
	}
	if err := writeProtectedRotationCode(path, code); err == nil {
		t.Fatal("rotation code output overwrote an existing file")
	}
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- deliberate unsafe-permission rejection fixture.
		t.Fatal(err)
	}
	if _, err := readProtectedRotationCode(path); err == nil {
		t.Fatal("permissive rotation code file accepted")
	}
	link := filepath.Join(t.TempDir(), "rotation-link.code")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedRotationCode(link); err == nil {
		t.Fatal("symlinked rotation code file accepted")
	}
}

func TestClientAddRejectsAmbiguousProjectScope(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"client", "add", "--actor-principal-id", "11111111-1111-4111-8111-111111111111", "--name", "laptop", "--client-binding", "22222222-2222-4222-8222-222222222222", "--project", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "--all-projects"}, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || strings.Contains(stderr.String(), "aaaaaaaa") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
