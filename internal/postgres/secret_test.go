package postgres

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadDSNFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "postgres.dsn")
	const secret = "postgres://app:do-not-leak@example.invalid/punaro?sslmode=verify-full" // #nosec G101 -- deliberate fake redaction fixture.
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDSNFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != secret {
		t.Fatalf("ReadDSNFile() = %q, want exact trimmed DSN", got)
	}
}

func TestReadDSNFileFailsClosedWithoutLeakingSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "postgres.dsn")
	const secret = "postgres://app:highly-sensitive@example.invalid/punaro" // #nosec G101 -- deliberate fake redaction fixture.
	// #nosec G306 -- the broad mode is the unsafe condition under test.
	if err := os.WriteFile(path, []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	_, err := ReadDSNFile(path)
	if err == nil {
		t.Fatal("ReadDSNFile() succeeded for group/world-readable secret")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "highly-sensitive") {
		t.Fatalf("error leaked DSN: %v", err)
	}
}

func TestReadDSNFileRejectsRelativeEmptyAndOversizedFiles(t *testing.T) {
	if _, err := ReadDSNFile("relative.dsn"); err == nil {
		t.Error("relative path accepted")
	}
	dir := t.TempDir()
	for name, content := range map[string][]byte{
		"empty": nil,
		"large": []byte(strings.Repeat("x", maxDSNFileBytes+1)),
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadDSNFile(path); err == nil {
			t.Errorf("%s file accepted", name)
		}
	}
}

func TestReadDSNFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available to unprivileged Windows tests")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("postgres://app:secret@example.invalid/punaro"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDSNFile(link); err == nil {
		t.Fatal("symlink DSN file accepted")
	}
}
