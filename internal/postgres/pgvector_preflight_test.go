package postgres

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRequirePGVectorRejectsUnavailablePrerequisite(t *testing.T) {
	path := writeTestDSN(t, "pgvector-owner.dsn", "postgres://ignored")
	original := pgVectorAvailableFn
	t.Cleanup(func() { pgVectorAvailableFn = original })
	pgVectorAvailableFn = func(context.Context, string) (bool, error) { return false, nil }
	if err := RequirePGVector(context.Background(), Config{DSNFile: path}); err == nil {
		t.Fatal("RequirePGVector() accepted an unavailable prerequisite")
	}
}

func TestRequirePGVectorRejectsProbeFailureWithoutLeakingDSN(t *testing.T) {
	const dsn = "postgres://secret@example.invalid/punaro"
	path := filepath.Join(t.TempDir(), "pgvector-owner.dsn")
	if err := os.WriteFile(path, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	original := pgVectorAvailableFn
	t.Cleanup(func() { pgVectorAvailableFn = original })
	pgVectorAvailableFn = func(context.Context, string) (bool, error) { return false, errors.New("probe failed") }
	err := RequirePGVector(context.Background(), Config{DSNFile: path})
	if err == nil || err.Error() == dsn {
		t.Fatalf("RequirePGVector() error=%v, want generic prerequisite refusal", err)
	}
}

func TestRequirePGVectorAcceptsAvailablePrerequisite(t *testing.T) {
	path := writeTestDSN(t, "pgvector-owner.dsn", "postgres://ignored")
	original := pgVectorAvailableFn
	t.Cleanup(func() { pgVectorAvailableFn = original })
	pgVectorAvailableFn = func(context.Context, string) (bool, error) { return true, nil }
	if err := RequirePGVector(context.Background(), Config{DSNFile: path}); err != nil {
		t.Fatalf("RequirePGVector() error=%v, want success", err)
	}
}
