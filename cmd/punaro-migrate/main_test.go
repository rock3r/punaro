package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

func TestRunRequiresExplicitOwnerDSNFile(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(nil, &stderr); code != 2 {
		t.Fatalf("run() = %d, want 2; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "owner-dsn-file") {
		t.Fatalf("stderr = %q, want required flag guidance", stderr.String())
	}
}

func TestRunInvokesExplicitMigrator(t *testing.T) {
	original := migratePostgres
	t.Cleanup(func() { migratePostgres = original })
	var gotFile string
	migratePostgres = func(_ context.Context, cfg punaropostgres.Config) (punaropostgres.SchemaState, error) {
		gotFile = cfg.DSNFile
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 1}, nil
	}
	var stderr bytes.Buffer
	if code := run([]string{"-owner-dsn-file", "/run/secrets/punaro-owner-dsn"}, &stderr); code != 0 {
		t.Fatalf("run()=%d stderr=%q", code, stderr.String())
	}
	if gotFile != "/run/secrets/punaro-owner-dsn" || !strings.Contains(stderr.String(), "version=1") {
		t.Fatalf("file=%q stderr=%q", gotFile, stderr.String())
	}
}
