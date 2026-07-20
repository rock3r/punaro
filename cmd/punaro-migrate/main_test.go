package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

var validArguments = []string{
	"-owner-dsn-file", "/run/secrets/punaro-owner-dsn",
	"-update-id", "0190ea2e-8a2d-7d42-b320-8515f7604bc1",
	"-backup-id", "0290ea2e-8a2d-7d42-b320-8515f7604bc1",
	"-target-release", "v0.7.0",
	"-target-image", "registry.example/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"-target-schema", "6",
	"-exported-snapshot-id", "00000003-0000001B-1",
	"-manifest-sha256", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
}

func TestRunRequiresCompleteUpdateAuthorization(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "empty", args: nil},
		{name: "missing owner DSN", args: withoutFlag(validArguments, "-owner-dsn-file")},
		{name: "missing update ID", args: withoutFlag(validArguments, "-update-id")},
		{name: "missing backup ID", args: withoutFlag(validArguments, "-backup-id")},
		{name: "missing target release", args: withoutFlag(validArguments, "-target-release")},
		{name: "missing target image", args: withoutFlag(validArguments, "-target-image")},
		{name: "missing target schema", args: withoutFlag(validArguments, "-target-schema")},
		{name: "missing snapshot", args: withoutFlag(validArguments, "-exported-snapshot-id")},
		{name: "missing manifest hash", args: withoutFlag(validArguments, "-manifest-sha256")},
		{name: "unknown flag", args: append(append([]string{}, validArguments...), "-unexpected", "value")},
		{name: "trailing argument", args: append(append([]string{}, validArguments...), "unexpected")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := run(test.args, &stderr); code != 2 {
				t.Fatalf("run() = %d, want 2; stderr=%q", code, stderr.String())
			}
		})
	}
}

func TestRunInvokesUpdateAuthorizedMigrator(t *testing.T) {
	original := migratePostgresUpdate
	t.Cleanup(func() { migratePostgresUpdate = original })
	var gotConfig punaropostgres.Config
	var gotAuthorization punaropostgres.UpdateMigrationAuthorization
	var gotDeadline time.Time
	migratePostgresUpdate = func(ctx context.Context, cfg punaropostgres.Config, authorization punaropostgres.UpdateMigrationAuthorization) (punaropostgres.SchemaState, error) {
		gotConfig = cfg
		gotAuthorization = authorization
		gotDeadline, _ = ctx.Deadline()
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 6}, nil
	}
	started := time.Now()
	var stderr bytes.Buffer
	if code := run(validArguments, &stderr); code != 0 {
		t.Fatalf("run()=%d stderr=%q", code, stderr.String())
	}
	wantAuthorization := punaropostgres.UpdateMigrationAuthorization{
		UpdateID: "0190ea2e-8a2d-7d42-b320-8515f7604bc1", BackupID: "0290ea2e-8a2d-7d42-b320-8515f7604bc1",
		TargetRelease: "v0.7.0", TargetImage: "registry.example/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TargetSchema: 6, ExportedSnapshotID: "00000003-0000001B-1",
		ManifestSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	if gotConfig.DSNFile != "/run/secrets/punaro-owner-dsn" || !reflect.DeepEqual(gotAuthorization, wantAuthorization) {
		t.Fatalf("config=%#v authorization=%#v", gotConfig, gotAuthorization)
	}
	if gotDeadline.Before(started.Add(119*time.Second)) || gotDeadline.After(started.Add(121*time.Second)) {
		t.Fatalf("deadline=%v, want approximately two minutes", gotDeadline)
	}
	if !strings.Contains(stderr.String(), "version=6") {
		t.Fatalf("stderr=%q, want completion summary", stderr.String())
	}
}

func TestRunRejectsInvalidAuthorizationBeforeMigration(t *testing.T) {
	original := migratePostgresUpdate
	t.Cleanup(func() { migratePostgresUpdate = original })
	called := false
	migratePostgresUpdate = func(context.Context, punaropostgres.Config, punaropostgres.UpdateMigrationAuthorization) (punaropostgres.SchemaState, error) {
		called = true
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 6}, nil
	}
	arguments := append([]string{}, validArguments...)
	for index := range arguments {
		if arguments[index] == "-update-id" {
			arguments[index+1] = "not-an-update-id"
		}
	}
	var stderr bytes.Buffer
	if code := run(arguments, &stderr); code != 2 {
		t.Fatalf("run()=%d, want 2; stderr=%q", code, stderr.String())
	}
	if called {
		t.Fatal("invalid authorization reached the migrator")
	}
}

func TestRunDoesNotPrintMigratorErrorDetails(t *testing.T) {
	original := migratePostgresUpdate
	t.Cleanup(func() { migratePostgresUpdate = original })
	const secret = "postgres://owner:top-secret@example.invalid/punaro" // #nosec G101 -- deliberate leak-suppression fixture.
	migratePostgresUpdate = func(context.Context, punaropostgres.Config, punaropostgres.UpdateMigrationAuthorization) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{}, errors.New(secret)
	}
	var stderr bytes.Buffer
	if code := run(validArguments, &stderr); code != 1 {
		t.Fatalf("run()=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), secret) || !strings.Contains(stderr.String(), "failed") {
		t.Fatalf("stderr leaked migrator details: %q", stderr.String())
	}
}

func withoutFlag(arguments []string, flagName string) []string {
	result := make([]string, 0, len(arguments)-2)
	for index := 0; index < len(arguments); index += 2 {
		if arguments[index] != flagName {
			result = append(result, arguments[index], arguments[index+1])
		}
	}
	return result
}
