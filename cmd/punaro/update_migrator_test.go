package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

func migrationStartedTransaction() punaropostgres.UpdateTransaction {
	request := testUpdateRequest()
	return punaropostgres.UpdateTransaction{
		UpdateRequest:        request,
		Phase:                punaropostgres.UpdateMigrationStarted,
		BackupID:             "019b4eb0-5317-79a6-a0de-fd97719910fb",
		BackupSnapshotID:     "00000003-000001A0-1",
		BackupManifestSHA256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
}

func TestUpdateMigratorRunsOneShotInExactTargetDigestWithExactAuthorization(t *testing.T) {
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGPASSWORD", "host-secret-must-not-propagate")
	t.Setenv("PUNARO_OWNER_DSN", "postgres://owner-secret-must-not-propagate")
	t.Setenv("COMPOSE_FILE", "/attacker/compose.yaml")
	t.Setenv("DOCKER_HOST", "tcp://attacker.example:2375")

	originalDocker := runUpdateDocker
	t.Cleanup(func() { runUpdateDocker = originalDocker })
	var gotDirectory string
	var gotEnvironment, gotArguments []string
	runUpdateDocker = func(_ context.Context, directory string, environment []string, arguments ...string) ([]byte, error) {
		gotDirectory = directory
		gotEnvironment = append([]string(nil), environment...)
		gotArguments = append([]string(nil), arguments...)
		return nil, nil
	}

	transaction := migrationStartedTransaction()
	executor := &commandUpdateExecutor{installation: installation}
	if err := executor.Migrate(context.Background(), transaction); err != nil {
		t.Fatal(err)
	}
	canonicalOwnerDSN, err := filepath.EvalSymlinks(installation.OwnerDSNFile)
	if err != nil {
		t.Fatal(err)
	}
	containerDSNPath := "/run/secrets/punaro-owner-dsn"
	want := []string{
		"run", "--rm", "--network", "host", "--read-only",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--user", installation.RuntimeUID + ":" + installation.RuntimeGID,
		"--mount", "type=bind,src=" + canonicalOwnerDSN + ",dst=" + containerDSNPath + ",readonly",
		"--entrypoint", "/usr/local/bin/punaro-migrate", transaction.TargetImage,
		"--owner-dsn-file", containerDSNPath,
		"--update-id", transaction.UpdateID,
		"--backup-id", transaction.BackupID,
		"--target-release", transaction.TargetRelease,
		"--target-image", transaction.TargetImage,
		"--target-schema", strconv.FormatInt(transaction.TargetSchema, 10),
		"--exported-snapshot-id", transaction.BackupSnapshotID,
		"--manifest-sha256", transaction.BackupManifestSHA256,
	}
	if gotDirectory != installation.Directory || !slices.Equal(gotArguments, want) {
		t.Fatalf("directory=%q args=%v want=%v", gotDirectory, gotArguments, want)
	}
	for _, entry := range gotEnvironment {
		name, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "PG") || strings.HasPrefix(upper, "PUNARO_") || strings.HasPrefix(upper, "COMPOSE_") || strings.HasPrefix(upper, "DOCKER_") {
			t.Fatalf("unsafe inherited migrator environment: %q", entry)
		}
	}
	joined := strings.Join(append(append([]string(nil), gotEnvironment...), gotArguments...), "\n")
	if strings.Contains(joined, "host-secret-must-not-propagate") || strings.Contains(joined, "owner-secret-must-not-propagate") || strings.Contains(joined, transaction.SourceImage) {
		t.Fatalf("migrator command exposed a secret or source image: %s", joined)
	}
}

func TestUpdateMigratorRefusesUnsafeOwnerPathAndUnpinnedTargetBeforeDocker(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *operator.Installation, *punaropostgres.UpdateTransaction){
		"unsafe owner file": func(t *testing.T, installation *operator.Installation, _ *punaropostgres.UpdateTransaction) {
			if err := os.Chmod(installation.OwnerDSNFile, 0o644); err != nil { // #nosec G302 -- deliberate unsafe permission drift.
				t.Fatal(err)
			}
		},
		"tagged target image": func(_ *testing.T, _ *operator.Installation, transaction *punaropostgres.UpdateTransaction) {
			transaction.TargetImage = "registry.example/punaro:latest"
		},
		"missing authorization": func(_ *testing.T, _ *operator.Installation, transaction *punaropostgres.UpdateTransaction) {
			transaction.BackupManifestSHA256 = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := testInstallation(t)
			installation, err := operator.Load(directory)
			if err != nil {
				t.Fatal(err)
			}
			transaction := migrationStartedTransaction()
			mutate(t, &installation, &transaction)
			originalDocker := runUpdateDocker
			t.Cleanup(func() { runUpdateDocker = originalDocker })
			called := false
			runUpdateDocker = func(context.Context, string, []string, ...string) ([]byte, error) {
				called = true
				return nil, nil
			}
			executor := &commandUpdateExecutor{installation: installation}
			if err := executor.Migrate(context.Background(), transaction); err == nil || called {
				t.Fatalf("err=%v dockerCalled=%t", err, called)
			}
		})
	}
}
