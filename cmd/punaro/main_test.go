package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	punarobackup "github.com/rock3r/punaro/internal/backup"
	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

const cliTestImage = "registry.example/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestRealPostgresBackupRestoreCleanStackAndRetry(t *testing.T) {
	sourceOwnerDSN := os.Getenv("PUNARO_TEST_RESTORE_SOURCE_OWNER_DSN")
	sourceAppDSN := os.Getenv("PUNARO_TEST_RESTORE_SOURCE_APP_DSN")
	targetOwnerDSN := os.Getenv("PUNARO_TEST_RESTORE_TARGET_OWNER_DSN")
	targetAppDSN := os.Getenv("PUNARO_TEST_RESTORE_TARGET_APP_DSN")
	if sourceOwnerDSN == "" || sourceAppDSN == "" || targetOwnerDSN == "" || targetAppDSN == "" {
		t.Skip("set the PUNARO_TEST_RESTORE_* DSNs to run the real backup/restore gate")
	}
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- private integration-test root.
		t.Fatal(err)
	}
	writeDSN := func(name, dsn string) string {
		path := filepath.Join(root, name)
		// #nosec G703 -- name is a fixed integration-test fixture label.
		if err := os.WriteFile(path, []byte(dsn+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	sourceOwner := writeDSN("source-owner.dsn", sourceOwnerDSN)
	sourceApp := writeDSN("source-app.dsn", sourceAppDSN)
	targetOwner := writeDSN("target-owner.dsn", targetOwnerDSN)
	targetApp := writeDSN("target-app.dsn", targetAppDSN)
	if state, err := punaropostgres.MigratePristinePair(ctx, punaropostgres.Config{DSNFile: sourceApp}, punaropostgres.Config{DSNFile: sourceOwner}); err != nil || state.Classification != punaropostgres.Compatible {
		t.Fatalf("source migration state=%#v err=%v", state, err)
	}
	if state, err := punaropostgres.MigratePristinePair(ctx, punaropostgres.Config{DSNFile: targetApp}, punaropostgres.Config{DSNFile: targetOwner}); err != nil || state.Classification != punaropostgres.Compatible {
		t.Fatalf("target migration state=%#v err=%v", state, err)
	}
	// Return the target to a role-proven pristine state for pg_restore.
	targetDB, err := sql.Open("pgx", targetOwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := targetDB.ExecContext(ctx, `DROP SCHEMA auth, relay, attachment, brain, jobs, audit CASCADE`); err != nil {
		_ = targetDB.Close()
		t.Fatal(err)
	}
	if err := targetDB.Close(); err != nil {
		t.Fatal(err)
	}

	sourceData := filepath.Join(root, "source-data")
	sourceBackups := filepath.Join(root, "source-backups")
	targetBackups := filepath.Join(root, "target-backups")
	for _, directory := range []string{filepath.Join(sourceData, "blobs", "ready"), sourceBackups, targetBackups} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourceData, "blobs", "ready", "test"), []byte("blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceInstallation, err := operator.Init(ctx, operator.InitOptions{
		Directory: filepath.Join(root, "source-installation"), DataDir: sourceData, BackupDir: sourceBackups,
		Image: cliTestImage, OwnerDSNFile: sourceOwner, AppDSNFile: sourceApp, OwnerName: "Restore integration owner",
		Ingress: ingress.Policy{Mode: ingress.Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"},
	}, func(initCtx context.Context, dsnFile, name string) (punaropostgres.Principal, error) {
		admin, openErr := punaropostgres.OpenAdministration(initCtx, punaropostgres.Config{DSNFile: dsnFile})
		if openErr != nil {
			return punaropostgres.Principal{}, openErr
		}
		defer func() { _ = admin.Close() }()
		return admin.BootstrapOwner(initCtx, name)
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceDB, err := sql.Open("pgx", sourceOwnerDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceDB.ExecContext(ctx, `INSERT INTO attachment.ready_blob_manifest(storage_path,size_bytes,sha256) VALUES ('ready/test',4,'fa2c8cc4f28176bbeed4b736df569a34c79cd3723e9ec42f9674b4d46ac6b8b8')`); err != nil {
		_ = sourceDB.Close()
		t.Fatal(err)
	}
	if err := sourceDB.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, backupDirectory, err := createBackup(ctx, sourceInstallation)
	if err != nil {
		t.Fatalf("real backup: %v", err)
	}
	request := restoreRequest{
		BackupDirectory: backupDirectory,
		Directory:       filepath.Join(root, "target-installation"),
		DataDir:         filepath.Join(root, "target-data"),
		BackupDir:       targetBackups,
		OwnerDSNFile:    targetOwner,
		AppDSNFile:      targetApp,
	}
	restored, err := restoreBackup(ctx, request)
	if err != nil {
		t.Fatalf("real restore: %v", err)
	}
	if restored.InstallationID != manifest.State.InstallationID || restored.TimelineID == manifest.State.TimelineID || restored.ChangeSequence != manifest.State.ChangeSequence {
		t.Fatalf("restored state=%#v manifest=%#v", restored, manifest.State)
	}
	loaded, err := operator.Load(request.Directory)
	if err != nil || loaded.OwnerPrincipalID != sourceInstallation.OwnerPrincipalID || loaded.DataDir != request.DataDir || loaded.OwnerDSNFile != targetOwner || loaded.AppDSNFile != targetApp {
		t.Fatalf("restored installation=%#v err=%v", loaded, err)
	}
	if body, err := os.ReadFile(filepath.Join(request.DataDir, "blobs", "ready", "test")); err != nil || string(body) != "blob" { // #nosec G304 -- fixed integration-test restore child.
		t.Fatalf("restored blob=%q err=%v", body, err)
	}
	if retried, err := restoreBackup(ctx, request); err != nil || retried != restored {
		t.Fatalf("same-command resume state=%#v err=%v", retried, err)
	}
}

func testInstallation(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"data", "backup"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"owner.dsn", "app.dsn"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("postgres://invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	directory := filepath.Join(root, "installation")
	_, err := operator.Init(context.Background(), operator.InitOptions{Directory: directory, DataDir: filepath.Join(root, "data"), BackupDir: filepath.Join(root, "backup"), Image: cliTestImage, OwnerDSNFile: filepath.Join(root, "owner.dsn"), AppDSNFile: filepath.Join(root, "app.dsn"), OwnerName: "owner", Ingress: ingress.Policy{Mode: ingress.Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"}}, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func preserveDependencies(t *testing.T) {
	t.Helper()
	originalInspect, originalOwner, originalMigrate := inspectSchema, inspectOwner, migratePristinePair
	originalCreate, originalRecover := createOwner, recoverInstallationOwner
	originalVerify := verifyInstallationPair
	originalStart, originalProbe, originalIssue := startServices, probe, issueEnrollment
	originalBackup, originalListBackups, originalVerifyBackup, originalRestore := createOperatorBackup, listOperatorBackups, verifyOperatorBackup, restoreOperatorBackup
	t.Cleanup(func() {
		inspectSchema, inspectOwner, migratePristinePair = originalInspect, originalOwner, originalMigrate
		createOwner, recoverInstallationOwner = originalCreate, originalRecover
		verifyInstallationPair = originalVerify
		startServices, probe = originalStart, originalProbe
		issueEnrollment = originalIssue
		createOperatorBackup, listOperatorBackups, verifyOperatorBackup, restoreOperatorBackup = originalBackup, originalListBackups, originalVerifyBackup, originalRestore
	})
	inspectOwner = func(context.Context, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111", DisplayName: "owner"}, nil
	}
	verifyInstallationPair = func(context.Context, string, string) error { return nil }
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
}

func TestBackupCommandsUsePublishedInstallationAndStrictVerifier(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	manifest := punarobackup.Manifest{Version: 1, BackupID: "018f47f4-7b18-7cc2-98d6-31d4fb5ab742", CreatedAt: time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC), SchemaVersion: 5, State: punarobackup.State{InstallationID: "4e02b0e5-1934-4dda-9c4a-767c120c2fac", TimelineID: "797476ad-8fdc-4c05-b144-3ccbb92b54bf", ChangeSequence: 42}}
	backupPath := filepath.Join(installation.BackupDir, "verified")
	createOperatorBackup = func(_ context.Context, got operator.Installation) (punarobackup.Manifest, string, error) {
		if got.Directory != directory {
			t.Fatalf("unexpected installation: %#v", got)
		}
		return manifest, backupPath, nil
	}
	listOperatorBackups = func(root string) ([]punarobackup.Summary, error) {
		if root != installation.BackupDir {
			t.Fatalf("unexpected backup root: %q", root)
		}
		return []punarobackup.Summary{{Directory: backupPath, BackupID: manifest.BackupID, CreatedAt: manifest.CreatedAt, SchemaVersion: 5, State: manifest.State}}, nil
	}
	verifyOperatorBackup = func(path string) (punarobackup.Manifest, error) {
		if path != backupPath {
			t.Fatalf("unexpected verify path: %q", path)
		}
		return manifest, nil
	}

	for _, command := range [][]string{{"backup", "--directory", directory}, {"backup", "list", "--directory", directory}, {"backup", "verify", "--backup", backupPath}} {
		var stdout, stderr bytes.Buffer
		if code := run(command, &stdout, &stderr); code != 0 {
			t.Fatalf("command=%v code=%d stdout=%s stderr=%s", command, code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), manifest.BackupID) {
			t.Fatalf("command=%v omitted backup identity: %s", command, stdout.String())
		}
	}
}

func TestRestoreCommandRequiresExplicitNewStackInputs(t *testing.T) {
	preserveDependencies(t)
	root := t.TempDir()
	backupPath := filepath.Join(root, "backup")
	if err := os.Mkdir(backupPath, 0o700); err != nil {
		t.Fatal(err)
	}
	requestSeen := restoreRequest{}
	restoreOperatorBackup = func(_ context.Context, request restoreRequest) (punarobackup.State, error) {
		requestSeen = request
		return punarobackup.State{InstallationID: "4e02b0e5-1934-4dda-9c4a-767c120c2fac", TimelineID: "7c016e76-aadb-48f8-b460-e75f7d90e888", ChangeSequence: 42}, nil
	}
	args := []string{"restore", "--backup", backupPath, "--into-new-stack", filepath.Join(root, "install"), "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "new-backups"), "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn")}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("restore code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if requestSeen.BackupDirectory != backupPath || requestSeen.Directory != filepath.Join(root, "install") || requestSeen.DataDir != filepath.Join(root, "data") {
		t.Fatalf("unexpected restore request: %#v", requestSeen)
	}
	if code := run([]string{"restore", "--backup", backupPath}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("incomplete restore code=%d, want 2", code)
	}
}

func TestPostgresToolNeverPlacesPasswordInArgumentsOrInheritedEnvironment(t *testing.T) {
	root := t.TempDir()
	dsnFile := filepath.Join(root, "owner.dsn")
	password := "visible-secret-password"
	if err := os.WriteFile(dsnFile, []byte("postgresql://punaro_owner:"+password+"@127.0.0.1:5432/punaro?sslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "capture.sh")
	capture := filepath.Join(root, "capture.txt")
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" \"${PGPASSWORD:-missing}\" > \"$CAPTURE_FILE\"\nexit 9\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- executable test fixture.
		t.Fatal(err)
	}
	t.Setenv("PGPASSWORD", "inherited-secret")
	t.Setenv("CAPTURE_FILE", capture)
	err := runPostgresTool(context.Background(), script, dsnFile, func(connection string) []string { return []string{"--dbname", connection} })
	if err == nil {
		t.Fatal("failing capture tool unexpectedly succeeded")
	}
	message := err.Error()
	if strings.Contains(message, password) || strings.Contains(message, "inherited-secret") {
		t.Fatalf("tool leaked a credential in its error: %q", message)
	}
	captured, readErr := os.ReadFile(capture) // #nosec G304 -- fixed private test capture path.
	if readErr != nil || strings.Contains(string(captured), password) || strings.Contains(string(captured), "inherited-secret") || !strings.Contains(string(captured), "missing") {
		t.Fatalf("tool leaked or inherited a credential: capture=%q err=%v", captured, readErr)
	}
	if !strings.Contains(string(captured), "postgresql://punaro_owner@127.0.0.1:5432/punaro?sslmode=disable") {
		t.Fatalf("sanitized connection was not passed: %q", captured)
	}
}

func TestPostgresDumpUsesPrivatePreopenedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	root := t.TempDir()
	dsnFile := filepath.Join(root, "owner.dsn")
	if err := os.WriteFile(dsnFile, []byte("postgresql://punaro_owner@127.0.0.1:5432/punaro?sslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "pg_dump")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'private-dump'\n"), 0o700); err != nil { // #nosec G306 -- executable test fixture.
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	destination := filepath.Join(root, "database.dump")
	if err := pgDumpSnapshot(context.Background(), dsnFile, "00000003-0000001B-999", destination); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("dump mode=%v", info.Mode().Perm())
	}
	body, err := os.ReadFile(destination) // #nosec G304 -- fixed test artifact path.
	if err != nil || string(body) != "private-dump" {
		t.Fatalf("dump=%q err=%v", body, err)
	}
}

func TestPostgresToolRejectsSSLPasswordWithoutLeakingIt(t *testing.T) {
	root := t.TempDir()
	dsnFile := filepath.Join(root, "owner.dsn")
	const secret = "client-key-secret" // #nosec G101 -- non-secret rejection sentinel.
	if err := os.WriteFile(dsnFile, []byte("postgresql://punaro_owner@127.0.0.1:5432/punaro?sslmode=require&sslpassword="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runPostgresTool(context.Background(), filepath.Join(root, "must-not-run"), dsnFile, func(connection string) []string { return []string{"--dbname", connection} })
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "password query parameters") {
		t.Fatalf("sslpassword rejection=%q", err)
	}
}

func TestComposeUpArgsUseInstallationSpecificProjectName(t *testing.T) {
	first := operator.Installation{Directory: filepath.Join(string(filepath.Separator), "srv", "a", "punaro"), OwnerPrincipalID: "11111111-1111-4111-8111-111111111111"}
	second := operator.Installation{Directory: filepath.Join(string(filepath.Separator), "srv", "b", "punaro"), OwnerPrincipalID: "22222222-2222-4222-8222-222222222222"}
	firstArgs, firstErr := composeUpArgs(first)
	secondArgs, secondErr := composeUpArgs(second)
	firstProject, _ := operator.ComposeProjectName(first)
	if firstErr != nil || secondErr != nil || len(firstArgs) < 3 || firstArgs[1] != "--project-name" || firstArgs[2] != firstProject {
		t.Fatalf("first args=%v", firstArgs)
	}
	if firstArgs[2] == secondArgs[2] {
		t.Fatalf("same-basename installations share project name: %q", firstArgs[2])
	}
	if _, err := composeUpArgs(operator.Installation{OwnerPrincipalID: "invalid"}); err == nil {
		t.Fatal("invalid owner identity reached Docker arguments")
	}
}

func TestComposeEnvironmentMakesGeneratedInputsAuthoritative(t *testing.T) {
	directory := filepath.Join(string(filepath.Separator), "srv", "punaro")
	got := composeEnvironment([]string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/operator",
		"DOCKER_HOST=unix:///run/user/1000/docker.sock",
		"DOCKER_CONTEXT=desktop-linux",
		"DOCKER_CONFIG=/home/operator/.docker",
		"HTTPS_PROXY=http://proxy.example",
		"PWD=/stale",
		"pwd=/also-stale",
		"PUNARO_IMAGE=attacker.example/punaro:latest",
		"PuNaRo_Listen_Addr=attacker",
		"PUNARO_POSTGRES_DSN_FILE=/attacker.dsn",
		"PUNARO_FUTURE=attacker",
		"COMPOSE_FILE=/attacker.yaml",
		"compose_path_separator=attacker",
		"COMPOSE_PROJECT_NAME=attacker",
		"COMPOSE_ENV_FILES=/attacker.env",
		"COMPOSE_PROFILES=attacker",
		"XPUNARO_IMAGE=unrelated",
		"XCOMPOSE_FILE=unrelated",
	}, directory)
	want := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/operator",
		"DOCKER_HOST=unix:///run/user/1000/docker.sock",
		"DOCKER_CONTEXT=desktop-linux",
		"DOCKER_CONFIG=/home/operator/.docker",
		"HTTPS_PROXY=http://proxy.example",
		"XPUNARO_IMAGE=unrelated",
		"XCOMPOSE_FILE=unrelated",
		"PWD=" + directory,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("environment=%v want=%v", got, want)
	}
}

func TestComposeUpCommandWiresSanitizedEnvironmentAndDirectory(t *testing.T) {
	t.Setenv("PUNARO_IMAGE", "attacker.example/punaro:latest")
	t.Setenv("COMPOSE_FILE", "/attacker.yaml")
	installation := operator.Installation{
		Directory:        filepath.Join(string(filepath.Separator), "srv", "punaro"),
		OwnerPrincipalID: "11111111-1111-4111-8111-111111111111",
	}
	command, err := composeUpCommand(context.Background(), installation)
	if err != nil {
		t.Fatal(err)
	}
	if command.Dir != installation.Directory {
		t.Fatalf("command directory=%q", command.Dir)
	}
	for _, entry := range command.Env {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "PUNARO_") || strings.HasPrefix(name, "COMPOSE_") {
			t.Fatalf("unsafe inherited variable %q", name)
		}
	}
	if !slices.Contains(command.Env, "PWD="+installation.Directory) {
		t.Fatalf("command environment lacks trusted PWD: %v", command.Env)
	}
}

func TestUpRefusesExistingUpgradeBeforeMigrationOrStart(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	migrated, started, pairChecked := false, false, false
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.UpgradeRequired, Version: 3}, nil
	}
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		migrated = true
		return punaropostgres.SchemaState{}, nil
	}
	startServices = func(context.Context, operator.Installation) error { started = true; return nil }
	verifyInstallationPair = func(context.Context, string, string) error { pairChecked = true; return errors.New("must not run") }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 1 || migrated || started || pairChecked || !strings.Contains(stderr.String(), "no in-place updater") || !strings.Contains(stderr.String(), "previous compatible release") || strings.Contains(stderr.String(), "punaro update") {
		t.Fatalf("code=%d migrated=%t started=%t pairChecked=%t stdout=%q stderr=%q", code, migrated, started, pairChecked, stdout.String(), stderr.String())
	}
}

func TestDoctorClassifiesOldSchemaBeforeRolePair(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.UpgradeRequired, Version: 3}, nil
	}
	pairChecked := false
	verifyInstallationPair = func(context.Context, string, string) error { pairChecked = true; return errors.New("must not run") }
	probe = func(context.Context, string) error { return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor", "--directory", directory}, &stdout, &stderr); code != 1 || pairChecked || !strings.Contains(stdout.String(), "schema not compatible") || strings.Contains(stdout.String(), "database roles target different") {
		t.Fatalf("code=%d pairChecked=%t stdout=%q stderr=%q", code, pairChecked, stdout.String(), stderr.String())
	}
}

func TestUpRefusesResetPristineDatabase(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	migrateCalls, startCalls, probeCalls := 0, 0, 0
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Pristine}, nil
	}
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		migrateCalls++
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	startServices = func(context.Context, operator.Installation) error { startCalls++; return nil }
	probe = func(context.Context, string) error { probeCalls++; return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if migrateCalls != 0 || startCalls != 0 || probeCalls != 0 || !strings.Contains(stderr.String(), "schema is pristine") {
		t.Fatalf("migrate=%d start=%d probe=%d stderr=%q", migrateCalls, startCalls, probeCalls, stderr.String())
	}
}

func TestUpStartsCompatibleThenDoctors(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectCalls, startCalls, probeCalls := 0, 0, 0
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		inspectCalls++
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	startServices = func(context.Context, operator.Installation) error { startCalls++; return nil }
	probe = func(context.Context, string) error { probeCalls++; return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if startCalls != 1 || inspectCalls != 2 || probeCalls != 3 {
		t.Fatalf("inspect=%d start=%d probe=%d", inspectCalls, startCalls, probeCalls)
	}
}

func TestUpRefusesMismatchedInstallationPairBeforeStart(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	verifyInstallationPair = func(context.Context, string, string) error {
		return errors.New("different installation")
	}
	started := false
	startServices = func(context.Context, operator.Installation) error { started = true; return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 1 || started || !strings.Contains(stderr.String(), "database roles") {
		t.Fatalf("code=%d started=%t stdout=%q stderr=%q", code, started, stdout.String(), stderr.String())
	}
}

func TestDoctorFailsForConfigurationDriftAndRoleMismatch(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	installation, err := operator.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(installation.BackupDir); err != nil {
		t.Fatal(err)
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	verifyInstallationPair = func(context.Context, string, string) error {
		return errors.New("different installation")
	}
	probe = func(context.Context, string) error { return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor", "--directory", directory}, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), `"healthy": false`) || !strings.Contains(stdout.String(), "database roles target different installations") || !strings.Contains(stdout.String(), "backup directory") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestInitMigratesPristineBeforeCreatingOwner(t *testing.T) {
	preserveDependencies(t)
	root := t.TempDir()
	for _, name := range []string{"data", "backup"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"owner.dsn", "app.dsn"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("postgres://invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sequence := []string{}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		sequence = append(sequence, "inspect")
		if len(sequence) == 1 {
			return punaropostgres.SchemaState{Classification: punaropostgres.Pristine}, nil
		}
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		sequence = append(sequence, "migrate")
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	createOwner = func(context.Context, string, string) (punaropostgres.Principal, error) {
		sequence = append(sequence, "owner")
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	}
	args := []string{"init", "--directory", filepath.Join(root, "install"), "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "backup"), "--image", cliTestImage, "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn"), "--owner-name", "operator", "--mode", "internet", "--public-url", "https://punaro.example"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 || strings.Join(sequence, ",") != "inspect,migrate,inspect,owner" {
		t.Fatalf("code=%d sequence=%v stdout=%q stderr=%q", code, sequence, stdout.String(), stderr.String())
	}
}

func TestInitProvesPristineDSNPairBeforeMigration(t *testing.T) {
	preserveDependencies(t)
	root := t.TempDir()
	for _, name := range []string{"data", "backup"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"owner.dsn", "app.dsn"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("postgres://invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Pristine}, nil
	}
	migratePristinePair = func(context.Context, string, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{}, fmt.Errorf("%w: different pristine databases", punaropostgres.ErrMigrationNotAttempted)
	}
	args := []string{"init", "--directory", filepath.Join(root, "install"), "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "backup"), "--image", cliTestImage, "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn"), "--owner-name", "operator", "--mode", "internet", "--public-url", "https://punaro.example"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "requires a pristine") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "install")); !os.IsNotExist(err) {
		t.Fatalf("pre-migration refusal left a resumable stage: %v", err)
	}
}

func TestInitRefusesAlreadyCompatibleDatabase(t *testing.T) {
	preserveDependencies(t)
	root := t.TempDir()
	for _, name := range []string{"data", "backup"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"owner.dsn", "app.dsn"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("postgres://invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	created := false
	createOwner = func(context.Context, string, string) (punaropostgres.Principal, error) {
		created = true
		return punaropostgres.Principal{}, nil
	}
	args := []string{"init", "--directory", filepath.Join(root, "install"), "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "backup"), "--image", cliTestImage, "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn"), "--owner-name", "operator", "--mode", "internet", "--public-url", "https://punaro.example"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || created || !strings.Contains(stderr.String(), "requires a pristine") {
		t.Fatalf("code=%d created=%t stdout=%q stderr=%q", code, created, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "install")); !os.IsNotExist(err) {
		t.Fatalf("refused fresh init left a resumable stage: %v", err)
	}
}

func TestUpRefusesCompatibleDatabaseWithDifferentOwner(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	inspectOwner = func(context.Context, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "22222222-2222-4222-8222-222222222222"}, nil
	}
	started := false
	startServices = func(context.Context, operator.Installation) error { started = true; return nil }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 1 || started || !strings.Contains(stderr.String(), "owner does not match") {
		t.Fatalf("code=%d started=%t stdout=%q stderr=%q", code, started, stdout.String(), stderr.String())
	}
}

func TestInitResumeRecoversUncertainOwnerOutcome(t *testing.T) {
	preserveDependencies(t)
	root := t.TempDir()
	for _, name := range []string{"data", "backup"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"owner.dsn", "app.dsn"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("postgres://invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inspectCalls := 0
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		inspectCalls++
		if inspectCalls == 1 {
			return punaropostgres.SchemaState{Classification: punaropostgres.Pristine}, nil
		}
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	createOwner = func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{}, context.DeadlineExceeded
	}
	directory := filepath.Join(root, "install")
	args := []string{"init", "--directory", directory, "--data-dir", filepath.Join(root, "data"), "--backup-dir", filepath.Join(root, "backup"), "--image", cliTestImage, "--owner-dsn-file", filepath.Join(root, "owner.dsn"), "--app-dsn-file", filepath.Join(root, "app.dsn"), "--owner-name", "operator", "--mode", "internet", "--public-url", "https://punaro.example"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "--resume") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	recoverInstallationOwner = func(_ context.Context, installation operator.Installation) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111", DisplayName: installation.OwnerName}, nil
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"init", "--resume", "--directory", directory}, &stdout, &stderr); code != 0 {
		t.Fatalf("resume code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestClientAddPrintsPreviewWithoutDatabaseMutation(t *testing.T) {
	directory := testInstallation(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"client", "add", "--directory", directory, "--name", "laptop", "--all-projects"}, &stdout, &stderr); code != 3 || !strings.Contains(stdout.String(), "trusted-agent") || !strings.Contains(stderr.String(), "rerun with --yes") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestClientAddRefusesYesWithoutPriorExactPreviewHash(t *testing.T) {
	directory := testInstallation(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"client", "add", "--directory", directory, "--name", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", "stale"}, &stdout, &stderr); code != 3 || !strings.Contains(stderr.String(), "does not match") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestClientAddRefusesMutationWhenDatabaseRolesDiffer(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	verifyInstallationPair = func(context.Context, string, string) error {
		return errors.New("different installation")
	}
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	var stdout, stderr bytes.Buffer
	_, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"client", "add", "--directory", directory, "--name", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", previewHash}
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "database roles") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestClientAddRevalidatesPathsAndOwnerBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{name: "path drift", mutate: func(t *testing.T, directory string) {
			installation, err := operator.Load(directory)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(installation.BackupDir); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "owner mismatch", mutate: func(_ *testing.T, _ string) {
			inspectOwner = func(context.Context, string) (punaropostgres.Principal, error) {
				return punaropostgres.Principal{ID: "22222222-2222-4222-8222-222222222222"}, nil
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			preserveDependencies(t)
			directory := testInstallation(t)
			inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
				return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
			}
			test.mutate(t, directory)
			issued := false
			issueEnrollment = func(context.Context, operator.Installation, punaropostgres.EnrollmentRequest, string) (punaropostgres.PendingEnrollment, error) {
				issued = true
				return punaropostgres.PendingEnrollment{}, nil
			}
			_, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(nil, true)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			args := []string{"client", "add", "--directory", directory, "--name", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", previewHash}
			if code := run(args, &stdout, &stderr); code != 1 || issued {
				t.Fatalf("code=%d issued=%t stdout=%q stderr=%q", code, issued, stdout.String(), stderr.String())
			}
		})
	}
}

func TestConfirmedClientAddEmitsOnlyEnrollmentJSON(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 5}, nil
	}
	issueEnrollment = func(_ context.Context, _ operator.Installation, request punaropostgres.EnrollmentRequest, previewHash string) (punaropostgres.PendingEnrollment, error) {
		return punaropostgres.PendingEnrollment{ID: "22222222-2222-4222-8222-222222222222", ClientBinding: request.ClientBinding, Code: "one-time-code", PreviewHash: previewHash}, nil
	}
	_, previewHash, err := punaropostgres.PreviewTrustedAgentEnrollment(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"client", "add", "--directory", directory, "--name", "laptop", "--all-projects", "--yes", "--confirm-preview-hash", previewHash}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	decoder := json.NewDecoder(&stdout)
	var pending punaropostgres.PendingEnrollment
	if err := decoder.Decode(&pending); err != nil || pending.Code != "one-time-code" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("confirmed add emitted multiple JSON documents: extra=%#v err=%v", extra, err)
	}
}
