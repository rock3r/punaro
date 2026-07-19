package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

const cliTestImage = "registry.example/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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
	originalInspect, originalOwner, originalMigrate := inspectSchema, inspectOwner, migrateSchema
	originalCreate, originalRecover := createOwner, recoverInstallationOwner
	originalVerify := verifyInstallationPair
	originalStart, originalProbe := startServices, probe
	t.Cleanup(func() {
		inspectSchema, inspectOwner, migrateSchema = originalInspect, originalOwner, originalMigrate
		createOwner, recoverInstallationOwner = originalCreate, originalRecover
		verifyInstallationPair = originalVerify
		startServices, probe = originalStart, originalProbe
	})
	inspectOwner = func(context.Context, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111", DisplayName: "owner"}, nil
	}
	verifyInstallationPair = func(context.Context, string, string) error { return nil }
}

func TestUpRefusesExistingUpgradeBeforeMigrationOrStart(t *testing.T) {
	preserveDependencies(t)
	directory := testInstallation(t)
	migrated, started, pairChecked := false, false, false
	inspectSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		return punaropostgres.SchemaState{Classification: punaropostgres.UpgradeRequired, Version: 3}, nil
	}
	migrateSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		migrated = true
		return punaropostgres.SchemaState{}, nil
	}
	startServices = func(context.Context, operator.Installation) error { started = true; return nil }
	verifyInstallationPair = func(context.Context, string, string) error { pairChecked = true; return errors.New("must not run") }
	var stdout, stderr bytes.Buffer
	if code := run([]string{"up", "--directory", directory}, &stdout, &stderr); code != 1 || migrated || started || pairChecked || !strings.Contains(stderr.String(), "punaro update") {
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
	migrateSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		migrateCalls++
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 4}, nil
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 4}, nil
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 4}, nil
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 4}, nil
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 4}, nil
	}
	migrateSchema = func(context.Context, string) (punaropostgres.SchemaState, error) {
		sequence = append(sequence, "migrate")
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 4}, nil
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 4}, nil
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 4}, nil
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 4}, nil
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
		return punaropostgres.SchemaState{Classification: punaropostgres.Compatible, Version: 4}, nil
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
