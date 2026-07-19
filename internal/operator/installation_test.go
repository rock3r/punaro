package operator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/ingress"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

const testImage = "registry.example/punaro@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func protectedFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("postgres://example.invalid/punaro\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func validInitOptions(t *testing.T) InitOptions {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	backup := filepath.Join(root, "backup")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	ownerDSN := filepath.Join(root, "owner.dsn")
	appDSN := filepath.Join(root, "app.dsn")
	protectedFile(t, ownerDSN)
	protectedFile(t, appDSN)
	return InitOptions{
		Directory:    filepath.Join(root, "installation"),
		DataDir:      data,
		BackupDir:    backup,
		Image:        testImage,
		OwnerDSNFile: ownerDSN,
		AppDSNFile:   appDSN,
		OwnerName:    "Primary operator",
		Ingress:      ingress.Policy{Mode: ingress.Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"},
	}
}

func TestInitPublishesConfigurationOnlyAfterOwnerBootstrap(t *testing.T) {
	options := validInitOptions(t)
	called := false
	installation, err := Init(context.Background(), options, func(_ context.Context, dsnFile, name string) (punaropostgres.Principal, error) {
		called = true
		if dsnFile != options.OwnerDSNFile || name != options.OwnerName {
			t.Fatalf("dsn=%q name=%q", dsnFile, name)
		}
		if _, err := os.Stat(filepath.Join(options.Directory, configName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("configuration was visible before bootstrap: %v", err)
		}
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111", DisplayName: name}, nil
	})
	if err != nil || !called {
		t.Fatalf("installation=%#v called=%t err=%v", installation, called, err)
	}
	loaded, err := Load(options.Directory)
	if err != nil || loaded.OwnerPrincipalID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	info, err := os.Stat(filepath.Join(options.Directory, configName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode=%v err=%v", info.Mode(), err)
	}
}

func TestInitFailureAndExistingDestinationAreFailClosed(t *testing.T) {
	options := validInitOptions(t)
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{}, errors.New("bootstrap failed")
	}); err == nil {
		t.Fatal("bootstrap failure was accepted")
	}
	if _, err := os.Stat(filepath.Join(options.Directory, configName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncertain initialization published state: %v", err)
	}
	if _, err := Resume(context.Background(), options.Directory, func(_ context.Context, installation Installation) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111", DisplayName: installation.OwnerName}, nil
	}); err != nil {
		t.Fatalf("staged initialization did not recover: %v", err)
	}
	called := false
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		called = true
		return punaropostgres.Principal{}, nil
	}); err == nil || called {
		t.Fatalf("existing destination err=%v bootstrapCalled=%t", err, called)
	}
}

func TestUpActionNeverMigratesExistingSchema(t *testing.T) {
	tests := []struct {
		state punaropostgres.Classification
		want  UpAction
	}{
		{state: punaropostgres.Pristine, want: RefuseAndRecover},
		{state: punaropostgres.Compatible, want: StartCompatible},
		{state: punaropostgres.UpgradeRequired, want: RefuseAndUpdate},
		{state: punaropostgres.Newer, want: RefuseAndRecover},
		{state: punaropostgres.Dirty, want: RefuseAndRecover},
		{state: punaropostgres.Incompatible, want: RefuseAndRecover},
	}
	for _, test := range tests {
		if got := DecideUp(punaropostgres.SchemaState{Classification: test.state}); got != test.want {
			t.Errorf("state=%s action=%s want=%s", test.state, got, test.want)
		}
	}
}

func TestLoadPreservesMissingPathDiagnosticsForDoctor(t *testing.T) {
	options := validInitOptions(t)
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(options.BackupDir); err != nil {
		t.Fatal(err)
	}
	installation, err := Load(options.Directory)
	if err != nil {
		t.Fatalf("missing runtime path hid the published configuration: %v", err)
	}
	failures := CheckPaths(installation)
	if len(failures) != 1 || failures[0] != "backup directory unavailable or unsafe" {
		t.Fatalf("failures=%v", failures)
	}
}

func TestInitRequiresDistinctRoleSecretFiles(t *testing.T) {
	options := validInitOptions(t)
	options.AppDSNFile = options.OwnerDSNFile
	called := false
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		called = true
		return punaropostgres.Principal{}, nil
	}); err == nil || called {
		t.Fatalf("same role file err=%v bootstrapCalled=%t", err, called)
	}
}

func TestInitRejectsOverlappingPathsAndUnpinnedImages(t *testing.T) {
	options := validInitOptions(t)
	options.BackupDir = filepath.Join(options.DataDir, ".")
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{}, nil
	}); err == nil {
		t.Fatal("aliased data and backup directories were accepted")
	}
	options = validInitOptions(t)
	options.Image = "registry.example/punaro:latest"
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{}, nil
	}); err == nil {
		t.Fatal("unpinned image was accepted")
	}
}

func TestInitRejectsOverlapThroughSymlinkedAncestor(t *testing.T) {
	options := validInitOptions(t)
	alias := filepath.Join(filepath.Dir(options.DataDir), "data-alias")
	if err := os.Symlink(options.DataDir, alias); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(alias, "backup")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	options.BackupDir = backup
	called := false
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		called = true
		return punaropostgres.Principal{}, nil
	}); err == nil || called {
		t.Fatalf("symlinked overlap err=%v bootstrapCalled=%t", err, called)
	}
}

func TestInitRejectsMalformedPinnedImageReference(t *testing.T) {
	options := validInitOptions(t)
	options.Image = "::::@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	called := false
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		called = true
		return punaropostgres.Principal{}, nil
	}); err == nil || called {
		t.Fatalf("malformed image err=%v bootstrapCalled=%t", err, called)
	}
}

func TestInitRejectsCredentialsAndOperatorStateBelowData(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *InitOptions)
	}{
		{name: "owner DSN direct", mutate: func(t *testing.T, options *InitOptions) {
			options.OwnerDSNFile = filepath.Join(options.DataDir, "owner.dsn")
			protectedFile(t, options.OwnerDSNFile)
		}},
		{name: "application DSN through symlinked ancestor", mutate: func(t *testing.T, options *InitOptions) {
			alias := filepath.Join(filepath.Dir(options.DataDir), "data-alias")
			if err := os.Symlink(options.DataDir, alias); err != nil {
				t.Fatal(err)
			}
			options.AppDSNFile = filepath.Join(alias, "app.dsn")
			protectedFile(t, options.AppDSNFile)
		}},
		{name: "operator state direct", mutate: func(_ *testing.T, options *InitOptions) {
			options.Directory = filepath.Join(options.DataDir, "operator")
		}},
		{name: "operator state through symlinked ancestor", mutate: func(t *testing.T, options *InitOptions) {
			alias := filepath.Join(filepath.Dir(options.DataDir), "data-alias")
			if err := os.Symlink(options.DataDir, alias); err != nil {
				t.Fatal(err)
			}
			options.Directory = filepath.Join(alias, "operator")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := validInitOptions(t)
			test.mutate(t, &options)
			called := false
			if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
				called = true
				return punaropostgres.Principal{}, nil
			}); err == nil || called {
				t.Fatalf("unsafe daemon overlap err=%v bootstrapCalled=%t", err, called)
			}
		})
	}
}

func TestCheckPathsDetectsBackupAncestorRetargetedBelowData(t *testing.T) {
	options := validInitOptions(t)
	root := filepath.Dir(options.DataDir)
	realBackupParent := filepath.Join(root, "real-backup-parent")
	if err := os.Mkdir(realBackupParent, 0o700); err != nil {
		t.Fatal(err)
	}
	realBackup := filepath.Join(realBackupParent, "backup")
	if err := os.Mkdir(realBackup, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "backup-alias")
	if err := os.Symlink(realBackupParent, alias); err != nil {
		t.Fatal(err)
	}
	options.BackupDir = filepath.Join(alias, "backup")
	installation, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(options.DataDir, "backup"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(options.DataDir, alias); err != nil {
		t.Fatal(err)
	}
	failures := CheckPaths(installation)
	if !containsFailure(failures, "data and backup directories overlap") {
		t.Fatalf("failures=%v", failures)
	}
}

func containsFailure(failures []string, want string) bool {
	for _, failure := range failures {
		if failure == want {
			return true
		}
	}
	return false
}

func TestGeneratedComposeUsesOnlyPinnedImage(t *testing.T) {
	options := validInitOptions(t)
	installation, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(OverrideFile(installation.Directory))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "image: ${PUNARO_IMAGE:?required}") || strings.Contains(string(body), "build:") {
		t.Fatalf("generated Compose is not immutable-image-only:\n%s", body)
	}
}
