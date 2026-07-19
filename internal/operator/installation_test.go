package operator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
		{state: punaropostgres.UpgradeRequired, want: RefuseUpgradeRequired},
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

func TestLoadAndCheckPathsRejectInstallationDirectoryPermissionDrift(t *testing.T) {
	options := validInitOptions(t)
	installation, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- the regression deliberately creates unsafe permission drift.
	if err := os.Chmod(options.Directory, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(options.Directory); err == nil {
		t.Fatal("Load accepted a group-writable installation directory")
	}
	if !containsFailure(CheckPaths(installation), "installation directory unavailable or unsafe") {
		t.Fatalf("failures=%v", CheckPaths(installation))
	}
}

func TestLoadAndCheckPathsRejectWritableInstallationAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory trust semantics")
	}
	options := validInitOptions(t)
	installation, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Dir(options.Directory)
	// #nosec G302 -- the regression deliberately creates an unsafe ancestor.
	if err := os.Chmod(ancestor, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// #nosec G302 -- restore the required private directory mode.
		_ = os.Chmod(ancestor, 0o700)
	})
	if _, err := Load(options.Directory); err == nil {
		t.Fatal("Load accepted an installation below a writable non-sticky ancestor")
	}
	if !containsFailure(CheckPaths(installation), "installation directory unavailable or unsafe") {
		t.Fatalf("failures=%v", CheckPaths(installation))
	}
}

func TestInitRejectsWritableInstallationAncestorBeforeBootstrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory trust semantics")
	}
	options := validInitOptions(t)
	ancestor := filepath.Dir(options.Directory)
	// #nosec G302 -- the regression deliberately creates an unsafe ancestor.
	if err := os.Chmod(ancestor, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// #nosec G302 -- restore the required private directory mode.
		_ = os.Chmod(ancestor, 0o700)
	})
	called := false
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		called = true
		return punaropostgres.Principal{}, nil
	}); err == nil || called {
		t.Fatalf("unsafe ancestor err=%v bootstrapCalled=%t", err, called)
	}
}

func TestLoadAcceptsStickyWritableInstallationAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory trust semantics")
	}
	options := validInitOptions(t)
	installation, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Dir(options.Directory)
	if err := os.Chmod(ancestor, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// #nosec G302 -- restore the required private directory mode.
		_ = os.Chmod(ancestor, 0o700)
	})
	if _, err := Load(options.Directory); err != nil {
		t.Fatalf("Load rejected sticky writable ancestor: %v", err)
	}
	if failures := CheckPaths(installation); len(failures) != 0 {
		t.Fatalf("failures=%v", failures)
	}
}

func TestInitRejectsSymlinkedInstallationAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory trust semantics")
	}
	options := validInitOptions(t)
	target := filepath.Join(filepath.Dir(options.Directory), "trusted-parent")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(options.Directory), "parent-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	options.Directory = filepath.Join(link, "installation")
	called := false
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		called = true
		return punaropostgres.Principal{}, nil
	}); err == nil || called {
		t.Fatalf("symlinked ancestor err=%v bootstrapCalled=%t", err, called)
	}
}

func TestInitRejectsUnsafeSensitivePathAncestorsBeforeBootstrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory trust semantics")
	}
	for _, kind := range []string{"data", "backup", "owner DSN", "application DSN"} {
		t.Run(kind, func(t *testing.T) {
			options := validInitOptions(t)
			parent := filepath.Join(filepath.Dir(options.Directory), strings.ReplaceAll(kind, " ", "-")+"-parent")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "data", "backup":
				leaf := filepath.Join(parent, "private")
				if err := os.Mkdir(leaf, 0o700); err != nil {
					t.Fatal(err)
				}
				if kind == "data" {
					options.DataDir = leaf
				} else {
					options.BackupDir = leaf
				}
			case "owner DSN", "application DSN":
				leaf := filepath.Join(parent, "database.dsn")
				protectedFile(t, leaf)
				if kind == "owner DSN" {
					options.OwnerDSNFile = leaf
				} else {
					options.AppDSNFile = leaf
				}
			}
			// #nosec G302 -- the regression deliberately creates an unsafe ancestor.
			if err := os.Chmod(parent, 0o777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				// #nosec G302 -- restore the required private directory mode.
				_ = os.Chmod(parent, 0o700)
			})
			called := false
			if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
				called = true
				return punaropostgres.Principal{}, nil
			}); err == nil || called {
				t.Fatalf("unsafe %s ancestor err=%v bootstrapCalled=%t", kind, err, called)
			}
		})
	}
}

func TestLoadAndResumeRejectExistingNonCanonicalInstallationPath(t *testing.T) {
	options := validInitOptions(t)
	if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	rawDirectory := options.Directory + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(options.Directory)
	if _, err := os.Stat(rawDirectory); err != nil {
		t.Fatalf("non-canonical path does not resolve to the installation: %v", err)
	}
	if _, err := Load(rawDirectory); err == nil {
		t.Fatal("Load accepted an existing non-canonical installation path")
	}
	recovered := false
	if _, err := Resume(context.Background(), rawDirectory, func(context.Context, Installation) (punaropostgres.Principal, error) {
		recovered = true
		return punaropostgres.Principal{}, nil
	}); err == nil || recovered {
		t.Fatalf("Resume err=%v recoveryCalled=%t", err, recovered)
	}
}

func TestCheckPathsRejectsSensitivePathAncestorPermissionDrift(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory trust semantics")
	}
	for _, test := range []struct {
		kind    string
		failure string
	}{
		{kind: "data", failure: "data directory unavailable or unsafe"},
		{kind: "backup", failure: "backup directory unavailable or unsafe"},
		{kind: "owner DSN", failure: "owner DSN file unavailable or unsafe"},
		{kind: "application DSN", failure: "application DSN file unavailable or unsafe"},
	} {
		t.Run(test.kind, func(t *testing.T) {
			options := validInitOptions(t)
			parent := filepath.Join(filepath.Dir(options.Directory), strings.ReplaceAll(test.kind, " ", "-")+"-parent")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			switch test.kind {
			case "data", "backup":
				leaf := filepath.Join(parent, "private")
				if err := os.Mkdir(leaf, 0o700); err != nil {
					t.Fatal(err)
				}
				if test.kind == "data" {
					options.DataDir = leaf
				} else {
					options.BackupDir = leaf
				}
			case "owner DSN", "application DSN":
				leaf := filepath.Join(parent, "database.dsn")
				protectedFile(t, leaf)
				if test.kind == "owner DSN" {
					options.OwnerDSNFile = leaf
				} else {
					options.AppDSNFile = leaf
				}
			}
			installation, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
				return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			// #nosec G302 -- the regression deliberately creates unsafe permission drift.
			if err := os.Chmod(parent, 0o777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				// #nosec G302 -- restore the required private directory mode.
				_ = os.Chmod(parent, 0o700)
			})
			if _, err := Load(options.Directory); err != nil {
				t.Fatalf("unrelated published installation became unreadable: %v", err)
			}
			if failures := CheckPaths(installation); !containsFailure(failures, test.failure) {
				t.Fatalf("failures=%v", failures)
			}
		})
	}
}

func TestLoadRejectsPersistedRuntimeIdentityMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix runtime identity semantics")
	}
	options := validInitOptions(t)
	installation, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(options.Directory, configName)
	body, err := os.ReadFile(path) // #nosec G304 -- fixed generated marker in the test installation.
	if err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.Replace(string(body), `"runtime_uid": "`+installation.RuntimeUID+`"`, `"runtime_uid": "4294967294"`, 1))
	if err := os.WriteFile(path, body, 0o600); err != nil { // #nosec G703 -- fixed generated marker in the test installation.
		t.Fatal(err)
	}
	if _, err := Load(options.Directory); err == nil {
		t.Fatal("Load accepted a persisted runtime identity mismatch")
	}
}

func TestComposeProjectNameUsesStableOwnerIdentity(t *testing.T) {
	first := Installation{Directory: "/srv/a/punaro", OwnerPrincipalID: "11111111-1111-4111-8111-111111111111"}
	moved := Installation{Directory: "/srv/b/punaro", OwnerPrincipalID: first.OwnerPrincipalID}
	second := Installation{Directory: "/srv/c/punaro", OwnerPrincipalID: "22222222-2222-4222-8222-222222222222"}
	firstName, firstErr := ComposeProjectName(first)
	movedName, movedErr := ComposeProjectName(moved)
	secondName, secondErr := ComposeProjectName(second)
	if firstErr != nil || movedErr != nil || secondErr != nil || firstName != movedName || firstName == secondName {
		t.Fatalf("first=%q/%v moved=%q/%v second=%q/%v", firstName, firstErr, movedName, movedErr, secondName, secondErr)
	}
	if !regexp.MustCompile(`^punaro-[0-9a-f]{32}$`).MatchString(firstName) {
		t.Fatalf("invalid Compose project name %q", firstName)
	}
	if _, err := ComposeProjectName(Installation{OwnerPrincipalID: "invalid"}); err == nil {
		t.Fatal("invalid owner identity produced a Compose project name")
	}
}

func TestGeneratedConfigurationUsesDedicatedLoopbackHealthListener(t *testing.T) {
	options := validInitOptions(t)
	installation, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if installation.HealthListenAddr != "127.0.0.1:8081" || installation.HealthURL != "http://127.0.0.1:8081" {
		t.Fatalf("health listener=%q URL=%q", installation.HealthListenAddr, installation.HealthURL)
	}
	body, err := os.ReadFile(EnvFile(installation.Directory))
	if err != nil || !strings.Contains(string(body), "PUNARO_HEALTH_LISTEN_ADDR=127.0.0.1:8081\n") {
		t.Fatalf("env=%q err=%v", body, err)
	}
}

func TestInitRejectsInvalidOrAliasingHealthListener(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1:", "127.0.0.1:http", "127.0.0.1:65536", "127.0.0.1:08080"} {
		t.Run(address, func(t *testing.T) {
			options := validInitOptions(t)
			options.HealthListenAddr = address
			if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
				return punaropostgres.Principal{}, nil
			}); err == nil {
				t.Fatalf("health listener accepted %q", address)
			}
		})
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

func TestInitRejectsNonCanonicalSensitivePathsBeforeBootstrap(t *testing.T) {
	for _, kind := range []string{"installation", "data", "backup", "owner DSN", "application DSN"} {
		t.Run(kind, func(t *testing.T) {
			options := validInitOptions(t)
			root := filepath.Dir(options.Directory)
			nonCanonical := root + string(filepath.Separator) + "alias" + string(filepath.Separator) + ".." + string(filepath.Separator) + "target"
			switch kind {
			case "installation":
				options.Directory = nonCanonical
			case "data":
				options.DataDir = nonCanonical
			case "backup":
				options.BackupDir = nonCanonical
			case "owner DSN":
				options.OwnerDSNFile = nonCanonical
			case "application DSN":
				options.AppDSNFile = nonCanonical
			}
			if _, err := validateStatic(options); err == nil {
				t.Fatalf("validateStatic accepted non-canonical %s path", kind)
			}
			called := false
			if _, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
				called = true
				return punaropostgres.Principal{}, nil
			}); err == nil || called {
				t.Fatalf("non-canonical %s path err=%v bootstrapCalled=%t", kind, err, called)
			}
		})
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
	backupParent := filepath.Join(root, "backup-parent")
	if err := os.Mkdir(backupParent, 0o700); err != nil {
		t.Fatal(err)
	}
	realBackup := filepath.Join(backupParent, "backup")
	if err := os.Mkdir(realBackup, 0o700); err != nil {
		t.Fatal(err)
	}
	options.BackupDir = realBackup
	installation, err := Init(context.Background(), options, func(context.Context, string, string) (punaropostgres.Principal, error) {
		return punaropostgres.Principal{ID: "11111111-1111-4111-8111-111111111111"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(options.DataDir, "backup"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backupParent, backupParent+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(options.DataDir, backupParent); err != nil {
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
