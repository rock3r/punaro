package operator

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rock3r/punaro/internal/ingress"
)

func TestParseInstallationArtifactAcceptsOmittedHistoricalDirectory(t *testing.T) {
	installation := Installation{Version: 1, Directory: filepath.Join(t.TempDir(), "source-installation"), DataDir: filepath.Join(t.TempDir(), "data"), BackupDir: filepath.Join(t.TempDir(), "backups"), Image: testImage, OwnerDSNFile: filepath.Join(t.TempDir(), "owner.dsn"), AppDSNFile: filepath.Join(t.TempDir(), "app.dsn"), OwnerPrincipalID: "11111111-1111-4111-8111-111111111111", OwnerName: "Primary operator", Ingress: ingress.Policy{Mode: ingress.Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"}, HealthListenAddr: "127.0.0.1:8081", HealthURL: "http://127.0.0.1:8081"}
	body, err := json.Marshal(installation)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInstallationArtifact(body)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Directory != "" || parsed.OwnerPrincipalID != installation.OwnerPrincipalID || parsed.DataDir != installation.DataDir {
		t.Fatalf("parsed artifact=%#v", parsed)
	}
}

func TestPrepareAndPublishRestoreCreatesOnlyNewInstallation(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- private test directory.
		t.Fatal(err)
	}
	backupDir := filepath.Join(root, "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ownerDSN := filepath.Join(root, "target-owner.dsn")
	appDSN := filepath.Join(root, "target-app.dsn")
	protectedFile(t, ownerDSN)
	protectedFile(t, appDSN)
	options := RestoreOptions{
		Source:       Installation{Version: 1, Image: testImage, OwnerPrincipalID: "11111111-1111-4111-8111-111111111111", OwnerName: "Primary operator", Ingress: ingress.Policy{Mode: ingress.Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"}, HealthListenAddr: "127.0.0.1:8081", HealthURL: "http://127.0.0.1:8081"},
		Directory:    filepath.Join(root, "restored-installation"),
		DataDir:      filepath.Join(root, "restored-data"),
		BackupDir:    backupDir,
		OwnerDSNFile: ownerDSN,
		AppDSNFile:   appDSN,
	}
	installation, err := PrepareRestore(options)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := os.Lstat(options.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepare mutated installation path: %v", err)
	}
	if err := os.Mkdir(options.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PublishRestore(installation); err != nil {
		t.Fatalf("publish: %v", err)
	}
	loaded, err := Load(options.Directory)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.OwnerPrincipalID != options.Source.OwnerPrincipalID || loaded.DataDir != options.DataDir || loaded.RuntimeUID == "" || loaded.RuntimeGID == "" {
		t.Fatalf("unexpected restored installation: %#v", loaded)
	}
}

func TestPrepareRestoreRefusesExistingOrOverlappingTargets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *RestoreOptions)
	}{
		{name: "existing installation", mutate: func(t *testing.T, options *RestoreOptions) {
			if err := os.Mkdir(options.Directory, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "data below backup", mutate: func(_ *testing.T, options *RestoreOptions) {
			options.DataDir = filepath.Join(options.BackupDir, "restored-data")
		}},
		{name: "operator state below data", mutate: func(_ *testing.T, options *RestoreOptions) {
			options.Directory = filepath.Join(options.DataDir, "operator")
		}},
		{name: "invalid source identity", mutate: func(_ *testing.T, options *RestoreOptions) {
			options.Source.OwnerPrincipalID = "not-a-uuid"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- private test directory.
				t.Fatal(err)
			}
			backupDir := filepath.Join(root, "backups")
			if err := os.Mkdir(backupDir, 0o700); err != nil {
				t.Fatal(err)
			}
			ownerDSN := filepath.Join(root, "owner.dsn")
			appDSN := filepath.Join(root, "app.dsn")
			protectedFile(t, ownerDSN)
			protectedFile(t, appDSN)
			options := RestoreOptions{Source: Installation{Version: 1, Image: testImage, OwnerPrincipalID: "11111111-1111-4111-8111-111111111111", OwnerName: "owner", Ingress: ingress.Policy{Mode: ingress.Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"}, HealthListenAddr: "127.0.0.1:8081", HealthURL: "http://127.0.0.1:8081"}, Directory: filepath.Join(root, "install"), DataDir: filepath.Join(root, "data"), BackupDir: backupDir, OwnerDSNFile: ownerDSN, AppDSNFile: appDSN}
			test.mutate(t, &options)
			if _, err := PrepareRestore(options); err == nil {
				t.Fatal("unsafe restore preparation unexpectedly succeeded")
			}
		})
	}
}
