package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestVerifyAcceptsExactPrivateBackup(t *testing.T) {
	directory := t.TempDir()
	requirePrivate(t, directory)
	paths := writeRequiredTestFiles(t, directory)
	manifest := testManifest(t, directory, paths)
	writeManifest(t, directory, manifest)

	verified, err := Verify(directory)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.BackupID != manifest.BackupID || verified.State != manifest.State || len(verified.Files) != len(paths) {
		t.Fatalf("unexpected verified manifest: %#v", verified)
	}
}

func TestReadVerifiedFileRejectsPathReplacementAfterManifestVerification(t *testing.T) {
	directory := t.TempDir()
	requirePrivate(t, directory)
	paths := writeRequiredTestFiles(t, directory)
	manifest := testManifest(t, directory, paths)
	writeManifest(t, directory, manifest)
	verified, err := Verify(directory)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "config", "installation.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVerifiedFile(directory, verified, "config/installation.json", maximumManifest); err == nil {
		t.Fatal("path replacement was accepted after manifest verification")
	}
}

func TestVerifyRejectsUntrustedManifestAndFiles(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string, *Manifest)
	}{
		{name: "unknown field", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			body, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			body = append(body[:len(body)-1], []byte(`,"unexpected":true}`)...)
			writeRawManifest(t, directory, body)
		}},
		{name: "trailing data", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			body, _ := json.Marshal(manifest)
			writeRawManifest(t, directory, append(body, []byte(` {}`)...))
		}},
		{name: "duplicate JSON key", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			body, _ := json.Marshal(manifest)
			body = append([]byte(`{"version":1,`), body[1:]...)
			writeRawManifest(t, directory, body)
		}},
		{name: "duplicate path", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			manifest.Files = append(manifest.Files, manifest.Files[0])
			writeManifest(t, directory, *manifest)
		}},
		{name: "reordered files", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			manifest.Files[0], manifest.Files[1] = manifest.Files[1], manifest.Files[0]
			writeManifest(t, directory, *manifest)
		}},
		{name: "reordered dependencies", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			manifest.ExternalDependencies[0], manifest.ExternalDependencies[1] = manifest.ExternalDependencies[1], manifest.ExternalDependencies[0]
			writeManifest(t, directory, *manifest)
		}},
		{name: "missing dependency", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			manifest.ExternalDependencies = manifest.ExternalDependencies[:len(manifest.ExternalDependencies)-1]
			writeManifest(t, directory, *manifest)
		}},
		{name: "traversal", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			manifest.Files[0].Path = "../database.dump"
			writeManifest(t, directory, *manifest)
		}},
		{name: "absolute", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			manifest.Files[0].Path = filepath.Join(directory, "database.dump")
			writeManifest(t, directory, *manifest)
		}},
		{name: "digest mismatch", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			manifest.Files[0].SHA256 = strings.Repeat("0", 64)
			writeManifest(t, directory, *manifest)
		}},
		{name: "size mismatch", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			manifest.Files[0].Size++
			writeManifest(t, directory, *manifest)
		}},
		{name: "symlink", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			if err := os.Remove(filepath.Join(directory, "database.dump")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(directory, "config", "installation.json"), filepath.Join(directory, "database.dump")); err != nil {
				t.Fatal(err)
			}
			writeManifest(t, directory, *manifest)
		}},
		{name: "missing required dump", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			manifest.Files = manifest.Files[1:]
			writeManifest(t, directory, *manifest)
		}},
		{name: "unexpected sensitive file", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			writeBackupFile(t, directory, "credentials/extra.dsn", []byte("secret"))
			writeManifest(t, directory, *manifest)
		}},
		{name: "undeclared namespace", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			writeBackupFile(t, directory, "notes.txt", []byte("unexpected"))
			body, _ := os.ReadFile(filepath.Join(directory, "notes.txt")) // #nosec G304 -- test fixture path.
			sum := sha256.Sum256(body)
			manifest.Files = append(manifest.Files, File{Path: "notes.txt", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
			sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
			writeManifest(t, directory, *manifest)
		}},
		{name: "oversized blob declaration", mutate: func(t *testing.T, directory string, manifest *Manifest) {
			manifest.Files = append(manifest.Files, File{Path: "blobs/huge", Size: maximumBlobSize + 1, SHA256: strings.Repeat("a", 64)})
			sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
			writeManifest(t, directory, *manifest)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			requirePrivate(t, directory)
			paths := writeRequiredTestFiles(t, directory)
			manifest := testManifest(t, directory, paths)
			test.mutate(t, directory, &manifest)
			if _, err := Verify(directory); err == nil {
				t.Fatal("verification unexpectedly succeeded")
			}
		})
	}
}

func TestListSkipsInvalidAndIncompleteCandidates(t *testing.T) {
	root := t.TempDir()
	requirePrivate(t, root)
	valid := filepath.Join(root, "valid")
	if err := os.Mkdir(valid, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := writeRequiredTestFiles(t, valid)
	writeManifest(t, valid, testManifest(t, valid, paths))
	if err := os.Mkdir(filepath.Join(root, ".incomplete"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(valid, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}

	backups, err := List(root)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(backups) != 1 || backups[0].Directory != valid {
		t.Fatalf("unexpected candidates: %#v", backups)
	}
}

func testManifest(t *testing.T, directory string, paths []string) Manifest {
	t.Helper()
	files := make([]File, 0, len(paths))
	for _, path := range paths {
		// #nosec G304 -- path comes from fixed test fixture labels.
		body, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		files = append(files, File{Path: path, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return Manifest{
		Version:       1,
		BackupID:      "018f47f4-7b18-7cc2-98d6-31d4fb5ab742",
		CreatedAt:     time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC),
		SnapshotID:    "00000003-0000001B-1",
		SchemaVersion: 5,
		State: State{
			InstallationID: "4e02b0e5-1934-4dda-9c4a-767c120c2fac",
			TimelineID:     "797476ad-8fdc-4c05-b144-3ccbb92b54bf",
			ChangeSequence: 42,
		},
		Files:                files,
		ExternalDependencies: []string{"host-tls", "oauth", "reverse-proxy", "telegram", "tunnel"},
	}
}

func writeRequiredTestFiles(t *testing.T, directory string) []string {
	t.Helper()
	files := map[string]string{ // #nosec G101 -- non-secret backup fixture labels.
		"database.dump":                "database",
		"config/installation.json":     "configuration",
		"config/punarod.env":           "environment",
		"config/compose.operator.yaml": "compose",
		"credentials/owner.dsn":        "owner credential",
		"credentials/app.dsn":          "application credential",
	}
	paths := []string{"database.dump", "config/installation.json", "config/punarod.env", "config/compose.operator.yaml", "credentials/owner.dsn", "credentials/app.dsn"}
	for _, path := range paths {
		writeBackupFile(t, directory, path, []byte(files[path]))
	}
	return paths
}

func writeBackupFile(t *testing.T, directory, path string, body []byte) {
	t.Helper()
	full := filepath.Join(directory, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeManifest(t *testing.T, directory string, manifest Manifest) {
	t.Helper()
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeRawManifest(t, directory, body)
}

func writeRawManifest(t *testing.T, directory string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func requirePrivate(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o700); err != nil { // #nosec G302 -- private test directory.
		t.Fatal(err)
	}
}
