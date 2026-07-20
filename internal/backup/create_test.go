package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreatePublishesOnlyVerifiedSnapshot(t *testing.T) {
	root, options := createTestInputs(t)
	blobBody := []byte("immutable ready blob")
	blobPath := filepath.Join(options.BlobRoot, "sha256", "ready")
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blobPath, blobBody, 0o600); err != nil {
		t.Fatal(err)
	}
	blobDigest := sha256.Sum256(blobBody)
	finished := []bool{}
	source := fakeSource{snapshot: &Snapshot{
		ID:            "00000003-0000001B-1",
		SchemaVersion: 5,
		State: State{
			InstallationID: "4e02b0e5-1934-4dda-9c4a-767c120c2fac",
			TimelineID:     "797476ad-8fdc-4c05-b144-3ccbb92b54bf",
			ChangeSequence: 42,
		},
		ReadyBlobs: []Blob{{StoragePath: "sha256/ready", Size: int64(len(blobBody)), SHA256: hex.EncodeToString(blobDigest[:])}},
		Dump: func(_ context.Context, destination string) error {
			return os.WriteFile(destination, []byte("database"), 0o600)
		},
		Finish: func(_ context.Context, verified bool) error {
			finished = append(finished, verified)
			return nil
		},
	}}

	manifest, directory, err := Create(context.Background(), options, source)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if filepath.Dir(directory) != root || filepath.Base(directory)[0] == '.' {
		t.Fatalf("backup was not published in root: %q", directory)
	}
	if len(finished) != 1 || !finished[0] {
		t.Fatalf("snapshot completion mismatch: %#v", finished)
	}
	verified, err := Verify(directory)
	if err != nil {
		t.Fatalf("verify published backup: %v", err)
	}
	if verified.BackupID != manifest.BackupID || verified.State != source.snapshot.State {
		t.Fatalf("published manifest mismatch: %#v", verified)
	}
	// #nosec G304 -- fixed child of the private test backup.
	if body, err := os.ReadFile(filepath.Join(directory, "blobs", "sha256", "ready")); err != nil || string(body) != string(blobBody) {
		t.Fatalf("published blob mismatch: %q, %v", body, err)
	}
}

func TestCreateDoesNotPublishFailedOrUnverifiedBackup(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *CreateOptions, *Snapshot)
	}{
		{name: "dump failure", mutate: func(_ *testing.T, _ *CreateOptions, snapshot *Snapshot) {
			snapshot.Dump = func(context.Context, string) error { return errors.New("dump failed") }
		}},
		{name: "blob digest mismatch", mutate: func(t *testing.T, options *CreateOptions, snapshot *Snapshot) {
			path := filepath.Join(options.BlobRoot, "ready")
			if err := os.WriteFile(path, []byte("blob"), 0o600); err != nil {
				t.Fatal(err)
			}
			snapshot.ReadyBlobs = []Blob{{StoragePath: "ready", Size: 4, SHA256: "0000000000000000000000000000000000000000000000000000000000000000"}}
		}},
		{name: "blob symlink", mutate: func(t *testing.T, options *CreateOptions, snapshot *Snapshot) {
			target := filepath.Join(options.BlobRoot, "target")
			if err := os.WriteFile(target, []byte("blob"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(options.BlobRoot, "ready")); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte("blob"))
			snapshot.ReadyBlobs = []Blob{{StoragePath: "ready", Size: 4, SHA256: hex.EncodeToString(sum[:])}}
		}},
		{name: "fence release failure", mutate: func(_ *testing.T, _ *CreateOptions, snapshot *Snapshot) {
			snapshot.Finish = func(context.Context, bool) error { return errors.New("release failed") }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, options := createTestInputs(t)
			finished := []bool{}
			snapshot := &Snapshot{
				ID:            "00000003-0000001B-1",
				SchemaVersion: 5,
				State:         State{InstallationID: "4e02b0e5-1934-4dda-9c4a-767c120c2fac", TimelineID: "797476ad-8fdc-4c05-b144-3ccbb92b54bf", ChangeSequence: 42},
				Dump: func(_ context.Context, destination string) error {
					return os.WriteFile(destination, []byte("database"), 0o600)
				},
				Finish: func(_ context.Context, verified bool) error {
					finished = append(finished, verified)
					return nil
				},
			}
			test.mutate(t, &options, snapshot)
			_, _, err := Create(context.Background(), options, fakeSource{snapshot: snapshot})
			if err == nil {
				t.Fatal("create unexpectedly succeeded")
			}
			entries, readErr := os.ReadDir(root)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("failed backup left filesystem entries: %#v", entries)
			}
			if test.name != "fence release failure" && (len(finished) != 1 || finished[0]) {
				t.Fatalf("failed snapshot was not aborted: %#v", finished)
			}
		})
	}
}

func TestCreateRetriesFailedVerifiedFinishAsAbort(t *testing.T) {
	root, options := createTestInputs(t)
	var finished []bool
	snapshot := &Snapshot{
		ID:            "00000003-0000001B-1",
		SchemaVersion: 5,
		State:         State{InstallationID: "4e02b0e5-1934-4dda-9c4a-767c120c2fac", TimelineID: "797476ad-8fdc-4c05-b144-3ccbb92b54bf", ChangeSequence: 42},
		Dump: func(_ context.Context, destination string) error {
			return os.WriteFile(destination, []byte("database"), 0o600)
		},
		Finish: func(_ context.Context, verified bool) error {
			finished = append(finished, verified)
			if verified {
				return errors.New("verified release failed")
			}
			return nil
		},
	}
	if _, _, err := Create(context.Background(), options, fakeSource{snapshot: snapshot}); err == nil {
		t.Fatal("create unexpectedly succeeded")
	}
	if len(finished) != 2 || !finished[0] || finished[1] {
		t.Fatalf("finish calls=%v, want [true false]", finished)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed backup left filesystem entries: %#v", entries)
	}
}

type fakeSource struct {
	snapshot *Snapshot
	err      error
}

func (source fakeSource) Begin(context.Context) (*Snapshot, error) {
	return source.snapshot, source.err
}

func createTestInputs(t *testing.T) (string, CreateOptions) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "backups")
	blobs := filepath.Join(t.TempDir(), "blobs")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(blobs, 0o700); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(t.TempDir(), "inputs")
	if err := os.Mkdir(inputs, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, name := range []string{"installation.json", "punarod.env", "compose.operator.yaml", "owner.dsn", "app.dsn"} {
		path := filepath.Join(inputs, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	return root, CreateOptions{
		BackupRoot:       root,
		BlobRoot:         blobs,
		InstallationFile: paths["installation.json"],
		EnvironmentFile:  paths["punarod.env"],
		ComposeFile:      paths["compose.operator.yaml"],
		OwnerDSNFile:     paths["owner.dsn"],
		AppDSNFile:       paths["app.dsn"],
		Now:              func() time.Time { return time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC) },
		NewID:            func() string { return "018f47f4-7b18-7cc2-98d6-31d4fb5ab742" },
	}
}
