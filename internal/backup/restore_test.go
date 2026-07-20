package backup

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRestorePublishesVerifiedBlobsAfterDatabaseAndTimeline(t *testing.T) {
	backupDirectory, manifest := createRestoreFixture(t, true)
	targetParent := t.TempDir()
	requirePrivate(t, targetParent)
	target := filepath.Join(targetParent, "restored-data")
	called := []string{}
	state, err := Restore(context.Background(), RestoreOptions{
		BackupDirectory: backupDirectory,
		TargetDataDir:   target,
		Target:          restoreTargetFixture(targetParent),
		Preflight:       func(context.Context) error { return nil },
		RestoreDump: func(_ context.Context, dump io.Reader) error {
			called = append(called, "database")
			body, readErr := io.ReadAll(dump)
			if readErr != nil || string(body) != "database" {
				t.Fatalf("unexpected dump: %q err=%v", body, readErr)
			}
			return nil
		},
		RotateTimeline: func(_ context.Context, got Manifest) (State, error) {
			called = append(called, "timeline")
			if got.BackupID != manifest.BackupID {
				t.Fatalf("unexpected manifest: %#v", got)
			}
			return State{InstallationID: got.State.InstallationID, TimelineID: "7c016e76-aadb-48f8-b460-e75f7d90e888", ChangeSequence: got.State.ChangeSequence}, nil
		},
		Finalize: func(_ context.Context, _ State) error { called = append(called, "finalize"); return nil },
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(called) != 3 || called[0] != "database" || called[1] != "timeline" || called[2] != "finalize" {
		t.Fatalf("unexpected restore order: %#v", called)
	}
	if state.InstallationID != manifest.State.InstallationID || state.TimelineID == manifest.State.TimelineID || state.ChangeSequence != manifest.State.ChangeSequence {
		t.Fatalf("unexpected restored state: %#v", state)
	}
	// #nosec G304 -- fixed child of the private test restore target.
	if body, err := os.ReadFile(filepath.Join(target, "blobs", "ready")); err != nil || string(body) != "blob" {
		t.Fatalf("restored blob=%q err=%v", body, err)
	}
}

func TestRestoreResumesAfterPublishedFinalizationFailureWithoutRepeatingMutation(t *testing.T) {
	backupDirectory, _ := createRestoreFixture(t, true)
	targetParent := t.TempDir()
	requirePrivate(t, targetParent)
	options := RestoreOptions{BackupDirectory: backupDirectory, TargetDataDir: filepath.Join(targetParent, "restored-data"), Target: restoreTargetFixture(targetParent), Preflight: func(context.Context) error { return nil }}
	dumps, rotations, finalizations := 0, 0, 0
	options.RestoreDump = func(context.Context, io.Reader) error { dumps++; return nil }
	options.RotateTimeline = func(_ context.Context, manifest Manifest) (State, error) {
		rotations++
		return State{InstallationID: manifest.State.InstallationID, TimelineID: "7c016e76-aadb-48f8-b460-e75f7d90e888", ChangeSequence: manifest.State.ChangeSequence}, nil
	}
	options.Finalize = func(context.Context, State) error {
		finalizations++
		if finalizations == 1 {
			return errors.New("simulated publication interruption")
		}
		return nil
	}
	if _, err := Restore(context.Background(), options); err == nil {
		t.Fatal("interrupted finalization unexpectedly succeeded")
	} else {
		var operationErr *OperationError
		if !errors.As(err, &operationErr) || operationErr.Phase != PhaseDataPublished {
			t.Fatalf("error=%v, want published phase", err)
		}
	}
	changed := options
	changed.Target.InstallationDirectory = filepath.Join(targetParent, "different-installation")
	if _, err := Restore(context.Background(), changed); err == nil {
		t.Fatal("resume accepted a changed target binding")
	}
	blobPath := filepath.Join(options.TargetDataDir, "blobs", "ready")
	if err := os.WriteFile(blobPath, []byte("bad!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), options); err == nil {
		t.Fatal("resume accepted a modified published blob")
	}
	if err := os.WriteFile(blobPath, []byte("blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(context.Background(), options); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if dumps != 1 || rotations != 1 || finalizations != 2 {
		t.Fatalf("resume repeated mutation: dumps=%d rotations=%d finalizations=%d", dumps, rotations, finalizations)
	}
}

func TestRestoreDoesNotTurnFailedPristineProofIntoResumeAuthority(t *testing.T) {
	backupDirectory, _ := createRestoreFixture(t, false)
	targetParent := t.TempDir()
	requirePrivate(t, targetParent)
	preflights, dumps := 0, 0
	options := RestoreOptions{
		BackupDirectory: backupDirectory,
		TargetDataDir:   filepath.Join(targetParent, "restored-data"),
		Target:          restoreTargetFixture(targetParent),
		Preflight: func(context.Context) error {
			preflights++
			return errors.New("not pristine")
		},
		RestoreDump:    func(context.Context, io.Reader) error { dumps++; return nil },
		RotateTimeline: func(context.Context, Manifest) (State, error) { return State{}, nil },
		Finalize:       func(context.Context, State) error { return nil },
	}
	for range 2 {
		if _, err := Restore(context.Background(), options); err == nil {
			t.Fatal("non-pristine target unexpectedly advanced")
		}
	}
	if preflights != 2 || dumps != 0 {
		t.Fatalf("failed proof became resume authority: preflights=%d dumps=%d", preflights, dumps)
	}
}

func TestRestoreSerializesOneJournal(t *testing.T) {
	backupDirectory, _ := createRestoreFixture(t, false)
	targetParent := t.TempDir()
	requirePrivate(t, targetParent)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	options := RestoreOptions{
		BackupDirectory: backupDirectory,
		TargetDataDir:   filepath.Join(targetParent, "restored-data"),
		Target:          restoreTargetFixture(targetParent),
		Preflight:       func(context.Context) error { return nil },
		RestoreDump: func(context.Context, io.Reader) error {
			once.Do(func() { close(entered) })
			<-release
			return nil
		},
		RotateTimeline: func(_ context.Context, manifest Manifest) (State, error) {
			return State{InstallationID: manifest.State.InstallationID, TimelineID: "7c016e76-aadb-48f8-b460-e75f7d90e888", ChangeSequence: manifest.State.ChangeSequence}, nil
		},
		Finalize: func(context.Context, State) error { return nil },
	}
	done := make(chan error, 1)
	go func() { _, err := Restore(context.Background(), options); done <- err }()
	<-entered
	if _, err := Restore(context.Background(), options); err == nil {
		t.Fatal("concurrent restore unexpectedly entered the active journal")
	}
	conflicting := options
	conflicting.TargetDataDir = filepath.Join(targetParent, "other-restored-data")
	conflicting.Target.DatabaseIdentity = strings.Repeat("b", 64)
	if _, err := Restore(context.Background(), conflicting); err == nil {
		t.Fatal("distinct journal concurrently reused the installation target")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("serialized restore: %v", err)
	}
}

func TestRestoreRefusesMutationAndUncertainOutcomes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string, *RestoreOptions)
	}{
		{name: "existing target", mutate: func(t *testing.T, _ string, options *RestoreOptions) {
			if err := os.Mkdir(options.TargetDataDir, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "database failure", mutate: func(_ *testing.T, _ string, options *RestoreOptions) {
			options.RestoreDump = func(context.Context, io.Reader) error { return errors.New("restore failed") }
		}},
		{name: "timeline failure", mutate: func(_ *testing.T, _ string, options *RestoreOptions) {
			options.RotateTimeline = func(context.Context, Manifest) (State, error) { return State{}, errors.New("rotate failed") }
		}},
		{name: "timeline not rotated", mutate: func(_ *testing.T, _ string, options *RestoreOptions) {
			options.RotateTimeline = func(_ context.Context, manifest Manifest) (State, error) { return manifest.State, nil }
		}},
		{name: "source equals target", mutate: func(_ *testing.T, backupDirectory string, options *RestoreOptions) {
			options.TargetDataDir = backupDirectory
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backupDirectory, manifest := createRestoreFixture(t, true)
			targetParent := t.TempDir()
			requirePrivate(t, targetParent)
			target := filepath.Join(targetParent, "restored-data")
			options := RestoreOptions{
				BackupDirectory: backupDirectory,
				TargetDataDir:   target,
				Target:          restoreTargetFixture(targetParent),
				Preflight:       func(context.Context) error { return nil },
				RestoreDump:     func(context.Context, io.Reader) error { return nil },
				RotateTimeline: func(_ context.Context, got Manifest) (State, error) {
					return State{InstallationID: got.State.InstallationID, TimelineID: "7c016e76-aadb-48f8-b460-e75f7d90e888", ChangeSequence: got.State.ChangeSequence}, nil
				},
				Finalize: func(context.Context, State) error { return errors.New("finalization stopped") },
			}
			test.mutate(t, backupDirectory, &options)
			if _, err := Restore(context.Background(), options); err == nil {
				t.Fatal("restore unexpectedly succeeded")
			}
			if options.TargetDataDir == target && test.name != "existing target" {
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed restore published target: %v", err)
				}
			}
			_ = manifest
		})
	}
}

func restoreTargetFixture(parent string) RestoreTarget {
	return RestoreTarget{
		InstallationDirectory: filepath.Join(parent, "installation"),
		BackupRoot:            filepath.Join(parent, "backups"),
		OwnerDSNFile:          filepath.Join(parent, "owner.dsn"),
		AppDSNFile:            filepath.Join(parent, "app.dsn"),
		DatabaseIdentity:      strings.Repeat("a", 64),
	}
}

func createRestoreFixture(t *testing.T, withBlob bool) (string, Manifest) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "backup")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := writeRequiredTestFiles(t, directory)
	if withBlob {
		writeBackupFile(t, directory, "blobs/ready", []byte("blob"))
		paths = append(paths, "blobs/ready")
	}
	manifest := testManifest(t, directory, paths)
	writeManifest(t, directory, manifest)
	if _, err := Verify(directory); err != nil {
		t.Fatalf("fixture verify: %v", err)
	}
	return directory, manifest
}
