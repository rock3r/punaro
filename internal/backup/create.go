package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/google/uuid"
)

const maximumBlobSize int64 = 16 << 30

// Blob is one immutable READY blob selected by the exported database snapshot.
type Blob struct {
	StoragePath string
	Size        int64
	SHA256      string
}

// Snapshot holds the exported transaction and its GC fence until Finish.
type Snapshot struct {
	ID            string
	SchemaVersion int64
	State         State
	ReadyBlobs    []Blob
	Dump          func(context.Context, string) error
	Finish        func(context.Context, bool) error
}

// Source starts one GC-fenced exported PostgreSQL snapshot.
type Source interface {
	Begin(context.Context) (*Snapshot, error)
}

// CreateOptions names all protected source paths and the private backup root.
type CreateOptions struct {
	BackupRoot       string
	BlobRoot         string
	InstallationFile string
	EnvironmentFile  string
	ComposeFile      string
	OwnerDSNFile     string
	AppDSNFile       string
	Now              func() time.Time
	NewID            func() string
	Update           *UpdateTarget
}

// UpdateTarget requests a v2 manifest for one update transaction. Source
// coordinates are derived from the exported snapshot and cannot be supplied by
// the caller.
type UpdateTarget struct {
	UpdateID          string
	TargetRelease     string
	TargetImageDigest string
}

// Create publishes a backup only after its exact snapshot dump, configuration,
// credentials, and READY blobs all pass size/hash verification.
func Create(ctx context.Context, options CreateOptions, source Source) (Manifest, string, error) {
	if source == nil || trustedPrivateDirectory(options.BackupRoot) != nil || !filepath.IsAbs(options.BlobRoot) || filepath.Clean(options.BlobRoot) != options.BlobRoot {
		return Manifest{}, "", errors.New("backup inputs are unavailable or unsafe")
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	if options.NewID == nil {
		options.NewID = uuid.NewString
	}
	backupID := options.NewID()
	createdAt := options.Now().UTC()
	if uuid.Validate(backupID) != nil || createdAt.IsZero() {
		return Manifest{}, "", errors.New("backup identity cannot be generated")
	}
	snapshot, err := source.Begin(ctx)
	if err != nil {
		return Manifest{}, "", errors.New("backup snapshot could not be started")
	}
	if snapshot == nil || snapshot.Dump == nil || snapshot.Finish == nil {
		return Manifest{}, "", errors.New("backup snapshot is invalid")
	}
	finished := false
	defer func() {
		if !finished {
			abortCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = snapshot.Finish(abortCtx, false)
		}
	}()
	if err := validateSnapshot(snapshot); err != nil {
		return Manifest{}, "", err
	}
	manifest := Manifest{Version: 1, BackupID: backupID, CreatedAt: createdAt, SnapshotID: snapshot.ID, SchemaVersion: snapshot.SchemaVersion, State: snapshot.State, ExternalDependencies: []string{"host-tls", "oauth", "reverse-proxy", "telegram", "tunnel"}}
	if options.Update != nil {
		manifest.Version = 2
		manifest.Update = &UpdateMetadata{
			UpdateID: options.Update.UpdateID, SourceSchema: snapshot.SchemaVersion,
			InstallationID: snapshot.State.InstallationID, TimelineID: snapshot.State.TimelineID,
			ChangeSequence: snapshot.State.ChangeSequence, TargetRelease: options.Update.TargetRelease,
			TargetImageDigest: options.Update.TargetImageDigest, ExportedSnapshotID: snapshot.ID,
		}
		if err := validateUpdateMetadata(*manifest.Update); err != nil {
			return Manifest{}, "", errors.New("backup update target is invalid")
		}
	}
	if len(snapshot.ReadyBlobs) != 0 && trustedPrivateDirectory(options.BlobRoot) != nil {
		return Manifest{}, "", errors.New("READY blob root is unavailable or unsafe")
	}
	stage := filepath.Join(options.BackupRoot, ".backup-"+backupID+".pending")
	if err := os.Mkdir(stage, 0o700); err != nil {
		return Manifest{}, "", errors.New("backup staging directory cannot be reserved")
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := snapshot.Dump(ctx, filepath.Join(stage, "database.dump")); err != nil {
		return Manifest{}, "", errors.New("database snapshot dump failed")
	}
	if err := addExistingFile(&manifest, stage, "database.dump", 1<<40); err != nil {
		return Manifest{}, "", errors.New("database snapshot dump is invalid")
	}
	inputs := []struct {
		source      string
		destination string
		maximum     int64
	}{
		{options.InstallationFile, "config/installation.json", maximumManifest},
		{options.EnvironmentFile, "config/punarod.env", maximumManifest},
		{options.ComposeFile, "config/compose.operator.yaml", maximumManifest},
		{options.OwnerDSNFile, "credentials/owner.dsn", 64 << 10},
		{options.AppDSNFile, "credentials/app.dsn", 64 << 10},
	}
	for _, input := range inputs {
		if err := copyProtectedFile(input.source, filepath.Join(stage, filepath.FromSlash(input.destination)), input.maximum); err != nil {
			return Manifest{}, "", errors.New("protected backup input could not be copied")
		}
		if err := addExistingFile(&manifest, stage, input.destination, input.maximum); err != nil {
			return Manifest{}, "", errors.New("protected backup input failed verification")
		}
	}
	for _, blob := range snapshot.ReadyBlobs {
		destination := "blobs/" + blob.StoragePath
		if !validRelativePath(blob.StoragePath) || blob.Size < 0 || blob.Size > maximumBlobSize || len(blob.SHA256) != 64 {
			return Manifest{}, "", errors.New("READY blob declaration is invalid")
		}
		if err := copyProtectedFile(filepath.Join(options.BlobRoot, filepath.FromSlash(blob.StoragePath)), filepath.Join(stage, filepath.FromSlash(destination)), blob.Size); err != nil {
			return Manifest{}, "", errors.New("READY blob could not be copied")
		}
		entry := File{Path: destination, Size: blob.Size, SHA256: blob.SHA256}
		if err := verifyFile(stage, entry); err != nil {
			return Manifest{}, "", errors.New("READY blob failed verification")
		}
		manifest.Files = append(manifest.Files, entry)
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	if err := writeManifestFile(filepath.Join(stage, manifestName), manifest); err != nil {
		return Manifest{}, "", errors.New("backup manifest could not be made durable")
	}
	if _, err := Verify(stage); err != nil {
		return Manifest{}, "", errors.New("staged backup did not verify")
	}
	if err := snapshot.Finish(ctx, true); err != nil {
		return Manifest{}, "", errors.New("backup GC fence could not be released safely")
	}
	finished = true
	directoryName := createdAt.Format("20060102T150405Z") + "-" + backupID
	destination := filepath.Join(options.BackupRoot, directoryName)
	if err := os.Rename(stage, destination); err != nil {
		return Manifest{}, "", errors.New("verified backup could not be published")
	}
	published = true
	if err := syncDirectory(options.BackupRoot); err != nil {
		return Manifest{}, destination, &OperationError{Phase: PhaseDataPublished, PublishedPath: destination, Err: errors.New("backup was published but directory durability could not be confirmed")}
	}
	return manifest, destination, nil
}

func validateSnapshot(snapshot *Snapshot) error {
	if !validSnapshotID(snapshot.ID) || snapshot.SchemaVersion <= 0 || uuid.Validate(snapshot.State.InstallationID) != nil || uuid.Validate(snapshot.State.TimelineID) != nil || snapshot.State.ChangeSequence < 0 || len(snapshot.ReadyBlobs) > maximumFileCount-len(requiredFiles) {
		return errors.New("backup snapshot metadata is invalid")
	}
	seen := make(map[string]bool, len(snapshot.ReadyBlobs))
	for _, blob := range snapshot.ReadyBlobs {
		if !validRelativePath(blob.StoragePath) || seen[blob.StoragePath] || blob.Size < 0 || blob.Size > maximumBlobSize || len(blob.SHA256) != 64 {
			return errors.New("READY blob manifest is invalid")
		}
		decoded, err := hex.DecodeString(blob.SHA256)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != blob.SHA256 {
			return errors.New("READY blob manifest is invalid")
		}
		seen[blob.StoragePath] = true
	}
	return nil
}

func copyProtectedFile(source, destination string, maximum int64) error {
	if source == "" || !filepath.IsAbs(source) || filepath.Clean(source) != source {
		return errors.New("source path is invalid")
	}
	before, err := os.Lstat(source)
	if err != nil || !before.Mode().IsRegular() || before.Size() > maximum || (runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0) || trustedProtectedFile(source, maximum) != nil {
		return errors.New("source is not a bounded regular file")
	}
	input, err := os.Open(source) // #nosec G304 -- explicit protected operator path or validated blob child.
	if err != nil {
		return err
	}
	after, err := input.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = input.Close()
		return errors.New("source changed during open")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		_ = input.Close()
		return err
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- validated private staging child.
	if err != nil {
		_ = input.Close()
		return err
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, maximum+1))
	inputCloseErr := input.Close()
	syncErr := output.Sync()
	outputCloseErr := output.Close()
	if copyErr != nil || inputCloseErr != nil || syncErr != nil || outputCloseErr != nil || written != before.Size() || written > maximum {
		return errors.New("file copy failed")
	}
	return nil
}

func addExistingFile(manifest *Manifest, root, relative string, maximum int64) error {
	path := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return errors.New("backup file is invalid")
	}
	file, err := os.Open(path) // #nosec G304 -- fixed child of private staging directory.
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written != info.Size() || written > maximum {
		return errors.New("backup file could not be hashed")
	}
	manifest.Files = append(manifest.Files, File{Path: relative, Size: written, SHA256: hex.EncodeToString(hash.Sum(nil))})
	return nil
}

func writeManifestFile(path string, manifest Manifest) error {
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed private staging child.
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- explicit private directory.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
