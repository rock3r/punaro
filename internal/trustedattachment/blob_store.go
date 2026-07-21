package trustedattachment

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const maxArtifactBytes int64 = 16 << 30

// UploadClaim is the database-fenced authority to write one immutable blob.
type UploadClaim struct {
	ArtifactID        string
	AttemptGeneration int64
	SizeBytes         int64
	SHA256            [sha256.Size]byte
}

// PublishedBlob is the content-free metadata used for conditional READY
// publication. StoragePath is always relative to the private blob root.
type PublishedBlob struct {
	StoragePath string
	SizeBytes   int64
	SHA256      [sha256.Size]byte
}

// BlobStore publishes immutable server-readable attachment bytes beneath one
// private root. The database remains authoritative for visibility.
type BlobStore struct {
	root       string
	stagingDir string
	readyDir   string
	lockDir    string
}

// OpenBlobStore verifies or creates the two private publication directories.
// The caller must provision the root itself with mode 0700.
func OpenBlobStore(root string) (*BlobStore, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("attachment blob root is unsafe")
	}
	if err := requirePrivateDirectory(root); err != nil {
		return nil, errors.New("attachment blob root is unsafe")
	}
	store := &BlobStore{root: root, stagingDir: filepath.Join(root, "staging"), readyDir: filepath.Join(root, "ready"), lockDir: filepath.Join(root, "locks")}
	for _, directory := range []string{store.stagingDir, store.readyDir, store.lockDir} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return nil, errors.New("attachment blob directory is unsafe")
		}
	}
	same, err := sameFilesystem(store.stagingDir, store.readyDir)
	if err != nil || !same {
		return nil, errors.New("attachment staging and ready directories must share a filesystem")
	}
	if err := syncDirectory(root); err != nil {
		return nil, errors.New("attachment blob root cannot be synchronized")
	}
	return store, nil
}

// LockArtifact serializes one artifact across daemon processes. The returned
// release must be called; lock files are opaque private coordination state and
// never part of a backup.
func (s *BlobStore) LockArtifact(ctx context.Context, artifactID string) (func() error, error) {
	if s == nil || uuid.Validate(artifactID) != nil {
		return nil, errors.New("invalid attachment lock")
	}
	return lockArtifactFile(ctx, filepath.Join(s.lockDir, artifactID+".lock"))
}

// Publish consumes at most the declared size plus one byte, verifies the exact
// digest, synchronizes the stage, and creates the final name without replacing
// an existing blob. A matching final is an idempotent retry; a changed final is
// never overwritten. Publication does not make the blob downloadable.
func (s *BlobStore) Publish(ctx context.Context, claim UploadClaim, source io.Reader) (PublishedBlob, error) {
	if s == nil || source == nil || claim.validate() != nil {
		return PublishedBlob{}, errors.New("invalid attachment upload claim")
	}
	expected := PublishedBlob{StoragePath: filepath.ToSlash(filepath.Join("ready", claim.ArtifactID+".blob")), SizeBytes: claim.SizeBytes, SHA256: claim.SHA256}
	finalPath := filepath.Join(s.root, filepath.FromSlash(expected.StoragePath))
	artifactStageDir := filepath.Join(s.stagingDir, claim.ArtifactID)
	if err := ensurePrivateDirectory(artifactStageDir); err != nil || syncDirectory(s.stagingDir) != nil {
		return PublishedBlob{}, errors.New("attachment staging namespace is unsafe")
	}
	stagePath := filepath.Join(artifactStageDir, fmt.Sprintf("%d.part", claim.AttemptGeneration))
	if _, err := os.Lstat(finalPath); err == nil {
		if err := s.Verify(expected); err != nil {
			return PublishedBlob{}, errors.New("immutable attachment blob conflicts with upload")
		}
		if err := syncDirectory(s.readyDir); err != nil {
			return PublishedBlob{}, errors.New("attachment retry publication cannot be synchronized")
		}
		if err := retireClaimStage(stagePath, artifactStageDir); err != nil {
			return PublishedBlob{}, errors.New("attachment retry stage cannot be retired")
		}
		return expected, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return PublishedBlob{}, errors.New("attachment final path is unavailable")
	}

	if err := removePrivateFile(stagePath, artifactStageDir); err != nil {
		return PublishedBlob{}, errors.New("attachment stale stage cannot be retired")
	}
	stage, err := os.OpenFile(stagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- server-derived UUID and generation beneath a verified private root.
	if err != nil {
		return PublishedBlob{}, errors.New("attachment upload stage is unavailable")
	}
	stagePresent := true
	defer func() {
		_ = stage.Close()
		if stagePresent {
			_ = retireClaimStage(stagePath, artifactStageDir)
		}
	}()

	hasher := sha256.New()
	written, err := copyBoundedContext(ctx, io.MultiWriter(stage, hasher), source, claim.SizeBytes+1)
	if err != nil {
		return PublishedBlob{}, errors.New("attachment upload stream failed")
	}
	if written != claim.SizeBytes {
		return PublishedBlob{}, errors.New("attachment upload size does not match reservation")
	}
	var actual [sha256.Size]byte
	copy(actual[:], hasher.Sum(nil))
	if actual != claim.SHA256 {
		return PublishedBlob{}, errors.New("attachment upload digest does not match reservation")
	}
	if err := stage.Sync(); err != nil {
		return PublishedBlob{}, errors.New("attachment upload stage cannot be synchronized")
	}
	if err := stage.Close(); err != nil {
		return PublishedBlob{}, errors.New("attachment upload stage cannot be closed")
	}

	if err := os.Link(stagePath, finalPath); err != nil {
		if _, statErr := os.Lstat(finalPath); statErr == nil {
			if verifyErr := s.Verify(expected); verifyErr == nil {
				if syncDirectory(s.readyDir) != nil {
					return PublishedBlob{}, errors.New("attachment retry publication cannot be synchronized")
				}
				if removeErr := retireClaimStage(stagePath, artifactStageDir); removeErr != nil {
					return PublishedBlob{}, errors.New("attachment retry stage cannot be retired")
				}
				stagePresent = false
				return expected, nil
			}
			return PublishedBlob{}, errors.New("immutable attachment blob conflicts with upload")
		}
		return PublishedBlob{}, errors.New("attachment blob cannot be published")
	}
	if err := syncDirectory(s.readyDir); err != nil {
		return PublishedBlob{}, errors.New("attachment publication cannot be synchronized")
	}
	if err := os.Remove(stagePath); err != nil {
		return PublishedBlob{}, errors.New("attachment stage cannot be retired")
	}
	stagePresent = false
	if err := syncDirectory(artifactStageDir); err != nil {
		return PublishedBlob{}, errors.New("attachment staging directory cannot be synchronized")
	}
	return expected, nil
}

// Verify proves that one published path still names the exact private regular
// file recorded in READY metadata.
func (s *BlobStore) Verify(blob PublishedBlob) error {
	if s == nil || blob.validate() != nil {
		return errors.New("invalid attachment blob metadata")
	}
	base := filepath.Base(blob.StoragePath)
	expected := filepath.ToSlash(filepath.Join("ready", base))
	artifactID, found := strings.CutSuffix(base, ".blob")
	if blob.StoragePath != expected || !found || uuid.Validate(artifactID) != nil {
		return errors.New("attachment blob path is unsafe")
	}
	path := filepath.Join(s.root, filepath.FromSlash(blob.StoragePath))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != blob.SizeBytes {
		return errors.New("attachment blob is missing or corrupt")
	}
	file, err := os.Open(path) // #nosec G304 -- validated relative path beneath a verified private root.
	if err != nil {
		return errors.New("attachment blob is missing or corrupt")
	}
	defer func() { _ = file.Close() }()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, blob.SizeBytes+1))
	if err != nil || written != blob.SizeBytes || digest(hasher) != blob.SHA256 {
		return errors.New("attachment blob is missing or corrupt")
	}
	return nil
}

// RemoveUnpublished durably removes bytes which never obtained a READY
// database projection. Callers must first prove the reservation is expired or
// belongs to an obsolete restored timeline; this method grants no authority.
func (s *BlobStore) RemoveUnpublished(artifactID string) error {
	if s == nil || uuid.Validate(artifactID) != nil {
		return errors.New("invalid unpublished attachment")
	}
	if err := s.RemoveStages(artifactID); err != nil {
		return errors.New("unpublished attachment stage cannot be retired")
	}
	if err := removePrivateFile(filepath.Join(s.readyDir, artifactID+".blob"), s.readyDir); err != nil {
		return errors.New("unpublished attachment final cannot be retired")
	}
	return nil
}

// RemoveStages durably removes every claim-specific stage for one artifact.
// It is safe only after the database has fenced publication or committed READY.
func (s *BlobStore) RemoveStages(artifactID string) error {
	if s == nil || uuid.Validate(artifactID) != nil {
		return errors.New("invalid attachment staging cleanup")
	}
	return removeArtifactStageDirectory(filepath.Join(s.stagingDir, artifactID), s.stagingDir)
}

func (claim UploadClaim) validate() error {
	if uuid.Validate(claim.ArtifactID) != nil || claim.AttemptGeneration < 1 || claim.SizeBytes < 1 || claim.SizeBytes > maxArtifactBytes {
		return errors.New("invalid attachment upload claim")
	}
	return nil
}

func (blob PublishedBlob) validate() error {
	if blob.StoragePath == "" || blob.SizeBytes < 1 || blob.SizeBytes > maxArtifactBytes {
		return errors.New("invalid attachment blob metadata")
	}
	return nil
}

func copyBoundedContext(ctx context.Context, destination io.Writer, source io.Reader, limit int64) (int64, error) {
	limited := io.LimitReader(source, limit)
	buffer := make([]byte, 64<<10)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		read, readErr := limited.Read(buffer)
		if read > 0 {
			count, writeErr := destination.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != read {
				return written, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}

func digest(hasher hash.Hash) [sha256.Size]byte {
	var value [sha256.Size]byte
	copy(value[:], hasher.Sum(nil))
	return value
}

func ensurePrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return requirePrivateDirectory(path)
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("directory is not private")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- verified private directory.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func removePrivateFile(path, parent string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("attachment path is unsafe")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func retireClaimStage(path, artifactStageDir string) error {
	return removePrivateFile(path, artifactStageDir)
}

func removeArtifactStageDirectory(path, parent string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("attachment staging directory is unsafe")
	}
	directory, err := os.Open(path) // #nosec G304 -- UUID child beneath verified private staging root.
	if err != nil {
		return err
	}
	names, readErr := directory.Readdirnames(1025)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if closeErr != nil || len(names) > 1024 {
		return errors.New("attachment staging cleanup is not bounded")
	}
	for _, name := range names {
		if filepath.Base(name) != name || !strings.HasSuffix(name, ".part") {
			return errors.New("attachment staging entry is unsafe")
		}
		generation := strings.TrimSuffix(name, ".part")
		parsedGeneration, parseErr := strconv.ParseInt(generation, 10, 64)
		if parseErr != nil || parsedGeneration < 1 || strconv.FormatInt(parsedGeneration, 10) != generation {
			return errors.New("attachment staging entry is unsafe")
		}
		if err := removePrivateFile(filepath.Join(path, name), path); err != nil {
			return err
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(parent)
}
