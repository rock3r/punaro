package backup

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// OperationPhase identifies the last durable boundary reached by an operation.
type OperationPhase string

const (
	// PhasePreflight means no database mutation was intentionally completed.
	PhasePreflight OperationPhase = "preflight"
	// PhaseDatabaseMutated means the exact command must resume its journal.
	PhaseDatabaseMutated OperationPhase = "database-mutated"
	// PhaseDataPublished means data is visible and finalization must resume.
	PhaseDataPublished OperationPhase = "data-published"
)

// OperationError tells operators whether a retry is safe and required.
type OperationError struct {
	Phase         OperationPhase
	PublishedPath string
	Err           error
}

func (e *OperationError) Error() string { return string(e.Phase) + ": " + e.Err.Error() }
func (e *OperationError) Unwrap() error { return e.Err }

// RestoreOptions names a verified backup and a brand-new daemon data path.
type RestoreOptions struct {
	BackupDirectory string
	TargetDataDir   string
	Target          RestoreTarget
	Preflight       func(context.Context) error
	RestoreDump     func(context.Context, io.Reader) error
	RotateTimeline  func(context.Context, Manifest) (State, error)
	Finalize        func(context.Context, State) error
}

// RestoreTarget binds every non-secret target identity to the durable journal.
type RestoreTarget struct {
	InstallationDirectory string `json:"installation_directory"`
	BackupRoot            string `json:"backup_root"`
	OwnerDSNFile          string `json:"owner_dsn_file"`
	AppDSNFile            string `json:"app_dsn_file"`
	DatabaseIdentity      string `json:"database_identity"`
	UpdateID              string `json:"update_id,omitempty"`
	ManifestSHA256        string `json:"manifest_sha256,omitempty"`
	RecoveryReceiptFile   string `json:"recovery_receipt_file,omitempty"`
	RecoveryReceiptSHA256 string `json:"recovery_receipt_sha256,omitempty"`
}

type restoreRequest struct {
	BackupID       string        `json:"backup_id"`
	BackupSource   string        `json:"backup_source"`
	TargetDataPath string        `json:"target_data_path"`
	Target         RestoreTarget `json:"target"`
}

const (
	restoreRequestName = "request.json"
	pristineMarker     = "00-target-pristine"
	stagedMarker       = "01-staged"
	databaseMarker     = "02-database-restored"
	timelineMarker     = "03-timeline-rotated.json"
	publishedMarker    = "04-data-published"
	completeMarker     = "05-complete"
)

// Restore resumes a journaled clean-stack restore through database mutation,
// timeline rotation, atomic data publication, and caller-owned finalization.
func Restore(ctx context.Context, options RestoreOptions) (State, error) {
	fail := func(phase OperationPhase, message string) (State, error) {
		return State{}, &OperationError{Phase: phase, Err: errors.New(message)}
	}
	if options.Preflight == nil || options.RestoreDump == nil || options.RotateTimeline == nil || options.Finalize == nil || !filepath.IsAbs(options.TargetDataDir) || filepath.Clean(options.TargetDataDir) != options.TargetDataDir || !validRestoreTarget(options.Target) {
		return fail(PhasePreflight, "restore inputs are invalid")
	}
	manifest, err := Verify(options.BackupDirectory)
	if err != nil {
		return fail(PhasePreflight, "restore requires a verified backup")
	}
	parent := filepath.Dir(options.TargetDataDir)
	if trustedPrivateDirectory(parent) != nil {
		return fail(PhasePreflight, "restore target parent is unavailable or unsafe")
	}
	canonicalBackup, backupErr := filepath.EvalSymlinks(options.BackupDirectory)
	canonicalParent, parentErr := filepath.EvalSymlinks(parent)
	plannedTarget := filepath.Join(canonicalParent, filepath.Base(options.TargetDataDir))
	if backupErr != nil || parentErr != nil || pathsOverlap(canonicalBackup, plannedTarget) {
		return fail(PhasePreflight, "restore source and target overlap")
	}
	journal := filepath.Join(parent, "."+filepath.Base(options.TargetDataDir)+".punaro-restore-"+manifest.BackupID)
	request := restoreRequest{BackupID: manifest.BackupID, BackupSource: canonicalBackup, TargetDataPath: plannedTarget, Target: options.Target}
	requestBody, err := json.Marshal(request)
	if err != nil {
		return fail(PhasePreflight, "restore request cannot be encoded")
	}
	requestBody = append(requestBody, '\n')
	installationReservation := filepath.Join(filepath.Dir(options.Target.InstallationDirectory), "."+filepath.Base(options.Target.InstallationDirectory)+".punaro-restore-reservation")
	if err := reserveRestoreJournal(installationReservation, requestBody); err != nil {
		return fail(PhasePreflight, "restore installation target is reserved by a different request")
	}
	releaseInstallationLock, err := lockRestoreJournal(filepath.Join(installationReservation, "restore.lock"))
	if err != nil {
		return fail(PhasePreflight, "this restore installation target is already active")
	}
	defer releaseInstallationLock()
	if err := reserveRestoreJournal(journal, requestBody); err != nil {
		return fail(PhasePreflight, "restore journal conflicts with this request")
	}
	releaseLock, err := lockRestoreJournal(filepath.Join(journal, "restore.lock"))
	if err != nil {
		return fail(PhasePreflight, "this restore journal is already active")
	}
	defer releaseLock()
	pristineBody := []byte(options.Target.DatabaseIdentity + "\n")
	if !markerMatches(journal, pristineMarker, pristineBody) {
		if err := options.Preflight(ctx); err != nil {
			var operationErr *OperationError
			if errors.As(err, &operationErr) {
				return State{}, operationErr
			}
			return fail(PhasePreflight, "restore target database is not a proved pristine target")
		}
		if err := writeMarker(journal, pristineMarker, pristineBody); err != nil {
			return fail(PhasePreflight, "pristine target proof could not be made durable")
		}
	}
	if _, err := os.Lstat(options.TargetDataDir); err == nil && !markerMatches(journal, databaseMarker, []byte("database-restored\n")) && !markerMatches(journal, publishedMarker, []byte("data-published\n")) {
		return fail(PhasePreflight, "restore target must not exist for a new restore")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(PhasePreflight, "restore target is unsafe")
	}

	stage := filepath.Join(journal, "data.pending")
	if !markerMatches(journal, stagedMarker, []byte("staged\n")) {
		if err := os.RemoveAll(stage); err != nil || os.Mkdir(stage, 0o700) != nil {
			return fail(PhasePreflight, "restore blob staging cannot be reserved")
		}
		for _, entry := range manifest.Files {
			if !strings.HasPrefix(entry.Path, "blobs/") {
				continue
			}
			relative := strings.TrimPrefix(entry.Path, "blobs/")
			if !validRelativePath(relative) {
				return fail(PhasePreflight, "backup blob path is invalid")
			}
			source := filepath.Join(options.BackupDirectory, filepath.FromSlash(entry.Path))
			destination := filepath.Join(stage, "blobs", filepath.FromSlash(relative))
			if err := copyProtectedFile(source, destination, entry.Size); err != nil || verifyFile(stage, entry) != nil {
				return fail(PhasePreflight, "verified backup blob could not be staged")
			}
		}
		if err := syncTree(stage); err != nil || writeMarker(journal, stagedMarker, []byte("staged\n")) != nil {
			return fail(PhasePreflight, "restore blob staging could not be made durable")
		}
	}
	blobVerificationRoot := stage
	if info, statErr := os.Lstat(options.TargetDataDir); statErr == nil && info.IsDir() {
		blobVerificationRoot = options.TargetDataDir
	}
	if err := verifyManifestBlobs(blobVerificationRoot, manifest); err != nil {
		if blobVerificationRoot == options.TargetDataDir {
			return fail(PhaseDataPublished, "published restore blobs do not match the verified backup")
		}
		return fail(PhasePreflight, "staged restore blobs do not match the verified backup")
	}

	if !markerMatches(journal, databaseMarker, []byte("database-restored\n")) {
		dumpEntry, ok := manifestFile(manifest, "database.dump")
		if !ok {
			return fail(PhasePreflight, "verified database dump is unavailable")
		}
		dump, openErr := openVerifiedFile(options.BackupDirectory, dumpEntry)
		if openErr != nil {
			return fail(PhasePreflight, "verified database dump changed before restore")
		}
		restoreErr := options.RestoreDump(ctx, dump)
		closeErr := dump.Close()
		if restoreErr != nil || closeErr != nil {
			var operationErr *OperationError
			if errors.As(restoreErr, &operationErr) && operationErr.Phase == PhasePreflight {
				return State{}, operationErr
			}
			return fail(PhaseDatabaseMutated, "database restore failed; retry the exact restore command")
		}
		if err := writeMarker(journal, databaseMarker, []byte("database-restored\n")); err != nil {
			return fail(PhaseDatabaseMutated, "database was restored but its journal marker is not durable; retry the exact restore command")
		}
	}

	timelinePath := filepath.Join(journal, timelineMarker)
	state, stateErr := readRestoreState(timelinePath)
	if stateErr != nil {
		if !errors.Is(stateErr, os.ErrNotExist) {
			if removeErr := os.Remove(timelinePath); removeErr != nil {
				return fail(PhaseDatabaseMutated, "timeline journal marker is corrupt and cannot be recovered")
			}
		}
		state, stateErr = options.RotateTimeline(ctx, manifest)
		if stateErr == nil && validRotatedState(state, manifest) {
			stateErr = writeStateMarker(journal, timelineMarker, state)
		}
	}
	if stateErr != nil || !validRotatedState(state, manifest) {
		return fail(PhaseDatabaseMutated, "database was restored but timeline rotation is incomplete; retry the exact restore command")
	}

	if !markerMatches(journal, publishedMarker, []byte("data-published\n")) {
		if _, err := os.Lstat(options.TargetDataDir); errors.Is(err, os.ErrNotExist) {
			stateBody, marshalErr := json.MarshalIndent(state, "", "  ")
			if marshalErr != nil {
				return fail(PhaseDatabaseMutated, "restored state could not be encoded")
			}
			stateBody = append(stateBody, '\n')
			if err := writeExclusiveSynced(filepath.Join(stage, "restore-state.json"), stateBody); err != nil || syncDirectory(stage) != nil {
				return fail(PhaseDatabaseMutated, "restore state could not be staged; retry the exact restore command")
			}
			if err := os.Rename(stage, options.TargetDataDir); err != nil {
				return fail(PhaseDatabaseMutated, "restore data publication failed; retry the exact restore command")
			}
		} else if err != nil || !publishedStateMatches(options.TargetDataDir, state) {
			return fail(PhaseDatabaseMutated, "restore target exists but is not this journal's published data")
		}
		if err := syncDirectory(parent); err != nil || writeMarker(journal, publishedMarker, []byte("data-published\n")) != nil {
			return fail(PhaseDataPublished, "restore data was published but its journal marker is not durable; retry the exact restore command")
		}
	}
	if err := verifyManifestBlobs(options.TargetDataDir, manifest); err != nil {
		return fail(PhaseDataPublished, "published restore blobs do not match the verified backup")
	}

	if err := options.Finalize(ctx, state); err != nil {
		return fail(PhaseDataPublished, "restore finalization failed; retry the exact restore command")
	}
	if !markerMatches(journal, completeMarker, []byte("complete\n")) {
		if err := writeMarker(journal, completeMarker, []byte("complete\n")); err != nil {
			return fail(PhaseDataPublished, "restore completed but its final journal marker is not durable; retry the exact restore command")
		}
	}
	return state, nil
}

func reserveRestoreJournal(journal string, requestBody []byte) error {
	if err := os.Mkdir(journal, 0o700); err == nil {
		if err := writeExclusiveSynced(filepath.Join(journal, restoreRequestName), requestBody); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrExist) || trustedPrivateDirectory(journal) != nil {
		return err
	} else {
		requestPath := filepath.Join(journal, restoreRequestName)
		if trustedProtectedFile(requestPath, maximumManifest) != nil {
			return errors.New("restore journal request is unsafe")
		}
		existing, readErr := os.ReadFile(requestPath) // #nosec G304 -- fixed child of the private restore journal.
		if readErr != nil || !bytes.Equal(existing, requestBody) {
			return errors.New("restore journal request mismatch")
		}
	}
	if err := syncDirectory(journal); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(journal))
}

func validRestoreTarget(target RestoreTarget) bool {
	for _, path := range []string{target.InstallationDirectory, target.BackupRoot, target.OwnerDSNFile, target.AppDSNFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return false
		}
	}
	decoded, err := hex.DecodeString(target.DatabaseIdentity)
	if target.OwnerDSNFile == target.AppDSNFile || err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != target.DatabaseIdentity {
		return false
	}
	if target.UpdateID == "" && target.ManifestSHA256 == "" && target.RecoveryReceiptFile == "" && target.RecoveryReceiptSHA256 == "" {
		return true
	}
	manifestDigest, digestErr := hex.DecodeString(target.ManifestSHA256)
	receiptDigest, receiptDigestErr := hex.DecodeString(target.RecoveryReceiptSHA256)
	return uuid.Validate(target.UpdateID) == nil && digestErr == nil && len(manifestDigest) == 32 && hex.EncodeToString(manifestDigest) == target.ManifestSHA256 &&
		filepath.IsAbs(target.RecoveryReceiptFile) && filepath.Clean(target.RecoveryReceiptFile) == target.RecoveryReceiptFile &&
		receiptDigestErr == nil && len(receiptDigest) == 32 && hex.EncodeToString(receiptDigest) == target.RecoveryReceiptSHA256
}

func verifyManifestBlobs(root string, manifest Manifest) error {
	for _, entry := range manifest.Files {
		if strings.HasPrefix(entry.Path, "blobs/") {
			if err := verifyFile(root, entry); err != nil {
				return err
			}
		}
	}
	return nil
}

func manifestFile(manifest Manifest, path string) (File, bool) {
	for _, entry := range manifest.Files {
		if entry.Path == path {
			return entry, true
		}
	}
	return File{}, false
}

func markerMatches(journal, name string, expected []byte) bool {
	path := filepath.Join(journal, name)
	if trustedProtectedFile(path, int64(len(expected))) != nil {
		return false
	}
	body, err := os.ReadFile(path) // #nosec G304 -- fixed private restore-journal child.
	return err == nil && bytes.Equal(body, expected)
}

func writeMarker(journal, name string, body []byte) error {
	path := filepath.Join(journal, name)
	if err := writeExclusiveSynced(path, body); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if markerMatches(journal, name, body) {
			return syncDirectory(journal)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := writeExclusiveSynced(path, body); err != nil {
			return err
		}
	}
	return syncDirectory(journal)
}

func writeStateMarker(journal, name string, state State) error {
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeMarker(journal, name, append(body, '\n'))
}

func readRestoreState(path string) (State, error) {
	if _, err := os.Lstat(path); err != nil {
		return State{}, err
	}
	if trustedProtectedFile(path, 64<<10) != nil {
		return State{}, errors.New("restore state file is unsafe")
	}
	body, err := os.ReadFile(path) // #nosec G304 -- fixed private journal or published data child.
	if err != nil {
		return State{}, err
	}
	var state State
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return State{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return State{}, errors.New("restore state has trailing data")
	}
	return state, nil
}

func validRotatedState(state State, manifest Manifest) bool {
	return state.InstallationID == manifest.State.InstallationID && state.TimelineID != "" && state.TimelineID != manifest.State.TimelineID && state.ChangeSequence == manifest.State.ChangeSequence
}

func publishedStateMatches(target string, expected State) bool {
	if trustedPrivateDirectory(target) != nil {
		return false
	}
	actual, err := readRestoreState(filepath.Join(target, "restore-state.json"))
	return err == nil && actual == expected
}

func pathsOverlap(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if first == second {
		return true
	}
	relative, err := filepath.Rel(first, second)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	relative, err = filepath.Rel(second, first)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return syncDirectory(path)
		}
		return nil
	})
}

func writeExclusiveSynced(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed private restore staging child.
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
	return file.Close()
}
