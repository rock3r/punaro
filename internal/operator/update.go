package operator

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const (
	updateStageDirectoryName = ".update"
	updateCandidateName      = "candidate"
	updateJournalName        = "journal.json"
	updateRecoveryName       = "recovery.json"
	updateJournalVersion     = 1

	publishStepEnvironment  = "environment"
	publishStepCompose      = "compose"
	publishStepInstallation = "installation"
)

var (
	updateReleasePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	updateDigestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	updateSnapshotPattern = regexp.MustCompile(`^[0-9A-Z-]{1,200}$`)
	updateHashPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// ErrUpdateStageConflict reports that the durable host stage belongs to a
	// different update request or no longer matches the published installation.
	ErrUpdateStageConflict = errors.New("update stage belongs to a different request")
	// ErrUpdateAlreadyPublished reports an abort requested after the final
	// installation marker became visible.
	ErrUpdateAlreadyPublished = errors.New("update configuration is already published")
	// ErrUpdateStageNotFound reports that no durable host-side update request
	// exists. Resume inspection never creates one.
	ErrUpdateStageNotFound = errors.New("update stage is not found")

	// updatePublicationHook is test-only fault injection. Production leaves it
	// nil; keeping it at the file boundary makes every durable rename testable.
	updatePublicationHook func(string) error
)

// UpdateStage is the exact immutable request reserved by the host journal.
// Previous fields are retained after publication as the compatible-image lock.
type UpdateStage struct {
	Directory       string
	UpdateID        string
	PreviousRelease string
	PreviousImage   string
	TargetRelease   string
	TargetImage     string
}

// StagedUpdate is the content-free durable stage status returned on first use
// and exact resume.
type StagedUpdate struct {
	Directory          string
	CandidateDirectory string
	UpdateID           string
	PreviousRelease    string
	PreviousImage      string
	TargetRelease      string
	TargetImage        string
	Published          bool
}

// UpdateRecoveryReceipt is the independently durable host authorization for
// restoring an update backup. It is written only after the backup has been
// completely verified and must match both the host journal and backup.
type UpdateRecoveryReceipt struct {
	Version            int    `json:"version"`
	UpdateID           string `json:"update_id"`
	BackupID           string `json:"backup_id"`
	BackupDirectory    string `json:"backup_directory"`
	InstallationID     string `json:"installation_id"`
	TimelineID         string `json:"timeline_id"`
	ChangeSequence     int64  `json:"change_sequence"`
	SourceSchema       int64  `json:"source_schema"`
	TargetRelease      string `json:"target_release"`
	TargetImageDigest  string `json:"target_image_digest"`
	ExportedSnapshotID string `json:"exported_snapshot_id"`
	ManifestSHA256     string `json:"manifest_sha256"`
}

type updateJournal struct {
	Version              int          `json:"version"`
	UpdateID             string       `json:"update_id"`
	PreviousRelease      string       `json:"previous_release"`
	PreviousImage        string       `json:"previous_image"`
	TargetRelease        string       `json:"target_release"`
	TargetImage          string       `json:"target_image"`
	PreviousInstallation Installation `json:"previous_installation"`
	Published            bool         `json:"published"`
}

// StageUpdate reserves one installation-local update request and durably
// renders its candidate configuration without changing any published file.
func StageUpdate(request UpdateStage) (StagedUpdate, error) {
	if err := request.validate(); err != nil {
		return StagedUpdate{}, err
	}
	if err := requireTrustedPrivateDirectory(request.Directory); err != nil {
		return StagedUpdate{}, errors.New("installation directory is unavailable or unsafe")
	}
	root := updateStageRoot(request.Directory)
	if _, err := os.Lstat(root); err == nil {
		return resumeUpdateStage(request)
	} else if !errors.Is(err, os.ErrNotExist) {
		return StagedUpdate{}, errors.New("update stage is unavailable or unsafe")
	}

	installation, err := Load(request.Directory)
	if err != nil || installation.Image != request.PreviousImage || len(CheckPaths(installation)) != 0 {
		return StagedUpdate{}, ErrUpdateStageConflict
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		return StagedUpdate{}, errors.New("update stage could not be reserved")
	}
	journalDurable := false
	defer func() {
		if !journalDurable {
			_ = os.RemoveAll(root)
		}
	}()
	if err := requireTrustedPrivateDirectory(root); err != nil {
		return StagedUpdate{}, errors.New("update stage is unavailable or unsafe")
	}
	journal := newUpdateJournal(request, installation)
	if err := writeExclusiveJSON(updateJournalPath(request.Directory), journal); err != nil || syncDirectory(root) != nil || syncDirectory(request.Directory) != nil {
		return StagedUpdate{}, errors.New("update request could not be made durable")
	}
	journalDurable = true
	if err := ensureUpdateCandidate(request.Directory, journal); err != nil {
		return StagedUpdate{}, err
	}
	return journal.stage(request.Directory), nil
}

// ResumeUpdateStage opens only an already-durable exact stage. It is used to
// recover a v5 bridge process crash without treating an unhealthy stack as
// authority to begin a different update.
func ResumeUpdateStage(request UpdateStage) (StagedUpdate, error) {
	if err := request.validate(); err != nil {
		return StagedUpdate{}, err
	}
	root := updateStageRoot(request.Directory)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return StagedUpdate{}, ErrUpdateStageNotFound
	} else if err != nil {
		return StagedUpdate{}, errors.New("update stage is unavailable or unsafe")
	}
	return resumeUpdateStage(request)
}

// ExistingUpdateStage returns the immutable request from an existing valid
// host journal. It never creates or adopts a stage from caller-supplied fields.
func ExistingUpdateStage(directory string) (UpdateStage, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !safeEnvPath(directory) {
		return UpdateStage{}, errors.New("update stage directory is invalid")
	}
	root := updateStageRoot(directory)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return UpdateStage{}, ErrUpdateStageNotFound
	} else if err != nil || requireTrustedPrivateDirectory(root) != nil {
		return UpdateStage{}, errors.New("update stage is unavailable or unsafe")
	}
	journal, err := readUpdateJournal(directory)
	if err != nil {
		return UpdateStage{}, errors.New("update stage is unavailable or unsafe")
	}
	request := UpdateStage{Directory: directory, UpdateID: journal.UpdateID, PreviousRelease: journal.PreviousRelease, PreviousImage: journal.PreviousImage, TargetRelease: journal.TargetRelease, TargetImage: journal.TargetImage}
	if _, err := ResumeUpdateStage(request); err != nil {
		return UpdateStage{}, err
	}
	return request, nil
}

// UpdateRecoveryReceiptFile returns the fixed receipt path for an installation.
func UpdateRecoveryReceiptFile(directory string) string {
	return filepath.Join(updateStageRoot(directory), updateRecoveryName)
}

// BindUpdateRecoveryReceipt durably records an exact verified backup outside
// that backup. Repeated calls are accepted only for byte-identical authority.
func BindUpdateRecoveryReceipt(request UpdateStage, receipt UpdateRecoveryReceipt) (string, error) {
	_, targetDigest, hasDigest := strings.Cut(request.TargetImage, "@")
	if err := request.validate(); err != nil || !hasDigest || !receipt.valid() || receipt.UpdateID != request.UpdateID || receipt.TargetRelease != request.TargetRelease || receipt.TargetImageDigest != targetDigest {
		return "", errors.New("update recovery receipt is invalid")
	}
	stage, err := ResumeUpdateStage(request)
	if err != nil || stage.Published {
		return "", errors.New("update recovery receipt cannot be bound to this stage")
	}
	body, err := indentedJSON(receipt)
	if err != nil {
		return "", errors.New("update recovery receipt cannot be encoded")
	}
	path := UpdateRecoveryReceiptFile(request.Directory)
	if err := ensureExactProtectedFile(path, body); err != nil || syncDirectory(updateStageRoot(request.Directory)) != nil || syncDirectory(request.Directory) != nil {
		return "", errors.New("update recovery receipt could not be made durable")
	}
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:]), nil
}

// LoadUpdateRecoveryReceipt strictly reads a protected receipt and returns the
// digest used to bind an exact restore resume request.
func LoadUpdateRecoveryReceipt(path string) (UpdateRecoveryReceipt, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != updateRecoveryName || requireTrustedProtectedFile(path, 64<<10) != nil {
		return UpdateRecoveryReceipt{}, "", errors.New("update recovery receipt is unavailable or unsafe")
	}
	body, err := os.ReadFile(path) // #nosec G304 -- caller path is absolute and validated as a protected regular file.
	if err != nil {
		return UpdateRecoveryReceipt{}, "", errors.New("update recovery receipt is unavailable or unsafe")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var receipt UpdateRecoveryReceipt
	if decoder.Decode(&receipt) != nil || ensureJSONEOF(decoder) != nil || !receipt.valid() {
		return UpdateRecoveryReceipt{}, "", errors.New("update recovery receipt is invalid")
	}
	sum := sha256.Sum256(body)
	return receipt, fmt.Sprintf("%x", sum[:]), nil
}

func (receipt UpdateRecoveryReceipt) valid() bool {
	return receipt.Version == 1 && uuid.Validate(receipt.UpdateID) == nil && uuid.Validate(receipt.BackupID) == nil &&
		filepath.IsAbs(receipt.BackupDirectory) && filepath.Clean(receipt.BackupDirectory) == receipt.BackupDirectory && safeEnvPath(receipt.BackupDirectory) &&
		uuid.Validate(receipt.InstallationID) == nil && uuid.Validate(receipt.TimelineID) == nil && receipt.ChangeSequence >= 0 && receipt.SourceSchema > 0 &&
		updateReleasePattern.MatchString(receipt.TargetRelease) && updateDigestPattern.MatchString(receipt.TargetImageDigest) &&
		updateSnapshotPattern.MatchString(receipt.ExportedSnapshotID) && updateHashPattern.MatchString(receipt.ManifestSHA256)
}

func resumeUpdateStage(request UpdateStage) (StagedUpdate, error) {
	root := updateStageRoot(request.Directory)
	if err := requireTrustedPrivateDirectory(root); err != nil {
		return StagedUpdate{}, errors.New("update stage is unavailable or unsafe")
	}
	journal, err := readUpdateJournal(request.Directory)
	if err != nil || !journal.matches(request) {
		return StagedUpdate{}, ErrUpdateStageConflict
	}
	current, err := Load(request.Directory)
	if err != nil {
		return StagedUpdate{}, ErrUpdateStageConflict
	}
	previous := journal.previous(request.Directory)
	candidate := journal.candidate(request.Directory)
	switch current {
	case previous:
		if journal.Published {
			return StagedUpdate{}, ErrUpdateStageConflict
		}
	case candidate:
		if len(CheckPaths(current)) != 0 {
			return StagedUpdate{}, ErrUpdateStageConflict
		}
		if !journal.Published {
			journal.Published = true
			if err := replaceUpdateJournal(request.Directory, journal); err != nil {
				return StagedUpdate{}, errors.New("published update journal could not be reconciled")
			}
		}
	default:
		return StagedUpdate{}, ErrUpdateStageConflict
	}
	if err := ensureUpdateCandidate(request.Directory, journal); err != nil {
		return StagedUpdate{}, err
	}
	return journal.stage(request.Directory), nil
}

// PublishUpdate atomically replaces the generated environment and Compose
// files, then publishes installation.json last. Every boundary is idempotent.
func PublishUpdate(request UpdateStage) (Installation, error) {
	stage, err := StageUpdate(request)
	if err != nil {
		return Installation{}, err
	}
	journal, err := readUpdateJournal(request.Directory)
	if err != nil || !journal.matches(request) {
		return Installation{}, ErrUpdateStageConflict
	}
	candidate := journal.candidate(request.Directory)
	if stage.Published {
		if current, loadErr := Load(request.Directory); loadErr == nil && current == candidate && len(CheckPaths(current)) == 0 {
			return current, nil
		}
		return Installation{}, ErrUpdateStageConflict
	}

	if err := replacePublishedFile(EnvFile(request.Directory), []byte(daemonEnv(candidate)), request.UpdateID); err != nil {
		return Installation{}, errors.New("candidate environment could not be published")
	}
	if err := runUpdatePublicationHook(publishStepEnvironment); err != nil {
		return Installation{}, errors.New("candidate publication was interrupted")
	}
	if err := replacePublishedFile(OverrideFile(request.Directory), []byte(composeOverride()), request.UpdateID); err != nil {
		return Installation{}, errors.New("candidate Compose configuration could not be published")
	}
	if err := runUpdatePublicationHook(publishStepCompose); err != nil {
		return Installation{}, errors.New("candidate publication was interrupted")
	}
	configBody, err := indentedJSON(candidate)
	if err != nil || replacePublishedFile(ConfigFile(request.Directory), configBody, request.UpdateID) != nil {
		return Installation{}, errors.New("candidate installation marker could not be published")
	}
	if err := runUpdatePublicationHook(publishStepInstallation); err != nil {
		return Installation{}, errors.New("candidate publication was interrupted")
	}
	journal.Published = true
	if err := replaceUpdateJournal(request.Directory, journal); err != nil {
		return Installation{}, errors.New("candidate was published; rerun update publication to reconcile its journal")
	}
	return candidate, nil
}

// AbortStage removes only an unpublished stage. If publication stopped before
// installation.json, it first restores the generated files for the previous
// image so the old marker is internally consistent again.
func AbortStage(request UpdateStage) error {
	if err := request.validate(); err != nil {
		return err
	}
	root := updateStageRoot(request.Directory)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		current, loadErr := Load(request.Directory)
		if loadErr == nil && current.Image == request.PreviousImage && len(CheckPaths(current)) == 0 {
			if syncDirectory(request.Directory) == nil {
				return nil
			}
			return errors.New("update stage removal durability could not be reconciled")
		}
		return ErrUpdateStageConflict
	}
	if err := requireTrustedPrivateDirectory(root); err != nil {
		return errors.New("update stage is unavailable or unsafe")
	}
	journal, err := readUpdateJournal(request.Directory)
	if err != nil || !journal.matches(request) {
		return ErrUpdateStageConflict
	}
	current, err := Load(request.Directory)
	if err != nil {
		return ErrUpdateStageConflict
	}
	previous := journal.previous(request.Directory)
	if journal.Published || current == journal.candidate(request.Directory) {
		return ErrUpdateAlreadyPublished
	}
	if current != previous {
		return ErrUpdateStageConflict
	}
	if err := replacePublishedFile(EnvFile(request.Directory), []byte(daemonEnv(previous)), request.UpdateID); err != nil || replacePublishedFile(OverrideFile(request.Directory), []byte(composeOverride()), request.UpdateID) != nil {
		return errors.New("previous configuration could not be restored")
	}
	if err := os.RemoveAll(root); err != nil || syncDirectory(request.Directory) != nil {
		return errors.New("update stage could not be removed durably")
	}
	return nil
}

// PublishPreviousUpdate restores the journaled previous generated
// configuration for an explicitly selected fenced recovery. Unlike AbortStage,
// it may reverse an already-published target marker and is marker-last and
// idempotent across crashes.
func PublishPreviousUpdate(request UpdateStage) error {
	return restorePreviousUpdate(request, true)
}

// RestorePreviousUpdate publishes the previous marker and generated files but
// retains the host journal until recovery doctor and final database transition
// have succeeded.
func RestorePreviousUpdate(request UpdateStage) error {
	return restorePreviousUpdate(request, false)
}

func restorePreviousUpdate(request UpdateStage, complete bool) error {
	if err := request.validate(); err != nil {
		return err
	}
	root := updateStageRoot(request.Directory)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		current, loadErr := Load(request.Directory)
		if loadErr == nil && current.Image == request.PreviousImage && len(CheckPaths(current)) == 0 {
			if !complete || syncDirectory(request.Directory) == nil {
				return nil
			}
			return errors.New("previous recovery stage removal durability could not be reconciled")
		}
		return ErrUpdateStageConflict
	}
	journal, err := readUpdateJournal(request.Directory)
	if err != nil || !journal.matches(request) {
		return ErrUpdateStageConflict
	}
	previous := journal.previous(request.Directory)
	if err := replacePublishedFile(EnvFile(request.Directory), []byte(daemonEnv(previous)), request.UpdateID); err != nil ||
		replacePublishedFile(OverrideFile(request.Directory), []byte(composeOverride()), request.UpdateID) != nil {
		return errors.New("previous recovery configuration could not be staged")
	}
	configBody, err := indentedJSON(previous)
	if err != nil || replacePublishedFile(ConfigFile(request.Directory), configBody, request.UpdateID) != nil {
		return errors.New("previous recovery marker could not be published")
	}
	if complete {
		if err := os.RemoveAll(root); err != nil || syncDirectory(request.Directory) != nil {
			return errors.New("previous recovery stage could not be removed durably")
		}
	}
	return nil
}

// CompleteStage removes the host journal only after the target marker and all
// generated files are published exactly. The durable database transaction is
// the long-term update record; retaining .update would block the next update.
func CompleteStage(request UpdateStage) error {
	if err := request.validate(); err != nil {
		return err
	}
	if _, err := os.Lstat(updateStageRoot(request.Directory)); errors.Is(err, os.ErrNotExist) {
		current, loadErr := Load(request.Directory)
		if loadErr == nil && current.Image == request.TargetImage && len(CheckPaths(current)) == 0 {
			if syncDirectory(request.Directory) == nil {
				return nil
			}
			return errors.New("completed update stage removal durability could not be reconciled")
		}
		return ErrUpdateStageConflict
	}
	journal, err := readUpdateJournal(request.Directory)
	if err != nil || !journal.matches(request) || !journal.Published {
		return ErrUpdateStageConflict
	}
	current, err := Load(request.Directory)
	if err != nil || current != journal.candidate(request.Directory) || len(CheckPaths(current)) != 0 {
		return ErrUpdateStageConflict
	}
	if err := os.RemoveAll(updateStageRoot(request.Directory)); err != nil || syncDirectory(request.Directory) != nil {
		return errors.New("completed update stage could not be removed durably")
	}
	return nil
}

func (request UpdateStage) validate() error {
	if !filepath.IsAbs(request.Directory) || filepath.Clean(request.Directory) != request.Directory || !safeEnvPath(request.Directory) || uuid.Validate(request.UpdateID) != nil || !updateReleasePattern.MatchString(request.PreviousRelease) || !updateReleasePattern.MatchString(request.TargetRelease) || request.PreviousRelease == request.TargetRelease || !validImageDigest(request.PreviousImage) || !validImageDigest(request.TargetImage) || request.PreviousImage == request.TargetImage {
		return errors.New("update stage request is invalid")
	}
	return nil
}

func newUpdateJournal(request UpdateStage, installation Installation) updateJournal {
	installation.Directory = ""
	return updateJournal{Version: updateJournalVersion, UpdateID: request.UpdateID, PreviousRelease: request.PreviousRelease, PreviousImage: request.PreviousImage, TargetRelease: request.TargetRelease, TargetImage: request.TargetImage, PreviousInstallation: installation}
}

func (journal updateJournal) valid() bool {
	request := UpdateStage{Directory: string(filepath.Separator), UpdateID: journal.UpdateID, PreviousRelease: journal.PreviousRelease, PreviousImage: journal.PreviousImage, TargetRelease: journal.TargetRelease, TargetImage: journal.TargetImage}
	return journal.Version == updateJournalVersion && request.validate() == nil && journal.PreviousInstallation.Version == 1 && journal.PreviousInstallation.Image == journal.PreviousImage && journal.PreviousInstallation.Directory == ""
}

func (journal updateJournal) matches(request UpdateStage) bool {
	return journal.valid() && journal.UpdateID == request.UpdateID && journal.PreviousRelease == request.PreviousRelease && journal.PreviousImage == request.PreviousImage && journal.TargetRelease == request.TargetRelease && journal.TargetImage == request.TargetImage
}

func (journal updateJournal) previous(directory string) Installation {
	installation := journal.PreviousInstallation
	installation.Directory = directory
	return installation
}

func (journal updateJournal) candidate(directory string) Installation {
	installation := journal.previous(directory)
	installation.Image = journal.TargetImage
	return installation
}

func (journal updateJournal) stage(directory string) StagedUpdate {
	return StagedUpdate{Directory: directory, CandidateDirectory: updateCandidateDirectory(directory), UpdateID: journal.UpdateID, PreviousRelease: journal.PreviousRelease, PreviousImage: journal.PreviousImage, TargetRelease: journal.TargetRelease, TargetImage: journal.TargetImage, Published: journal.Published}
}

func updateStageRoot(directory string) string {
	return filepath.Join(directory, updateStageDirectoryName)
}

func updateCandidateDirectory(directory string) string {
	return filepath.Join(updateStageRoot(directory), updateCandidateName)
}

func updateJournalPath(directory string) string {
	return filepath.Join(updateStageRoot(directory), updateJournalName)
}

func ensureUpdateCandidate(directory string, journal updateJournal) error {
	candidateDirectory := updateCandidateDirectory(directory)
	if _, err := os.Lstat(candidateDirectory); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(candidateDirectory, 0o700); err != nil {
			return errors.New("candidate configuration could not be reserved")
		}
	} else if err != nil {
		return errors.New("candidate configuration is unavailable or unsafe")
	}
	if err := requireTrustedPrivateDirectory(candidateDirectory); err != nil {
		return errors.New("candidate configuration is unavailable or unsafe")
	}
	candidate := journal.candidate(directory)
	configBody, err := indentedJSON(candidate)
	if err != nil || ensureExactProtectedFile(ConfigFile(candidateDirectory), configBody) != nil || ensureExactProtectedFile(EnvFile(candidateDirectory), []byte(daemonEnv(candidate))) != nil || ensureExactProtectedFile(OverrideFile(candidateDirectory), []byte(composeOverride())) != nil {
		return errors.New("candidate configuration is incomplete or does not match the update request")
	}
	if syncDirectory(candidateDirectory) != nil || syncDirectory(updateStageRoot(directory)) != nil || syncDirectory(directory) != nil {
		return errors.New("candidate configuration could not be made durable")
	}
	return nil
}

func ensureExactProtectedFile(path string, body []byte) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return writeExclusive(path, body)
	} else if err != nil || requireTrustedProtectedFile(path, int64(len(body))+1) != nil {
		return errors.New("protected staged file is unsafe")
	}
	existing, err := os.ReadFile(path) // #nosec G304 -- fixed file in a validated private stage.
	if err != nil || !bytes.Equal(existing, body) {
		return errors.New("protected staged file does not match")
	}
	return nil
}

func readUpdateJournal(directory string) (updateJournal, error) {
	path := updateJournalPath(directory)
	if err := requireTrustedProtectedFile(path, 64<<10); err != nil {
		return updateJournal{}, err
	}
	file, err := os.Open(path) // #nosec G304 -- fixed journal below a validated private installation.
	if err != nil {
		return updateJournal{}, err
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	var journal updateJournal
	if err := decoder.Decode(&journal); err != nil || ensureJSONEOF(decoder) != nil || !journal.valid() {
		return updateJournal{}, errors.New("update journal is invalid")
	}
	return journal, nil
}

func indentedJSON(value any) ([]byte, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func replaceUpdateJournal(directory string, journal updateJournal) error {
	body, err := indentedJSON(journal)
	if err != nil {
		return err
	}
	return replacePublishedFile(updateJournalPath(directory), body, journal.UpdateID)
}

func replacePublishedFile(path string, body []byte, updateID string) error {
	if err := requireTrustedDirectoryAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	temporary := path + "." + updateID + ".pending"
	if _, err := os.Lstat(temporary); err == nil {
		if err := ensureExactProtectedFile(temporary, body); err != nil {
			return err
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := writeExclusive(temporary, body); err != nil {
			return err
		}
	} else {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func runUpdatePublicationHook(step string) error {
	if updatePublicationHook == nil {
		return nil
	}
	return updatePublicationHook(step)
}
