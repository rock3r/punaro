package bootstrap

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

type acceptedState struct {
	Schema          int64  `json:"schema"`
	Release         string `json:"release"`
	ReleaseSequence int64  `json:"release_sequence"`
	CatalogSequence int64  `json:"catalog_sequence"`
	ManifestSHA256  string `json:"manifest_sha256"`
}

type healthyGenerationState struct {
	Schema         int64  `json:"schema"`
	Release        string `json:"release"`
	Sequence       int64  `json:"sequence"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Generation     int64  `json:"generation"`
}

type slotState struct {
	Schema         int64  `json:"schema"`
	Release        string `json:"release"`
	Sequence       int64  `json:"sequence"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Generation     int64  `json:"generation,omitempty"`
}

type journal struct {
	Schema          int64  `json:"schema"`
	Phase           string `json:"phase"`
	Release         string `json:"release"`
	Sequence        int64  `json:"sequence"`
	CatalogSequence int64  `json:"catalog_sequence,omitempty"`
	ManifestSHA256  string `json:"manifest_sha256,omitempty"`
}

type autoRollbackState struct {
	Schema         int64  `json:"schema"`
	Release        string `json:"release"`
	Sequence       int64  `json:"sequence"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Generation     int64  `json:"generation,omitempty"`
}

func prepareDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.New("bootstrap directory is invalid")
		}
		if err := requireTrustedExistingAncestor(filepath.Dir(filepath.Clean(directory))); err != nil {
			return err
		}
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return errors.New("bootstrap directory is invalid")
		}
		// #nosec G302 -- newly created bootstrap directories are 0700, not 0600 files.
		if err := os.Chmod(directory, 0o700); err != nil {
			return errors.New("bootstrap directory is invalid")
		}
	} else if !info.IsDir() {
		return errors.New("bootstrap directory is invalid")
	}
	return requireTrustedBootstrapDirectory(directory)
}

func publishSlot(directory, release string, sequence int64, manifestSHA256 string) error {
	candidate := filepath.Join(directory, candidateSlot)
	current := filepath.Join(directory, currentSlot)
	previous := filepath.Join(directory, previousSlot)
	if err := requireRealDir(candidate); err != nil {
		return err
	}
	generation, err := nextSlotGeneration(directory)
	if err != nil {
		return err
	}
	record, err := json.Marshal(slotState{Schema: 1, Release: release, Sequence: sequence, ManifestSHA256: manifestSHA256, Generation: generation})
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(candidate, slotRecord), record, 0o600); err != nil {
		return err
	}
	currentExists, err := existsRealDir(current)
	if err != nil {
		return err
	}
	if currentExists {
		if err := os.RemoveAll(previous); err != nil {
			return err
		}
		if err := os.Rename(current, previous); err != nil {
			return err
		}
		if err := syncDir(directory); err != nil {
			return err
		}
	}
	if err := os.Rename(candidate, current); err != nil {
		return err
	}
	return syncDir(directory)
}

func replaceCurrent(directory, release string, sequence int64, manifestSHA256 string) error {
	candidate := filepath.Join(directory, candidateSlot)
	current := filepath.Join(directory, currentSlot)
	if err := requireRealDir(candidate); err != nil {
		return err
	}
	generation, err := nextSlotGeneration(directory)
	if err != nil {
		return err
	}
	record, err := json.Marshal(slotState{Schema: 1, Release: release, Sequence: sequence, ManifestSHA256: manifestSHA256, Generation: generation})
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(candidate, slotRecord), record, 0o600); err != nil {
		return err
	}
	if err := quarantineUnreadablePrevious(directory); err != nil {
		return err
	}
	if err := os.RemoveAll(current); err != nil {
		return err
	}
	if err := os.Rename(candidate, current); err != nil {
		return err
	}
	return syncDir(directory)
}

// Rollback swaps the published current and previous slots. It does not lower
// the highest accepted sequences, so a later automatic update still cannot
// move backward.
func Rollback(directory string) (Result, error) {
	if directory == "" || !filepath.IsAbs(directory) {
		return Result{}, errors.New("bootstrap directory is invalid")
	}
	if err := prepareDirectory(directory); err != nil {
		return Result{}, err
	}
	unlock, err := lockDirectory(directory)
	if err != nil {
		return Result{}, err
	}
	defer unlock()
	if err := recoverRepairableJournal(directory); err != nil {
		return Result{}, err
	}
	current := filepath.Join(directory, currentSlot)
	previous := filepath.Join(directory, previousSlot)
	if err := requireRealDir(current); err != nil {
		return Result{}, errors.New("bootstrap has no current slot")
	}
	if err := requireRealDir(previous); err != nil {
		return Result{}, errors.New("bootstrap has no previous slot")
	}
	target, err := readSlot(previous)
	if err != nil {
		return Result{}, err
	}
	if err := writeJournal(directory, journal{Schema: 1, Phase: "rolling-back", Release: target.Release, Sequence: target.Sequence, ManifestSHA256: target.ManifestSHA256}); err != nil {
		return Result{}, err
	}
	if err := completeRollback(directory, target); err != nil {
		return Result{}, err
	}
	if err := recordRolledAwayCurrent(directory); err != nil {
		return Result{}, err
	}
	if err := clearRecovery(directory); err != nil {
		return Result{}, err
	}
	if err := clearJournal(directory); err != nil {
		return Result{}, err
	}
	slot, err := readSlot(current)
	if err != nil {
		return Result{}, err
	}
	return Result{Release: slot.Release, Sequence: slot.Sequence, Manifest: slot.ManifestSHA256}, nil
}

var errInvalidJournal = errors.New("bootstrap journal is invalid")

func recoverRepairableJournal(directory string) error {
	err := recoverJournal(directory)
	if errors.Is(err, errInvalidJournal) {
		return nil
	}
	return err
}

func recoverJournal(directory string) error {
	if err := removeAbandonedTemps(directory); err != nil {
		return err
	}
	record, err := readJournal(directory)
	if errors.Is(err, errInvalidJournal) {
		return failInvalidJournal(directory)
	}
	if err != nil {
		return err
	}
	if record.Phase != "" && record.Schema != 1 {
		return failInvalidJournal(directory)
	}
	switch record.Phase {
	case "", "staging":
		return os.RemoveAll(filepath.Join(directory, candidateSlot))
	case "seeding":
		if record.Release == "" || record.Sequence < 1 || !validManifestDigest(record.ManifestSHA256) {
			return failInvalidJournal(directory)
		}
		exists, err := existsRealDir(filepath.Join(directory, candidateSlot))
		if err != nil {
			return err
		}
		if exists {
			if err := replaceCurrent(directory, record.Release, record.Sequence, record.ManifestSHA256); err != nil {
				return err
			}
		}
		return finishSeed(directory, record)
	case "publishing", "repairing":
		if record.Release == "" || record.Sequence < 1 || record.CatalogSequence < 1 || !validManifestDigest(record.ManifestSHA256) {
			return failInvalidJournal(directory)
		}
		exists, err := existsRealDir(filepath.Join(directory, candidateSlot))
		if err != nil {
			return err
		}
		if exists {
			if record.Phase == "repairing" {
				if err := replaceCurrent(directory, record.Release, record.Sequence, record.ManifestSHA256); err != nil {
					return err
				}
			} else if err := publishSlot(directory, record.Release, record.Sequence, record.ManifestSHA256); err != nil {
				return err
			}
		}
		return finishPublication(directory, acceptedState{
			Schema:          1,
			Release:         record.Release,
			ReleaseSequence: record.Sequence,
			CatalogSequence: record.CatalogSequence,
			ManifestSHA256:  record.ManifestSHA256,
		})
	case "rolling-back":
		if record.Release == "" || record.Sequence < 1 || !validManifestDigest(record.ManifestSHA256) {
			return failInvalidJournal(directory)
		}
		if err := completeRollback(directory, slotState{Release: record.Release, Sequence: record.Sequence, ManifestSHA256: record.ManifestSHA256}); err != nil {
			return err
		}
		if err := applyRollbackCatalogSequence(directory, record.CatalogSequence); err != nil {
			return err
		}
		if err := recordRolledAwayCurrent(directory); err != nil {
			return err
		}
		if err := clearRecovery(directory); err != nil {
			return err
		}
		return clearJournal(directory)
	default:
		return failInvalidJournal(directory)
	}
}

func readRepairableCurrent(directory string) (slotState, error) {
	current, err := readOptionalSlot(filepath.Join(directory, currentSlot))
	if err == nil {
		if obsErr := observeGeneration(directory, current.Generation); obsErr != nil {
			return slotState{}, obsErr
		}
		return current, nil
	}
	if recErr := writeRecoveryRecord(directory, recoveryCurrentExited); recErr != nil {
		return slotState{}, recErr
	}
	if err := os.RemoveAll(filepath.Join(directory, currentSlot)); err != nil {
		return slotState{}, err
	}
	return slotState{}, nil
}

func currentGenerationIsHealthy(directory string, current slotState) bool {
	if current.Release == "" || current.Sequence < 1 || !validManifestDigest(current.ManifestSHA256) {
		return false
	}
	record, err := loadHealthyGeneration(directory)
	return err == nil && record.Release == current.Release && record.Sequence == current.Sequence && record.ManifestSHA256 == current.ManifestSHA256 && record.Generation == current.Generation
}

func rememberHealthyGeneration(directory string, current slotState) error {
	if current.Release == "" || current.Sequence < 1 || !validManifestDigest(current.ManifestSHA256) {
		return nil
	}
	body, err := json.Marshal(healthyGenerationState{
		Schema:         1,
		Release:        current.Release,
		Sequence:       current.Sequence,
		ManifestSHA256: current.ManifestSHA256,
		Generation:     current.Generation,
	})
	if err != nil {
		return err
	}
	path := filepath.Join(directory, healthyGenerationFile)
	if err := removeNonRegular(path); err != nil {
		return err
	}
	if err := writeAtomic(path, body, 0o600); err != nil {
		return err
	}
	return observeGeneration(directory, current.Generation)
}

func loadHealthyGeneration(directory string) (healthyGenerationState, error) {
	body, err := os.ReadFile(filepath.Join(directory, healthyGenerationFile)) // #nosec G304 -- healthy generation is a fixed child of the bootstrap directory.
	if err != nil {
		return healthyGenerationState{}, err
	}
	var record healthyGenerationState
	if json.Unmarshal(body, &record) != nil || record.Schema != 1 || record.Release == "" || record.Sequence < 1 || !validManifestDigest(record.ManifestSHA256) {
		return healthyGenerationState{}, errors.New("bootstrap healthy generation is invalid")
	}
	return record, nil
}

func failInvalidJournal(directory string) error {
	if err := writeRecoveryRecord(directory, recoveryCurrentExited); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(directory, journalFile)); err != nil {
		return err
	}
	if err := syncDir(directory); err != nil {
		return err
	}
	return errInvalidJournal
}

func recordRolledAwayCurrent(directory string) error {
	away, err := readOptionalSlot(filepath.Join(directory, previousSlot))
	if err != nil {
		return err
	}
	if away.Release == "" {
		return nil
	}
	return saveAutoRollback(directory, away)
}

func loadAutoRollback(directory string) (autoRollbackState, error) {
	path := filepath.Join(directory, autoRollbackFile)
	info, err := os.Lstat(path) // #nosec G703 -- auto-rollback record is a fixed child of the bootstrap directory.
	if os.IsNotExist(err) {
		return autoRollbackState{}, nil
	}
	if err != nil {
		return autoRollbackState{}, err
	}
	if !info.Mode().IsRegular() {
		if err := os.RemoveAll(path); err != nil {
			return autoRollbackState{}, err
		}
		if err := syncDir(directory); err != nil {
			return autoRollbackState{}, err
		}
		return autoRollbackState{}, nil
	}
	body, err := os.ReadFile(path) // #nosec G304 -- auto-rollback record is a fixed child of the bootstrap directory.
	if err != nil {
		return autoRollbackState{}, err
	}
	if err := rejectDuplicateJSONFields(body); err != nil {
		return quarantineInvalidAutoRollback(directory)
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var record autoRollbackState
	if err := decoder.Decode(&record); err != nil {
		return quarantineInvalidAutoRollback(directory)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return quarantineInvalidAutoRollback(directory)
	}
	if record.Schema != 1 || record.Release == "" || record.Sequence < 1 || !validManifestDigest(record.ManifestSHA256) {
		return quarantineInvalidAutoRollback(directory)
	}
	return record, nil
}

func quarantineInvalidAutoRollback(directory string) (autoRollbackState, error) {
	if err := os.RemoveAll(filepath.Join(directory, autoRollbackFile)); err != nil {
		return autoRollbackState{}, err
	}
	if err := syncDir(directory); err != nil {
		return autoRollbackState{}, err
	}
	return autoRollbackState{}, nil
}

func saveAutoRollback(directory string, away slotState) error {
	if away.Release == "" || away.Sequence < 1 || !validManifestDigest(away.ManifestSHA256) {
		return errors.New("bootstrap auto-rollback state is invalid")
	}
	body, err := json.Marshal(autoRollbackState{
		Schema:         1,
		Release:        away.Release,
		Sequence:       away.Sequence,
		ManifestSHA256: away.ManifestSHA256,
		Generation:     away.Generation,
	})
	if err != nil {
		return err
	}
	path := filepath.Join(directory, autoRollbackFile)
	if err := removeNonRegular(path); err != nil {
		return err
	}
	return writeAtomic(path, body, 0o600)
}

func blocksAutoRollback(directory string, previous slotState) (bool, error) {
	record, err := loadAutoRollback(directory)
	if err != nil {
		return false, err
	}
	if record.Release == "" {
		return false, nil
	}
	return record.Release == previous.Release && record.Sequence == previous.Sequence && record.ManifestSHA256 == previous.ManifestSHA256 && record.Generation == previous.Generation, nil
}

func applyRollbackCatalogSequence(directory string, catalogSequence int64) error {
	if catalogSequence < 1 {
		return nil
	}
	accepted, err := loadAccepted(directory)
	if err != nil {
		return err
	}
	if accepted.ReleaseSequence < 1 || accepted.CatalogSequence >= catalogSequence {
		return nil
	}
	accepted.CatalogSequence = catalogSequence
	return saveAccepted(directory, accepted)
}

func finishSeed(directory string, record journal) error {
	if record.Release == "" || record.Sequence < 1 || !validManifestDigest(record.ManifestSHA256) {
		return errors.New("bootstrap journal is invalid")
	}
	accepted, err := loadAccepted(directory)
	if err != nil {
		return err
	}
	if accepted.Release == "" || accepted.Release == localCheckoutRelease {
		if err := saveAccepted(directory, acceptedState{
			Schema:          1,
			Release:         record.Release,
			ReleaseSequence: record.Sequence,
			CatalogSequence: 1,
			ManifestSHA256:  record.ManifestSHA256,
		}); err != nil {
			return err
		}
	}
	if err := clearRecovery(directory); err != nil {
		return err
	}
	return clearJournal(directory)
}

func finishPublication(directory string, accepted acceptedState) error {
	if accepted.Schema != 1 || accepted.Release == "" || accepted.ReleaseSequence < 1 || accepted.CatalogSequence < 1 || accepted.ManifestSHA256 == "" {
		return errors.New("bootstrap journal is invalid")
	}
	if err := saveAccepted(directory, accepted); err != nil {
		return err
	}
	if err := quarantineUnreadablePrevious(directory); err != nil {
		return err
	}
	if err := clearRecovery(directory); err != nil {
		return err
	}
	return clearJournal(directory)
}

func quarantineUnreadablePrevious(directory string) error {
	if _, err := readOptionalSlot(filepath.Join(directory, previousSlot)); err != nil {
		if err := os.RemoveAll(filepath.Join(directory, previousSlot)); err != nil {
			return err
		}
		return syncDir(directory)
	}
	return nil
}

func completeRollback(directory string, target slotState) error {
	current := filepath.Join(directory, currentSlot)
	previous := filepath.Join(directory, previousSlot)
	swap := filepath.Join(directory, swapSlot)
	currentExists, err := existsRealDir(current)
	if err != nil {
		return err
	}
	previousExists, err := existsRealDir(previous)
	if err != nil {
		return err
	}
	swapExists, err := existsRealDir(swap)
	if err != nil {
		return err
	}
	if currentExists {
		currentSlotState, err := readSlot(current)
		if err != nil {
			return err
		}
		if currentSlotState.Release == target.Release && currentSlotState.Sequence == target.Sequence && currentSlotState.ManifestSHA256 == target.ManifestSHA256 {
			if swapExists && !previousExists {
				if err := os.Rename(swap, previous); err != nil {
					return err
				}
				return syncDir(directory)
			}
			if !swapExists {
				return nil
			}
			if err := os.RemoveAll(swap); err != nil {
				return err
			}
			return syncDir(directory)
		}
	}
	if currentExists && previousExists && !swapExists {
		if err := os.Rename(current, swap); err != nil {
			return err
		}
		if err := syncDir(directory); err != nil {
			return err
		}
		currentExists = false
		swapExists = true
	}
	if swapExists && previousExists && !currentExists {
		if err := os.Rename(previous, current); err != nil {
			return err
		}
		if err := syncDir(directory); err != nil {
			return err
		}
		previousExists = false
		currentExists = true
	}
	if swapExists && currentExists && !previousExists {
		if err := os.Rename(swap, previous); err != nil {
			return err
		}
		return syncDir(directory)
	}
	if !swapExists && currentExists && previousExists {
		return nil
	}
	return errors.New("bootstrap rollback is incomplete")
}

func writeJournal(directory string, record journal) error {
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(directory, journalFile), body, 0o600)
}

func clearJournal(directory string) error {
	err := os.Remove(filepath.Join(directory, journalFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(directory)
}

func readJournal(directory string) (journal, error) {
	path := filepath.Join(directory, journalFile)
	info, err := os.Lstat(path) // #nosec G703 -- journal is a fixed child of the bootstrap directory.
	if os.IsNotExist(err) {
		return journal{}, nil
	}
	if err != nil {
		return journal{}, err
	}
	if !info.Mode().IsRegular() {
		return journal{}, errInvalidJournal
	}
	body, err := os.ReadFile(path) // #nosec G304 -- journal is a fixed child of the bootstrap directory.
	if err != nil {
		return journal{}, err
	}
	return parseJournal(body)
}

func parseJournal(body []byte) (journal, error) {
	if err := rejectDuplicateJSONFields(body); err != nil {
		return journal{}, errInvalidJournal
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var record journal
	if err := decoder.Decode(&record); err != nil {
		return journal{}, errInvalidJournal
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return journal{}, errInvalidJournal
	}
	return record, nil
}

func loadAccepted(directory string) (acceptedState, error) {
	body, err := os.ReadFile(filepath.Join(directory, acceptedFile)) // #nosec G304 -- accepted record is a fixed child of the bootstrap directory.
	if os.IsNotExist(err) {
		return acceptedState{}, nil
	}
	if err != nil {
		return acceptedState{}, err
	}
	accepted, err := parseAccepted(body)
	if err != nil {
		return acceptedState{}, err
	}
	return accepted, nil
}

func parseAccepted(body []byte) (acceptedState, error) {
	if err := rejectDuplicateJSONFields(body); err != nil {
		return acceptedState{}, errors.New("bootstrap accepted state is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var accepted acceptedState
	if err := decoder.Decode(&accepted); err != nil {
		return acceptedState{}, errors.New("bootstrap accepted state is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return acceptedState{}, errors.New("bootstrap accepted state is invalid")
	}
	if accepted.Schema != 1 || accepted.Release == "" || accepted.ReleaseSequence < 1 || accepted.CatalogSequence < 1 || !validManifestDigest(accepted.ManifestSHA256) {
		return acceptedState{}, errors.New("bootstrap accepted state is invalid")
	}
	return accepted, nil
}

func saveAccepted(directory string, accepted acceptedState) error {
	body, err := json.Marshal(accepted)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(directory, acceptedFile), body, 0o600)
}

// Status reports the published slots without contacting the origin.
func Status(directory string) (State, error) {
	if directory == "" || !filepath.IsAbs(directory) {
		return State{}, errors.New("bootstrap directory is invalid")
	}
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return State{}, nil
	}
	if err := prepareDirectory(directory); err != nil {
		return State{}, err
	}
	unlock, err := lockDirectory(directory)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	if err := recoverRepairableJournal(directory); err != nil {
		return State{}, err
	}
	accepted, err := loadAccepted(directory)
	if err != nil {
		return State{}, err
	}
	current, err := readOptionalSlot(filepath.Join(directory, currentSlot))
	if err != nil {
		return State{}, err
	}
	previous, err := readOptionalSlot(filepath.Join(directory, previousSlot))
	if err != nil {
		return State{}, err
	}
	recovery, err := loadRecovery(directory)
	if err != nil {
		return State{}, err
	}
	return State{
		Current:          current.Release,
		CurrentSequence:  current.Sequence,
		Previous:         previous.Release,
		PreviousSequence: previous.Sequence,
		CatalogSequence:  accepted.CatalogSequence,
		RecoveryOnly:     recovery.Mode == recoveryMode,
	}, nil
}

type generationHighWaterState struct {
	Schema     int64 `json:"schema"`
	Generation int64 `json:"generation"`
}

func nextSlotGeneration(directory string) (int64, error) {
	var high int64
	for _, name := range []string{currentSlot, previousSlot, candidateSlot} {
		slot, err := readOptionalSlot(filepath.Join(directory, name))
		if err != nil {
			continue
		}
		if slot.Generation > high {
			high = slot.Generation
		}
	}
	if record, err := loadAutoRollback(directory); err == nil && record.Generation > high {
		high = record.Generation
	}
	if record, err := loadHealthyGeneration(directory); err == nil && record.Generation > high {
		high = record.Generation
	}
	if record, err := loadGenerationHighWater(directory); err == nil && record.Generation > high {
		high = record.Generation
	}
	if high == math.MaxInt64 {
		return 0, errors.New("bootstrap generation high-water is exhausted")
	}
	next := high + 1
	if err := observeGeneration(directory, next); err != nil {
		return 0, err
	}
	return next, nil
}

func observeGeneration(directory string, generation int64) error {
	if generation < 1 {
		return nil
	}
	if record, err := loadGenerationHighWater(directory); err == nil && record.Generation >= generation {
		return nil
	}
	return saveGenerationHighWater(directory, generation)
}

func loadGenerationHighWater(directory string) (generationHighWaterState, error) {
	body, err := os.ReadFile(filepath.Join(directory, generationHighWaterFile)) // #nosec G304 -- generation high-water is a fixed child of the bootstrap directory.
	if err != nil {
		return generationHighWaterState{}, err
	}
	var record generationHighWaterState
	if json.Unmarshal(body, &record) != nil || record.Schema != 1 || record.Generation < 1 {
		return generationHighWaterState{}, errors.New("bootstrap generation high-water is invalid")
	}
	return record, nil
}

func saveGenerationHighWater(directory string, generation int64) error {
	if generation < 1 {
		return nil
	}
	body, err := json.Marshal(generationHighWaterState{Schema: 1, Generation: generation})
	if err != nil {
		return err
	}
	path := filepath.Join(directory, generationHighWaterFile)
	if err := removeNonRegular(path); err != nil {
		return err
	}
	return writeAtomic(path, body, 0o600)
}

func readOptionalSlot(directory string) (slotState, error) {
	_, err := os.Lstat(directory) // #nosec G703 -- slot is a fixed child of the bootstrap directory.
	if os.IsNotExist(err) {
		return slotState{}, nil
	}
	if err != nil {
		return slotState{}, err
	}
	return readSlot(directory)
}

func readSlot(directory string) (slotState, error) {
	if err := requireRealDir(directory); err != nil {
		return slotState{}, err
	}
	recordPath := filepath.Join(directory, slotRecord)
	info, err := os.Lstat(recordPath) // #nosec G703 -- slot record is a fixed child.
	if err != nil || !info.Mode().IsRegular() {
		return slotState{}, errors.New("bootstrap slot is invalid")
	}
	body, err := os.ReadFile(recordPath) // #nosec G304 -- slot record is a fixed child.
	if err != nil {
		return slotState{}, err
	}
	slot, err := parseSlot(body)
	if err != nil {
		return slotState{}, err
	}
	return slot, nil
}

func parseSlot(body []byte) (slotState, error) {
	if err := rejectDuplicateJSONFields(body); err != nil {
		return slotState{}, errors.New("bootstrap slot is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var slot slotState
	if err := decoder.Decode(&slot); err != nil {
		return slotState{}, errors.New("bootstrap slot is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return slotState{}, errors.New("bootstrap slot is invalid")
	}
	if slot.Schema != 1 || slot.Release == "" || slot.Sequence < 1 || !validManifestDigest(slot.ManifestSHA256) {
		return slotState{}, errors.New("bootstrap slot is invalid")
	}
	return slot, nil
}

func rejectDuplicateJSONFields(body []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("bootstrap document is invalid")
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := key.(string)
		if !ok {
			return errors.New("bootstrap document is invalid")
		}
		if _, exists := seen[name]; exists {
			return errors.New("bootstrap document is invalid")
		}
		seen[name] = struct{}{}
		var value any
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	return nil
}

func validManifestDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func requireRealDir(path string) error {
	info, err := os.Lstat(path) // #nosec G703 -- path is a bootstrap-owned slot or the operator-selected absolute directory.
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("bootstrap directory is invalid")
	}
	return nil
}

func existsRealDir(path string) (bool, error) {
	info, err := os.Lstat(path) // #nosec G703 -- path is a bootstrap-owned slot or the operator-selected absolute directory.
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, errors.New("bootstrap directory is invalid")
	}
	return true, nil
}

func removeAbandonedTemps(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tmp") {
			continue
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func removeNonRegular(path string) error {
	info, err := os.Lstat(path) // #nosec G703 -- marker is a fixed child of the bootstrap directory.
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode().IsRegular() {
		return nil
	}
	return os.RemoveAll(path) // #nosec G703 -- marker is a fixed child of the bootstrap directory.
}

func writeAtomic(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}
