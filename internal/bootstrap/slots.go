package bootstrap

import (
	"encoding/json"
	"errors"
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

type slotState struct {
	Schema         int64  `json:"schema"`
	Release        string `json:"release"`
	Sequence       int64  `json:"sequence"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type journal struct {
	Schema          int64  `json:"schema"`
	Phase           string `json:"phase"`
	Release         string `json:"release"`
	Sequence        int64  `json:"sequence"`
	CatalogSequence int64  `json:"catalog_sequence,omitempty"`
	ManifestSHA256  string `json:"manifest_sha256,omitempty"`
}

func prepareDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		if !os.IsNotExist(err) {
			return errors.New("bootstrap directory is invalid")
		}
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return errors.New("bootstrap directory is invalid")
		}
	} else if !info.IsDir() {
		return errors.New("bootstrap directory is invalid")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
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
	record, err := json.Marshal(slotState{Schema: 1, Release: release, Sequence: sequence, ManifestSHA256: manifestSHA256})
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
	if err := recoverJournal(directory); err != nil {
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
	if err := clearJournal(directory); err != nil {
		return Result{}, err
	}
	slot, err := readSlot(current)
	if err != nil {
		return Result{}, err
	}
	return Result{Release: slot.Release, Sequence: slot.Sequence, Manifest: slot.ManifestSHA256}, nil
}

func recoverJournal(directory string) error {
	if err := removeAbandonedTemps(directory); err != nil {
		return err
	}
	record, err := readJournal(directory)
	if err != nil {
		return err
	}
	switch record.Phase {
	case "", "staging":
		return os.RemoveAll(filepath.Join(directory, candidateSlot))
	case "publishing":
		if record.Release == "" || record.Sequence < 1 || record.CatalogSequence < 1 || record.ManifestSHA256 == "" {
			return errors.New("bootstrap journal is invalid")
		}
		exists, err := existsRealDir(filepath.Join(directory, candidateSlot))
		if err != nil {
			return err
		}
		if exists {
			if err := publishSlot(directory, record.Release, record.Sequence, record.ManifestSHA256); err != nil {
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
		if record.Release == "" || record.Sequence < 1 {
			return errors.New("bootstrap journal is invalid")
		}
		if err := completeRollback(directory, slotState{Release: record.Release, Sequence: record.Sequence, ManifestSHA256: record.ManifestSHA256}); err != nil {
			return err
		}
		return clearJournal(directory)
	default:
		return errors.New("bootstrap journal is invalid")
	}
}

func finishPublication(directory string, accepted acceptedState) error {
	if accepted.Schema != 1 || accepted.Release == "" || accepted.ReleaseSequence < 1 || accepted.CatalogSequence < 1 || accepted.ManifestSHA256 == "" {
		return errors.New("bootstrap journal is invalid")
	}
	if err := saveAccepted(directory, accepted); err != nil {
		return err
	}
	return clearJournal(directory)
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
		if currentSlotState.Release == target.Release && currentSlotState.Sequence == target.Sequence {
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
	body, err := os.ReadFile(filepath.Join(directory, journalFile)) // #nosec G304 -- journal is a fixed child of the bootstrap directory.
	if os.IsNotExist(err) {
		return journal{}, nil
	}
	if err != nil {
		return journal{}, err
	}
	var record journal
	if err := json.Unmarshal(body, &record); err != nil {
		return journal{}, errors.New("bootstrap journal is invalid")
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
	var accepted acceptedState
	if err := json.Unmarshal(body, &accepted); err != nil || accepted.Schema != 1 {
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
	return State{
		Current:          current.Release,
		CurrentSequence:  current.Sequence,
		Previous:         previous.Release,
		PreviousSequence: previous.Sequence,
		CatalogSequence:  accepted.CatalogSequence,
	}, nil
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
	body, err := os.ReadFile(filepath.Join(directory, slotRecord)) // #nosec G304 -- slot record is a fixed child.
	if err != nil {
		return slotState{}, err
	}
	var slot slotState
	if err := json.Unmarshal(body, &slot); err != nil {
		return slotState{}, err
	}
	return slot, nil
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
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}
