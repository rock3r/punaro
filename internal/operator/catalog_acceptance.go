package operator

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const (
	acceptedCatalogName         = "accepted-server-catalog.json"
	acceptedCatalogPendingName  = ".accepted-server-catalog.pending.json"
	acceptedCatalogRequiredName = "accepted-server-catalog.required.json"
	acceptedCatalogMaximum      = 1024
	acceptedCatalogRequiredBody = "{\"version\":1}\n"
)

var (
	// ErrCatalogSequenceDowngrade reports an attempted server update authorized
	// by a catalog older than the installation's durable accepted high-water.
	ErrCatalogSequenceDowngrade = errors.New("release catalog sequence downgrade")
	// ErrCatalogAcceptanceMissing reports loss of mandatory anti-rollback
	// state after an installation first adopted catalog-authorized updates.
	ErrCatalogAcceptanceMissing = errors.New("required release catalog acceptance is missing")

	acceptedCatalogPublicationHook func(string) error
)

type acceptedCatalogState struct {
	Version  int   `json:"version"`
	Sequence int64 `json:"sequence"`
}

// ServerCatalogSequence returns the effective accepted high-water while
// holding the same cross-process lock used by update starts. A synced pending
// publication counts as accepted security state and is recovered first.
func ServerCatalogSequence(directory string) (int64, error) {
	sequence, unlock, err := BeginServerCatalogSnapshot(directory)
	if err != nil {
		return 0, err
	}
	unlock()
	return sequence, nil
}

// BeginServerCatalogSnapshot returns the effective accepted high-water and
// retains the update-start lock. Backup callers must hold the returned release
// function until the captured manifest has been published or publication has
// failed, so catalog acceptance and backup publication remain totally ordered.
func BeginServerCatalogSnapshot(directory string) (int64, func(), error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return 0, nil, errors.New("release catalog acceptance is unavailable")
	}
	if err := ensureTrustedCatalogDirectory(directory); err != nil {
		return 0, nil, errors.New("release catalog acceptance is unavailable")
	}
	unpin, err := pinTrustedCatalogDirectory(directory)
	if err != nil {
		return 0, nil, errors.New("release catalog acceptance is unavailable")
	}
	unlockFile, err := acquireCatalogAcceptanceLock(directory)
	if err != nil {
		unpin()
		return 0, nil, err
	}
	unlock := func() {
		unlockFile()
		unpin()
	}
	state, exists, err := recoverAcceptedCatalogState(directory)
	if err != nil {
		unlock()
		return 0, nil, err
	}
	required, err := readCatalogAcceptanceRequirement(directory)
	if err != nil || required && !exists {
		unlock()
		if err != nil {
			return 0, nil, err
		}
		return 0, nil, ErrCatalogAcceptanceMissing
	}
	if !exists {
		return 0, unlock, nil
	}
	if !required {
		if err := publishCatalogAcceptanceRequirement(directory); err != nil {
			unlock()
			return 0, nil, err
		}
	}
	return state.Sequence, unlock, nil
}

// AcceptServerCatalogSequence durably advances the monotonic catalog
// high-water before a new server update transaction may start. A synced
// pending state is recovered first, so a crash cannot make a previously
// accepted retirement disappear.
func AcceptServerCatalogSequence(directory string, sequence, embeddedMinimum int64) error {
	unlock, err := BeginServerCatalogAcceptance(directory, sequence, embeddedMinimum)
	if err != nil {
		return err
	}
	unlock()
	return nil
}

// BeginServerCatalogAcceptance advances the catalog high-water and retains its
// cross-process lock. The caller must hold the returned release function until
// the corresponding update transaction exists durably or the start fails.
func BeginServerCatalogAcceptance(directory string, sequence, embeddedMinimum int64) (func(), error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || sequence < 1 || embeddedMinimum < 0 || sequence < embeddedMinimum {
		return nil, ErrCatalogSequenceDowngrade
	}
	if err := ensureTrustedCatalogDirectory(directory); err != nil {
		return nil, errors.New("release catalog acceptance is unavailable")
	}
	unpin, err := pinTrustedCatalogDirectory(directory)
	if err != nil {
		return nil, errors.New("release catalog acceptance is unavailable")
	}
	unlockFile, err := acquireCatalogAcceptanceLock(directory)
	if err != nil {
		unpin()
		return nil, err
	}
	unlock := func() {
		unlockFile()
		unpin()
	}
	succeeded := false
	defer func() {
		if !succeeded {
			unlock()
		}
	}()

	accepted, exists, err := recoverAcceptedCatalogState(directory)
	if err != nil {
		return nil, err
	}
	required, err := readCatalogAcceptanceRequirement(directory)
	if err != nil {
		return nil, err
	}
	if required && !exists {
		return nil, ErrCatalogAcceptanceMissing
	}
	if exists && sequence < accepted.Sequence {
		return nil, ErrCatalogSequenceDowngrade
	}
	if exists && sequence == accepted.Sequence {
		if !required {
			if err := publishCatalogAcceptanceRequirement(directory); err != nil {
				return nil, err
			}
		}
		succeeded = true
		return unlock, nil
	}

	state := acceptedCatalogState{Version: 1, Sequence: sequence}
	body, err := json.Marshal(state)
	if err != nil {
		return nil, errors.New("release catalog acceptance is unavailable")
	}
	body = append(body, '\n')
	pending := filepath.Join(directory, acceptedCatalogPendingName)
	if err := writeExclusive(pending, body); err != nil || syncDirectory(directory) != nil {
		return nil, errors.New("release catalog acceptance is unavailable")
	}
	if acceptedCatalogPublicationHook != nil {
		if err := acceptedCatalogPublicationHook("pending"); err != nil {
			return nil, errors.New("release catalog acceptance was interrupted")
		}
	}
	if err := os.Rename(pending, filepath.Join(directory, acceptedCatalogName)); err != nil || syncDirectory(directory) != nil {
		return nil, errors.New("release catalog acceptance is unavailable")
	}
	if !required {
		if err := publishCatalogAcceptanceRequirement(directory); err != nil {
			return nil, err
		}
	}
	succeeded = true
	return unlock, nil
}

// InspectServerCatalogAcceptance validates the durable catalog high-water
// without changing or reconciling it. Release-bound initialization and restore
// always publish this state, so absence means the anti-rollback invariant was
// lost rather than that the installation is pristine.
func InspectServerCatalogAcceptance(directory string, embeddedMinimum int64) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || embeddedMinimum < 1 {
		return errors.New("release catalog acceptance is unavailable")
	}
	unpin, err := pinTrustedCatalogDirectory(directory)
	if err != nil {
		return errors.New("release catalog acceptance is unavailable")
	}
	defer unpin()
	accepted, acceptedExists, err := readAcceptedCatalogState(filepath.Join(directory, acceptedCatalogName))
	if err != nil {
		return err
	}
	pending, pendingExists, err := readAcceptedCatalogState(filepath.Join(directory, acceptedCatalogPendingName))
	if err != nil {
		return err
	}
	required, err := readCatalogAcceptanceRequirement(directory)
	if err != nil {
		return err
	}
	if !required {
		return ErrCatalogAcceptanceMissing
	}
	if !acceptedExists && !pendingExists {
		return ErrCatalogAcceptanceMissing
	}
	sequence := accepted.Sequence
	if pendingExists && pending.Sequence > sequence {
		sequence = pending.Sequence
	}
	if sequence < embeddedMinimum {
		return ErrCatalogSequenceDowngrade
	}
	return nil
}

func recoverAcceptedCatalogState(directory string) (acceptedCatalogState, bool, error) {
	acceptedPath := filepath.Join(directory, acceptedCatalogName)
	pendingPath := filepath.Join(directory, acceptedCatalogPendingName)
	accepted, acceptedExists, err := readAcceptedCatalogState(acceptedPath)
	if err != nil {
		return acceptedCatalogState{}, false, err
	}
	pending, pendingExists, err := readAcceptedCatalogState(pendingPath)
	if err != nil {
		return acceptedCatalogState{}, false, err
	}
	if !pendingExists {
		return accepted, acceptedExists, nil
	}
	if acceptedExists && pending.Sequence < accepted.Sequence {
		if err := os.Remove(pendingPath); err != nil || syncDirectory(directory) != nil {
			return acceptedCatalogState{}, false, errors.New("release catalog acceptance recovery is unavailable")
		}
		return accepted, true, nil
	}
	if err := os.Rename(pendingPath, acceptedPath); err != nil || syncDirectory(directory) != nil {
		return acceptedCatalogState{}, false, errors.New("release catalog acceptance recovery is unavailable")
	}
	return pending, true, nil
}

func readAcceptedCatalogState(path string) (acceptedCatalogState, bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return acceptedCatalogState{}, false, nil
	} else if err != nil || requireTrustedCatalogFile(path, acceptedCatalogMaximum) != nil {
		return acceptedCatalogState{}, false, errors.New("release catalog acceptance is unavailable")
	}
	body, err := os.ReadFile(path) // #nosec G304 -- fixed state path beneath a validated installation directory.
	if err != nil || len(body) == 0 || len(body) > acceptedCatalogMaximum {
		return acceptedCatalogState{}, false, errors.New("release catalog acceptance is unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var state acceptedCatalogState
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || state.Version != 1 || state.Sequence < 1 {
		return acceptedCatalogState{}, false, errors.New("release catalog acceptance is invalid")
	}
	return state, true, nil
}

func readCatalogAcceptanceRequirement(directory string) (bool, error) {
	path := filepath.Join(directory, acceptedCatalogRequiredName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil || requireTrustedCatalogFile(path, acceptedCatalogMaximum) != nil {
		return false, errors.New("release catalog acceptance requirement is unavailable")
	}
	body, err := os.ReadFile(path) // #nosec G304 -- fixed state path beneath a validated installation directory.
	if err != nil || string(body) != acceptedCatalogRequiredBody {
		return false, errors.New("release catalog acceptance requirement is invalid")
	}
	return true, nil
}

func publishCatalogAcceptanceRequirement(directory string) error {
	if exists, err := readCatalogAcceptanceRequirement(directory); err != nil {
		return err
	} else if exists {
		return nil
	}
	if err := writeExclusive(filepath.Join(directory, acceptedCatalogRequiredName), []byte(acceptedCatalogRequiredBody)); err != nil || syncDirectory(directory) != nil {
		return errors.New("release catalog acceptance requirement could not be published")
	}
	return nil
}
