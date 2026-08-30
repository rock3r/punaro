package operator

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcceptServerCatalogSequenceIsMonotonicAndIdempotent(t *testing.T) {
	directory := catalogFixtureDirectory(t)
	if err := AcceptServerCatalogSequence(directory, 2, 1); err != nil {
		t.Fatal(err)
	}
	if err := AcceptServerCatalogSequence(directory, 2, 1); err != nil {
		t.Fatalf("exact accepted sequence was not idempotent: %v", err)
	}
	if err := AcceptServerCatalogSequence(directory, 1, 1); !errors.Is(err, ErrCatalogSequenceDowngrade) {
		t.Fatalf("downgrade error=%v", err)
	}
	if err := AcceptServerCatalogSequence(directory, 2, 3); !errors.Is(err, ErrCatalogSequenceDowngrade) {
		t.Fatalf("embedded-floor error=%v", err)
	}
}

func TestBeginServerCatalogAcceptanceHoldsLockUntilCallerReleases(t *testing.T) {
	directory := catalogFixtureDirectory(t)
	unlock, err := BeginServerCatalogAcceptance(directory, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if competingUnlock, err := BeginServerCatalogAcceptance(directory, 3, 1); err == nil {
		competingUnlock()
		t.Fatal("concurrent catalog acceptance acquired the transaction-start lock")
	}
	unlock()
	competingUnlock, err := BeginServerCatalogAcceptance(directory, 3, 1)
	if err != nil {
		t.Fatalf("catalog acceptance remained locked after release: %v", err)
	}
	competingUnlock()
}

func TestAcceptServerCatalogSequenceRecoversSyncedPendingHighWater(t *testing.T) {
	directory := catalogFixtureDirectory(t)
	acceptedCatalogPublicationHook = func(step string) error {
		if step == "pending" {
			return errors.New("crash")
		}
		return nil
	}
	t.Cleanup(func() { acceptedCatalogPublicationHook = nil })
	if err := AcceptServerCatalogSequence(directory, 4, 0); err == nil {
		t.Fatal("injected acceptance interruption was ignored")
	}
	acceptedCatalogPublicationHook = nil
	sequence, err := ServerCatalogSequence(directory)
	if err != nil || sequence != 4 {
		t.Fatalf("effective pending high-water sequence=%d err=%v", sequence, err)
	}
	if err := AcceptServerCatalogSequence(directory, 3, 0); !errors.Is(err, ErrCatalogSequenceDowngrade) {
		t.Fatalf("synced pending high-water was not recovered: %v", err)
	}
	state, exists, err := readAcceptedCatalogState(filepath.Join(directory, acceptedCatalogName))
	if err != nil || !exists || state.Sequence != 4 {
		t.Fatalf("accepted state=%#v exists=%v err=%v", state, exists, err)
	}
}

func TestCatalogAcceptanceRequirementRejectsLostHighWater(t *testing.T) {
	directory := catalogFixtureDirectory(t)
	if err := AcceptServerCatalogSequence(directory, 4, 1); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(directory, acceptedCatalogName)); err != nil {
		t.Fatal(err)
	}
	if _, err := BeginServerCatalogAcceptance(directory, 3, 1); !errors.Is(err, ErrCatalogAcceptanceMissing) {
		t.Fatalf("lost high-water update error=%v", err)
	}
	if _, unlock, err := BeginServerCatalogSnapshot(directory); !errors.Is(err, ErrCatalogAcceptanceMissing) || unlock != nil {
		if unlock != nil {
			unlock()
		}
		t.Fatalf("lost high-water snapshot unlock=%v error=%v", unlock != nil, err)
	}
}

func TestCatalogAcceptanceSnapshotMigratesExistingHighWaterRequirement(t *testing.T) {
	directory := catalogFixtureDirectory(t)
	if err := writeExclusiveJSON(filepath.Join(directory, acceptedCatalogName), acceptedCatalogState{Version: 1, Sequence: 4}); err != nil {
		t.Fatal(err)
	}
	sequence, unlock, err := BeginServerCatalogSnapshot(directory)
	if err != nil || sequence != 4 {
		if unlock != nil {
			unlock()
		}
		t.Fatalf("snapshot sequence=%d err=%v", sequence, err)
	}
	unlock()
	if required, err := readCatalogAcceptanceRequirement(directory); err != nil || !required {
		t.Fatalf("migrated requirement=%t err=%v", required, err)
	}
}

func TestServerCatalogSequenceReturnsZeroForPristineInstallation(t *testing.T) {
	directory := catalogFixtureDirectory(t)
	sequence, err := ServerCatalogSequence(directory)
	if err != nil || sequence != 0 {
		t.Fatalf("pristine sequence=%d err=%v", sequence, err)
	}
}

func TestBeginServerCatalogSnapshotHoldsLockUntilBackupPublication(t *testing.T) {
	directory := catalogFixtureDirectory(t)
	if err := AcceptServerCatalogSequence(directory, 2, 1); err != nil {
		t.Fatal(err)
	}
	sequence, releaseSnapshot, err := BeginServerCatalogSnapshot(directory)
	if err != nil || sequence != 2 {
		t.Fatalf("snapshot sequence=%d err=%v", sequence, err)
	}
	if competingUnlock, err := BeginServerCatalogAcceptance(directory, 3, 1); err == nil {
		competingUnlock()
		t.Fatal("catalog acceptance advanced before backup publication released its snapshot")
	}
	releaseSnapshot()
	competingUnlock, err := BeginServerCatalogAcceptance(directory, 3, 1)
	if err != nil {
		t.Fatalf("catalog acceptance remained locked after backup publication: %v", err)
	}
	competingUnlock()
}

func TestInspectServerCatalogAcceptance(t *testing.T) {
	directory := catalogFixtureDirectory(t)
	if err := InspectServerCatalogAcceptance(directory, 3); err == nil {
		t.Fatal("missing catalog acceptance passed inspection")
	}
	if err := AcceptServerCatalogSequence(directory, 4, 3); err != nil {
		t.Fatal(err)
	}
	if err := InspectServerCatalogAcceptance(directory, 4); err != nil {
		t.Fatalf("accepted inspection: %v", err)
	}
	if err := InspectServerCatalogAcceptance(directory, 5); !errors.Is(err, ErrCatalogSequenceDowngrade) {
		t.Fatalf("embedded downgrade error=%v", err)
	}
	requirement := filepath.Join(directory, acceptedCatalogRequiredName)
	if err := os.Remove(requirement); err != nil {
		t.Fatal(err)
	}
	if err := InspectServerCatalogAcceptance(directory, 4); !errors.Is(err, ErrCatalogAcceptanceMissing) {
		t.Fatalf("missing requirement error=%v", err)
	}
	if _, err := os.Lstat(requirement); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspection repaired missing requirement: %v", err)
	}
	if err := AcceptServerCatalogSequence(directory, 4, 3); err != nil {
		t.Fatalf("restore requirement: %v", err)
	}
	if err := os.Remove(requirement); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(requirement, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := InspectServerCatalogAcceptance(directory, 4); err == nil {
		t.Fatal("invalid catalog acceptance requirement passed inspection")
	}
}

func catalogFixtureDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- private operator-state fixture root.
		t.Fatal(err)
	}
	if err := protectNewOperatorDirectory(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}
