package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverJournalDiscardsStagingCandidate(t *testing.T) {
	dir := privateDir(t)
	candidate := filepath.Join(dir, candidateSlot)
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "punaro-adapter-linux-amd64"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(dir, journal{Schema: 1, Phase: "staging", Release: "v0.2.0", Sequence: 2}); err != nil {
		t.Fatal(err)
	}
	if err := recoverJournal(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(candidate); !os.IsNotExist(err) {
		t.Fatalf("staging candidate retained: %v", err)
	}
}

func TestRecoverJournalCompletesPublishAfterCurrentMoved(t *testing.T) {
	dir := privateDir(t)
	if err := saveAccepted(dir, acceptedState{Schema: 1, Release: "v0.1.0", ReleaseSequence: 1, CatalogSequence: 1, ManifestSHA256: repeatC()}); err != nil {
		t.Fatal(err)
	}
	previous := filepath.Join(dir, previousSlot)
	if err := os.Mkdir(previous, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(previous, "old-current"), []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(previous, slotRecord), []byte(`{"schema":1,"release":"v0.1.0","sequence":1,"manifest_sha256":"`+repeatC()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(dir, candidateSlot)
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "new-current"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(dir, journal{Schema: 1, Phase: "publishing", Release: "v0.2.0", Sequence: 2, CatalogSequence: 2, ManifestSHA256: repeatC()}); err != nil {
		t.Fatal(err)
	}
	if err := recoverJournal(dir); err != nil {
		t.Fatal(err)
	}
	kept, err := os.ReadFile(filepath.Join(dir, previousSlot, "old-current")) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != "keep-me" {
		t.Fatalf("previous slot was discarded during publish recovery: %q", kept)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || status.Previous != "v0.1.0" || status.CatalogSequence != 2 {
		t.Fatalf("status=%#v", status)
	}
	accepted, err := loadAccepted(dir)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.ReleaseSequence != 2 || accepted.CatalogSequence != 2 {
		t.Fatalf("accepted=%#v", accepted)
	}
}

func TestRecoverJournalPersistsAcceptedAfterPublishWithoutCandidate(t *testing.T) {
	dir := privateDir(t)
	current := filepath.Join(dir, currentSlot)
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(current, slotRecord), []byte(`{"schema":1,"release":"v0.2.0","sequence":2,"manifest_sha256":"`+repeatC()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveAccepted(dir, acceptedState{Schema: 1, Release: "v0.1.0", ReleaseSequence: 1, CatalogSequence: 1, ManifestSHA256: repeatC()}); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(dir, journal{Schema: 1, Phase: "publishing", Release: "v0.2.0", Sequence: 2, CatalogSequence: 2, ManifestSHA256: repeatC()}); err != nil {
		t.Fatal(err)
	}
	if err := recoverJournal(dir); err != nil {
		t.Fatal(err)
	}
	accepted, err := loadAccepted(dir)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Release != "v0.2.0" || accepted.ReleaseSequence != 2 || accepted.CatalogSequence != 2 {
		t.Fatalf("accepted=%#v", accepted)
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFile)); !os.IsNotExist(err) {
		t.Fatal("publishing journal retained after accepted recovery")
	}
}

func TestRecoverJournalClearsRecoveryAfterCompletedSeed(t *testing.T) {
	dir := privateDir(t)
	current := filepath.Join(dir, currentSlot)
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(current, slotRecord), []byte(`{"schema":1,"release":"`+localCheckoutRelease+`","sequence":1,"manifest_sha256":"`+repeatC()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRecoveryRecord(dir, recoveryUnhealthy); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(dir, journal{Schema: 1, Phase: "seeding", Release: localCheckoutRelease, Sequence: 1, ManifestSHA256: repeatC()}); err != nil {
		t.Fatal(err)
	}
	if err := recoverJournal(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, recoveryFile)); !os.IsNotExist(err) {
		t.Fatal("recovery marker retained after completed seed recovery")
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFile)); !os.IsNotExist(err) {
		t.Fatal("seeding journal retained after completed seed recovery")
	}
}

func TestRecoverJournalCompletesInterruptedRollback(t *testing.T) {
	dir := privateDir(t)
	previous := filepath.Join(dir, previousSlot)
	swap := filepath.Join(dir, swapSlot)
	if err := os.Mkdir(previous, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(swap, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(previous, slotRecord), []byte(`{"schema":1,"release":"v0.1.0","sequence":1,"manifest_sha256":"`+repeatC()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(swap, slotRecord), []byte(`{"schema":1,"release":"v0.2.0","sequence":2,"manifest_sha256":"`+repeatC()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(dir, journal{Schema: 1, Phase: "rolling-back", Release: "v0.1.0", Sequence: 1, ManifestSHA256: repeatC()}); err != nil {
		t.Fatal(err)
	}
	if err := recoverJournal(dir); err != nil {
		t.Fatal(err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.Previous != "v0.2.0" {
		t.Fatalf("status=%#v", status)
	}
}

func TestRecoverJournalAppliesRollbackCatalogSequence(t *testing.T) {
	dir := privateDir(t)
	previous := filepath.Join(dir, previousSlot)
	swap := filepath.Join(dir, swapSlot)
	if err := os.Mkdir(previous, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(swap, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(previous, slotRecord), []byte(`{"schema":1,"release":"v0.1.0","sequence":1,"manifest_sha256":"`+repeatC()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(swap, slotRecord), []byte(`{"schema":1,"release":"v0.2.0","sequence":2,"manifest_sha256":"`+repeatC()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveAccepted(dir, acceptedState{
		Schema:          1,
		Release:         "v0.2.0",
		ReleaseSequence: 2,
		CatalogSequence: 1,
		ManifestSHA256:  repeatC(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(dir, journal{Schema: 1, Phase: "rolling-back", Release: "v0.1.0", Sequence: 1, CatalogSequence: 3, ManifestSHA256: repeatC()}); err != nil {
		t.Fatal(err)
	}
	if err := recoverJournal(dir); err != nil {
		t.Fatal(err)
	}
	accepted, err := loadAccepted(dir)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.CatalogSequence != 3 || accepted.Release != "v0.2.0" {
		t.Fatalf("accepted=%#v", accepted)
	}
	away, err := loadAutoRollback(dir)
	if err != nil {
		t.Fatal(err)
	}
	if away.Release != "v0.2.0" || away.Sequence != 2 {
		t.Fatalf("auto-rollback=%#v", away)
	}
}

func TestRecoverJournalDoesNotReswapCompletedRollback(t *testing.T) {
	dir := privateDir(t)
	current := filepath.Join(dir, currentSlot)
	previous := filepath.Join(dir, previousSlot)
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(previous, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(current, slotRecord), []byte(`{"schema":1,"release":"v0.1.0","sequence":1,"manifest_sha256":"`+repeatC()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(previous, slotRecord), []byte(`{"schema":1,"release":"v0.2.0","sequence":2,"manifest_sha256":"`+repeatC()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(dir, journal{Schema: 1, Phase: "rolling-back", Release: "v0.1.0", Sequence: 1, ManifestSHA256: repeatC()}); err != nil {
		t.Fatal(err)
	}
	if err := recoverJournal(dir); err != nil {
		t.Fatal(err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.Previous != "v0.2.0" {
		t.Fatalf("status=%#v", status)
	}
}

func TestParseSlotRejectsEmptyRecord(t *testing.T) {
	if _, err := parseSlot([]byte(`{}`)); err == nil {
		t.Fatal("empty slot record accepted")
	}
}

func TestRecoverJournalRemovesAbandonedTempFiles(t *testing.T) {
	dir := privateDir(t)
	if err := os.WriteFile(filepath.Join(dir, "journal.json.tmp"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".accepted.json-old.tmp"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recoverJournal(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "journal.json.tmp")); !os.IsNotExist(err) {
		t.Fatal("fixed temporary journal retained")
	}
	if _, err := os.Lstat(filepath.Join(dir, ".accepted.json-old.tmp")); !os.IsNotExist(err) {
		t.Fatal("unique temporary file retained")
	}
}

func TestReplaceCurrentQuarantinesCorruptPrevious(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	previous := filepath.Join(dir, previousSlot)
	if err := os.Mkdir(previous, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(previous, slotRecord), []byte(`{"schema":1`), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(dir, candidateSlot)
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "punaro-adapter"), []byte("repaired"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceCurrent(dir, "v0.2.0", 2, payloadDigest("current-adapter")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(previous); !os.IsNotExist(err) {
		t.Fatal("corrupt previous retained after same-identity repair")
	}
	if _, err := readOptionalSlot(previous); err != nil {
		t.Fatal(err)
	}
}

func TestNextSlotGenerationIgnoresCorruptPrevious(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeSlotRecordGeneration(t, filepath.Join(dir, currentSlot), "v0.2.0", 2, payloadDigest("current-adapter"), 2)
	previous := filepath.Join(dir, previousSlot)
	if err := os.Mkdir(previous, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(previous, slotRecord), []byte(`{"schema":1`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := nextSlotGeneration(dir)
	if err != nil || got != 3 {
		t.Fatalf("next generation=%d err=%v", got, err)
	}
}

func TestNextSlotGenerationUsesPreviousAndAutoRollback(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "previous-adapter")
	writeSlotRecordGeneration(t, filepath.Join(dir, currentSlot), "v0.1.0", 1, payloadDigest("previous-adapter"), 1)
	writeAdapterSlot(t, dir, previousSlot, "v0.2.0", 2, "current-adapter")
	writeSlotRecordGeneration(t, filepath.Join(dir, previousSlot), "v0.2.0", 2, payloadDigest("current-adapter"), 2)
	if err := saveAutoRollback(dir, slotState{Release: "v0.2.0", Sequence: 2, ManifestSHA256: payloadDigest("current-adapter"), Generation: 2}); err != nil {
		t.Fatal(err)
	}
	got, err := nextSlotGeneration(dir)
	if err != nil || got != 3 {
		t.Fatalf("next generation=%d err=%v", got, err)
	}
}

func TestNextSlotGenerationPersistsAfterCurrentRemoved(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeSlotRecordGeneration(t, filepath.Join(dir, currentSlot), "v0.2.0", 2, payloadDigest("current-adapter"), 2)
	got, err := nextSlotGeneration(dir)
	if err != nil || got != 3 {
		t.Fatalf("first next generation=%d err=%v", got, err)
	}
	if err := os.RemoveAll(filepath.Join(dir, currentSlot)); err != nil {
		t.Fatal(err)
	}
	got, err = nextSlotGeneration(dir)
	if err != nil || got != 4 {
		t.Fatalf("persisted next generation=%d err=%v", got, err)
	}
}

func TestNextSlotGenerationUsesCandidate(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, candidateSlot, "v0.2.0", 2, "candidate-adapter")
	writeSlotRecordGeneration(t, filepath.Join(dir, candidateSlot), "v0.2.0", 2, payloadDigest("candidate-adapter"), 2)
	got, err := nextSlotGeneration(dir)
	if err != nil || got != 3 {
		t.Fatalf("next generation=%d err=%v", got, err)
	}
}

func TestNextSlotGenerationUsesHealthyGeneration(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeSlotRecordGeneration(t, filepath.Join(dir, previousSlot), "v0.1.0", 1, payloadDigest("previous-adapter"), 1)
	if err := rememberHealthyGeneration(dir, slotState{Release: "v0.2.0", Sequence: 2, ManifestSHA256: payloadDigest("current-adapter"), Generation: 4}); err != nil {
		t.Fatal(err)
	}
	got, err := nextSlotGeneration(dir)
	if err != nil || got != 5 {
		t.Fatalf("next generation=%d err=%v", got, err)
	}
}

func TestNextSlotGenerationReplacesGenerationDirectoryNode(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeSlotRecordGeneration(t, filepath.Join(dir, currentSlot), "v0.2.0", 2, payloadDigest("current-adapter"), 2)
	writeNonFileMarker(t, filepath.Join(dir, generationHighWaterFile))
	got, err := nextSlotGeneration(dir)
	if err != nil || got != 3 {
		t.Fatalf("next generation=%d err=%v", got, err)
	}
	info, err := os.Lstat(filepath.Join(dir, generationHighWaterFile))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("generation high-water still not a file: info=%v err=%v", info, err)
	}
	record, err := loadGenerationHighWater(dir)
	if err != nil || record.Generation != 3 {
		t.Fatalf("persisted generation=%+v err=%v", record, err)
	}
}

func TestRememberHealthyGenerationReplacesDirectoryNode(t *testing.T) {
	dir := privateDir(t)
	writeNonFileMarker(t, filepath.Join(dir, healthyGenerationFile))
	identity := slotState{Release: "v0.2.0", Sequence: 2, ManifestSHA256: payloadDigest("current-adapter"), Generation: 2}
	if err := rememberHealthyGeneration(dir, identity); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(dir, healthyGenerationFile))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("healthy generation still not a file: info=%v err=%v", info, err)
	}
	if !currentGenerationIsHealthy(dir, identity) {
		t.Fatal("healthy identity was not recorded after replacing the directory node")
	}
}

func TestBlocksAutoRollbackAllowsLaterGeneration(t *testing.T) {
	dir := privateDir(t)
	away := slotState{Release: "v0.2.0", Sequence: 2, ManifestSHA256: repeatC(), Generation: 1}
	if err := saveAutoRollback(dir, away); err != nil {
		t.Fatal(err)
	}
	blocked, err := blocksAutoRollback(dir, away)
	if err != nil || !blocked {
		t.Fatalf("same publication blocked=%v err=%v", blocked, err)
	}
	later := away
	later.Generation = 2
	blocked, err = blocksAutoRollback(dir, later)
	if err != nil || blocked {
		t.Fatalf("later publication blocked=%v err=%v", blocked, err)
	}
}

func repeatC() string {
	return "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
}
