package bootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverJournalDiscardsStagingCandidate(t *testing.T) {
	dir := t.TempDir()
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
	dir := t.TempDir()
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
	if err := writeJournal(dir, journal{Schema: 1, Phase: "publishing", Release: "v0.2.0", Sequence: 2, ManifestSHA256: repeatC()}); err != nil {
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
	if status.Current != "v0.2.0" || status.Previous != "v0.1.0" {
		t.Fatalf("status=%#v", status)
	}
}

func TestRecoverJournalCompletesInterruptedRollback(t *testing.T) {
	dir := t.TempDir()
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
	if err := writeJournal(dir, journal{Schema: 1, Phase: "rolling-back"}); err != nil {
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

func repeatC() string {
	return "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
}
