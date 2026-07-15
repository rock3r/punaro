package v3

import (
	"testing"
	"time"
)

func TestTransferLifecycleFencesRecipientVisibilityUntilSourceReady(t *testing.T) {
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	record := newTransferRecord(testID(1), testHash(2), now.Add(30*time.Second).Unix())
	if _, err := record.transition(transferActionOffer, now, transitionProof{}); err == nil {
		t.Fatal("offer before source staging accepted")
	}
	for _, action := range []transferAction{transferActionSourceInit, transferActionSourceReady, transferActionOffer, transferActionAccept, transferActionBegin, transferActionComplete} {
		var err error
		proof := transitionProof{sourceComplete: true, receiptComplete: true}
		if action == transferActionComplete {
			proof.expectedAttemptGeneration = 1
		}
		record, err = record.transition(action, now, proof)
		if err != nil {
			t.Fatalf("action=%d err=%v", action, err)
		}
	}
	if record.Status != transferCompleted || record.AttemptGeneration != 1 {
		t.Fatalf("record=%+v", record)
	}
}

func TestTransferTerminalAndExpiryStatesCannotRevive(t *testing.T) {
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	record := newTransferRecord(testID(1), testHash(2), now.Add(time.Second).Unix())
	var err error
	record, err = record.transition(transferActionCancel, now, transitionProof{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.transition(transferActionSourceInit, now, transitionProof{}); err == nil {
		t.Fatal("cancelled source revived")
	}
	expiring := newTransferRecord(testID(3), testHash(4), now.Add(time.Second).Unix())
	expired, err := expiring.transition(transferActionExpire, now.Add(time.Second), transitionProof{})
	if err != nil || expired.Status != transferExpired {
		t.Fatalf("record=%+v err=%v", expired, err)
	}
}

func TestTransferLifecycleRejectsUnverifiedSourceOrReceiptCompletion(t *testing.T) {
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	record := newTransferRecord(testID(1), testHash(2), now.Add(30*time.Second).Unix())
	var err error
	record, err = record.transition(transferActionSourceInit, now, transitionProof{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.transition(transferActionSourceReady, now, transitionProof{}); err == nil {
		t.Fatal("premature source-ready accepted")
	}
	record, err = record.transition(transferActionSourceReady, now, transitionProof{sourceComplete: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []transferAction{transferActionOffer, transferActionAccept, transferActionBegin} {
		record, err = record.transition(action, now, transitionProof{})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := record.transition(transferActionComplete, now, transitionProof{expectedAttemptGeneration: 1}); err == nil {
		t.Fatal("incomplete receipt accepted")
	}
}

func TestTransferLifecycleFencesCompletionToBegunAttempt(t *testing.T) {
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	record := newTransferRecord(testID(1), testHash(2), now.Add(30*time.Second).Unix())
	var err error
	for _, action := range []transferAction{transferActionSourceInit, transferActionSourceReady, transferActionOffer, transferActionAccept, transferActionBegin} {
		record, err = record.transition(action, now, transitionProof{sourceComplete: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := record.transition(transferActionComplete, now, transitionProof{receiptComplete: true, expectedAttemptGeneration: 0}); err == nil {
		t.Fatal("stale completion generation accepted")
	}
	if _, err := record.transition(transferActionComplete, now, transitionProof{receiptComplete: true, expectedAttemptGeneration: 1}); err != nil {
		t.Fatal(err)
	}
}
