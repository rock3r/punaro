package v2

import (
	"testing"
	"time"
)

func TestTransferLifecycleAllowsOnlyTheSuccessfulPathAndOneAttempt(t *testing.T) {
	t.Parallel()
	clock := time.Now().UTC().Truncate(time.Second)
	record := NewTransferRecord(bytes16(1), bytes32(2), testUnix(t, clock.Add(time.Minute)))
	for _, action := range []TransferAction{TransferActionSourceReady, TransferActionOffer, TransferActionAccept, TransferActionBegin} {
		var err error
		record, err = record.Transition(action, clock)
		if err != nil {
			t.Fatalf("action %d: %v", action, err)
		}
	}
	if record.Status != TransferTransferring || record.AttemptGeneration != 1 {
		t.Fatalf("record=%+v", record)
	}
	if _, err := record.Transition(TransferActionBegin, clock); err == nil {
		t.Fatal("second concurrent transfer attempt was accepted")
	}
	record, err := record.Transition(TransferActionComplete, clock)
	if err != nil || record.Status != TransferCompleted {
		t.Fatalf("complete record=%+v err=%v", record, err)
	}
	if _, err := record.Transition(TransferActionOffer, clock); err == nil {
		t.Fatal("completed transfer was revived")
	}
}

func TestTransferLifecycleRejectsOutOfOrderAndExpiresFailClosed(t *testing.T) {
	t.Parallel()
	clock := time.Now().UTC().Truncate(time.Second)
	record := NewTransferRecord(bytes16(1), bytes32(2), testUnix(t, clock.Add(time.Second)))
	if _, err := record.Transition(TransferActionAccept, clock); err == nil {
		t.Fatal("accept before an offer was accepted")
	}
	record, err := record.Transition(TransferActionSourceReady, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.Transition(TransferActionOffer, clock.Add(time.Second)); err == nil {
		t.Fatal("expired transfer accepted an offer")
	}
	if record.Status != TransferSourceReady {
		t.Fatal("transition modified the caller record on expiry")
	}
	expired, err := record.Transition(TransferActionExpire, clock.Add(time.Second))
	if err != nil || expired.Status != TransferExpired {
		t.Fatalf("expired=%+v err=%v", expired, err)
	}
}

func TestTransferLifecycleRevocationAndCancellationAreTerminal(t *testing.T) {
	t.Parallel()
	clock := time.Now().UTC().Truncate(time.Second)
	for _, action := range []TransferAction{TransferActionCancel, TransferActionRevoke} {
		record := NewTransferRecord(bytes16(1), bytes32(2), testUnix(t, clock.Add(time.Minute)))
		var err error
		record, err = record.Transition(action, clock)
		if err != nil || !record.Status.Terminal() {
			t.Fatalf("action=%d record=%+v err=%v", action, record, err)
		}
		if _, err := record.Transition(TransferActionSourceReady, clock); err == nil {
			t.Fatalf("terminal %d transfer was revived", action)
		}
	}
}
