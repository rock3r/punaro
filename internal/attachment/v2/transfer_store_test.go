package v2

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteTransferStoreRedeemsOfferAtomicallyAndSurvivesRestart(t *testing.T) {
	t.Parallel()
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	permit := samplePermit()
	permit.Operation = PermitOperationOffer
	permit.IssuedAt, permit.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(30*time.Second))
	if err := SignPermit(&permit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	request, err := NewOperationRecordRequest(3, "/v2/transfers/transfer/offer", []byte("transfer"), []byte("offer"))
	if err != nil {
		t.Fatal(err)
	}
	operation := sampleOperation(permit, request)
	operation.IssuedAt, operation.ExpiresAt = permit.IssuedAt, permit.ExpiresAt
	if err := SignOperation(&operation, holderPrivate); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "ledger.db")
	ledger, err := OpenSQLitePermitLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	issuers := permitAuthorityStub{keyID: permit.IssuerKeyID, key: issuerPublic}
	holders := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: holderPublic}
	if err := ledger.Issue(permit, issuers, clock); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSQLiteTransferStore(ledger)
	if err != nil {
		t.Fatal(err)
	}
	sourceReady := NewTransferRecord(permit.TransferID, bytes32(91), permit.ExpiresAt)
	sourceReady, err = sourceReady.Transition(TransferActionSourceReady, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSourceReady(context.Background(), sourceReady); err != nil {
		t.Fatal(err)
	}
	route := AttachmentRoute{TransferID: permit.TransferID, Operation: PermitOperationOffer, Action: TransferActionOffer}
	result, replayed, err := store.RedeemTransition(context.Background(), permit, operation, request, route, issuers, holders, clock)
	if err != nil || replayed || result.Status != TransferOffered || result.AttemptGeneration != 1 {
		t.Fatalf("result=%+v replayed=%v err=%v", result, replayed, err)
	}
	result, replayed, err = store.RedeemTransition(context.Background(), permit, operation, request, route, issuers, holders, clock)
	if err != nil || !replayed || result.Status != TransferOffered {
		t.Fatalf("retry result=%+v replayed=%v err=%v", result, replayed, err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err = OpenSQLitePermitLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	store, err = OpenSQLiteTransferStore(ledger)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.Load(permit.TransferID)
	if err != nil || !found || loaded.Status != TransferOffered || loaded.AttemptGeneration != 1 {
		t.Fatalf("loaded=%+v found=%v err=%v", loaded, found, err)
	}
}

func TestSQLiteTransferStoreRejectsTransitionWithWrongPermitOperation(t *testing.T) {
	t.Parallel()
	store := &SQLiteTransferStore{}
	if _, _, err := store.RedeemTransition(context.Background(), Permit{Operation: PermitOperationAccept}, OperationRecord{}, OperationRequest{}, AttachmentRoute{Operation: PermitOperationOffer, Action: TransferActionOffer}, nil, nil, time.Now()); err == nil {
		t.Fatal("offer accepted an accept permit")
	}
}

func TestSQLiteTransferStoreRejectsRouteForAnotherTransfer(t *testing.T) {
	t.Parallel()
	store := &SQLiteTransferStore{}
	permit := samplePermit()
	permit.Operation = PermitOperationOffer
	route := AttachmentRoute{TransferID: bytes16(99), Operation: PermitOperationOffer, Action: TransferActionOffer}
	if _, _, err := store.RedeemTransition(context.Background(), permit, OperationRecord{}, OperationRequest{}, route, nil, nil, time.Now()); err == nil {
		t.Fatal("permit was accepted on another transfer route")
	}
}
