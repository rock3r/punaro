package v3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"fmt"
	"testing"
	"time"
)

func TestPermitLedgerIsAtomicAndReturnsExactReplayResult(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	source := verifiedTestSource(t, now, 1, 4, 4)
	if err := store.initialize(context.Background(), source, now); err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit := permitForManifest(source.manifest, source.raw, now)
	permit.Operation, permit.MaxOperations, permit.MaxBytes, permit.MaxChunks = permitOperationSourceUpload, 2, 64, 2
	if err := SignPermit(&permit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	authority := permitAuthorityStub{key: issuerPublic}
	if err := store.issuePermit(context.Background(), permit, authority, now); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/v3/attachments/%x/source/chunks/0", permit.TransferID)
	route, request, err := NewAttachmentOperationRequest("PUT", path, []byte("ciphertext"), nil)
	if err != nil {
		t.Fatal(err)
	}
	op := testOperation(permit, request, now)
	if err := SignOperation(&op, holderPrivate); err != nil {
		t.Fatal(err)
	}
	holders := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: holderPublic}
	calls := 0
	mutation := func(_ context.Context, tx *sql.Tx) ([]byte, error) {
		calls++
		if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS v3_test_mutation(value INTEGER NOT NULL)`); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO v3_test_mutation(value) VALUES (1)`); err != nil {
			return nil, err
		}
		return []byte("result"), nil
	}
	result, replayed, err := store.redeemPermitOperation(context.Background(), permit, op, route, request, authority, holders, now, mutation)
	if err != nil || replayed || string(result) != "result" || calls != 1 {
		t.Fatalf("result=%q replayed=%v calls=%d err=%v", result, replayed, calls, err)
	}
	result, replayed, err = store.redeemPermitOperation(context.Background(), permit, op, route, request, authority, holders, now, mutation)
	if err != nil || !replayed || string(result) != "result" || calls != 1 {
		t.Fatalf("result=%q replayed=%v calls=%d err=%v", result, replayed, calls, err)
	}
	if err := store.cancel(context.Background(), permit.TransferID, now); err != nil {
		t.Fatal(err)
	}
	result, replayed, err = store.redeemPermitOperation(context.Background(), permit, op, route, request, authority, holders, now, mutation)
	if err != nil || !replayed || string(result) != "result" || calls != 1 {
		t.Fatalf("terminal replay result=%q replayed=%v calls=%d err=%v", result, replayed, calls, err)
	}
}
