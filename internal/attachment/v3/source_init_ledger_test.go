package v3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestSourceInitRedeemsPermitAndStagesSourceAtomically(t *testing.T) {
	path := privateDatabase(t)
	store, err := openSourceStore(path, defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	manifest := testManifest(now)
	manifestPrivate := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if err := SignManifest(&manifest, manifestPrivate); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
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
	permit := permitForManifest(manifest, raw, now)
	permit.Operation, permit.MaxOperations = permitOperationSourceInit, 1
	if err := SignPermit(&permit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	route, request, err := NewAttachmentOperationRequest("POST", "/v3/attachments/02000000000000000000000000000000/source", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	op := testOperation(permit, request, now)
	if err := SignOperation(&op, holderPrivate); err != nil {
		t.Fatal(err)
	}
	authority := permitAuthorityStub{key: issuerPublic}
	holders := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: holderPublic}
	directory := manifestAuthorityStub{public: manifestPrivate.Public().(ed25519.PublicKey)}
	result, replayed, err := store.redeemSourceInit(context.Background(), directory, permit, op, route, request, authority, holders, now)
	if err != nil || replayed || len(result) == 0 {
		t.Fatalf("result=%x replayed=%v err=%v", result, replayed, err)
	}
	assertTransferStatus(t, store, permit.TransferID, transferSourceUploading)
	result, replayed, err = store.redeemSourceInit(context.Background(), directory, permit, op, route, request, authority, holders, now)
	if err != nil || !replayed || len(result) == 0 {
		t.Fatalf("replay result=%x replayed=%v err=%v", result, replayed, err)
	}
	second := permit
	second.Serial = testID(99)
	if err := SignPermit(&second, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	secondOp := testOperation(second, request, now)
	secondOp.OperationID = testID(98)
	secondOp.IdempotencyKey = testHash(98)
	if err := SignOperation(&secondOp, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.redeemSourceInit(context.Background(), directory, second, secondOp, route, request, authority, holders, now); err == nil {
		t.Fatal("second source-init permit accepted for an existing source")
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openSourceStore(path, defaultSourceLimits()); err != nil {
		t.Fatalf("reopen did not validate complete ledger admission: %v", err)
	}
}
