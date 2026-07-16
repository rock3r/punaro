package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestRedeemUploadAndCancelHaveOneRetryIdentity(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	source := verifiedTestSource(t, now, 2, 4, 8)
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
	authority := permitAuthorityStub{key: issuerPublic}
	holders := operationHolderStub{device: source.manifest.SenderDeviceID, generation: source.manifest.SenderGeneration, key: holderPublic}
	permit := permitForManifest(source.manifest, source.raw, now)
	permit.Operation, permit.MaxBytes, permit.MaxChunks, permit.MaxOperations = permitOperationSourceUpload, 40, 2, 2
	if err := SignPermit(&permit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := store.issuePermit(context.Background(), permit, authority, now); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/v3/attachments/%x/source/chunks/0", permit.TransferID)
	route, request, err := NewAttachmentOperationRequest("PUT", path, bytes.Repeat([]byte{1}, 20), nil)
	if err != nil {
		t.Fatal(err)
	}
	operation := testOperation(permit, request, now)
	if err := SignOperation(&operation, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, replayed, err := store.redeemUpload(context.Background(), permit, operation, route, request, authority, holders, now); err != nil || replayed {
		t.Fatalf("upload replayed=%v err=%v", replayed, err)
	}
	if _, replayed, err := store.redeemUpload(context.Background(), permit, operation, route, request, authority, holders, now); err != nil || !replayed {
		t.Fatalf("upload replay retry=%v err=%v", replayed, err)
	}
	changed := operation
	changed.OperationID = testID(201)
	changed.IdempotencyKey = testHash(201)
	if err := SignOperation(&changed, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.redeemUpload(context.Background(), permit, changed, route, request, authority, holders, now); err == nil {
		t.Fatal("second retry identity accepted")
	}
	cancel := permit
	cancel.Operation, cancel.Serial = permitOperationCancel, testID(202)
	if err := SignPermit(&cancel, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := store.issuePermit(context.Background(), cancel, authority, now); err != nil {
		t.Fatal(err)
	}
	path = fmt.Sprintf("/v3/attachments/%x/cancel", cancel.TransferID)
	route, request, err = NewAttachmentOperationRequest("POST", path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	operation = testOperation(cancel, request, now)
	if err := SignOperation(&operation, holderPrivate); err != nil {
		t.Fatal(err)
	}
	if _, replayed, err := store.redeemCancel(context.Background(), cancel, operation, route, request, authority, holders, now); err != nil || replayed {
		t.Fatalf("cancel replayed=%v err=%v", replayed, err)
	}
	assertTransferStatus(t, store, source.TransferID(), transferCancelled)
	if _, replayed, err := store.redeemCancel(context.Background(), cancel, operation, route, request, authority, holders, now); err != nil || !replayed {
		t.Fatalf("cancel retry=%v err=%v", replayed, err)
	}
}
