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

func TestOfferAndAcceptAdvanceOneTimeLifecycle(t *testing.T) {
	pathDB := privateDatabase(t)
	limits := defaultSourceLimits()
	limits.Relay.Transfers = 1
	store, err := openSourceStore(pathDB, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	source := verifiedTestSource(t, now, 1, 4, 4)
	if err := store.initialize(context.Background(), source, now); err != nil {
		t.Fatal(err)
	}
	if err := store.upload(context.Background(), source.TransferID(), 0, bytes.Repeat([]byte{1}, 20), now); err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	senderPublic, senderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic, recipientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority := permitAuthorityStub{key: issuerPublic}
	directory := manifestAuthorityStub{public: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)).Public().(ed25519.PublicKey)}
	envelope := testEnvelopeForManifest(source.manifest, source.raw)
	if err := SignEnvelope(&envelope, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))); err != nil {
		t.Fatal(err)
	}
	nonce := testHash(88)
	payload, err := EncodeOfferPayload(source.manifest, envelope, nonce)
	if err != nil {
		t.Fatal(err)
	}
	offerPermit := permitForManifest(source.manifest, source.raw, now)
	offerPermit.Operation = permitOperationOffer
	if err := SignPermit(&offerPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := store.issuePermit(context.Background(), offerPermit, authority, now); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/v3/attachments/%x/offer", offerPermit.TransferID)
	route, request, err := NewAttachmentOperationRequest("POST", path, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	op := testOperation(offerPermit, request, now)
	if err := SignOperation(&op, senderPrivate); err != nil {
		t.Fatal(err)
	}
	holders := operationHolderStub{device: offerPermit.HolderDeviceID, generation: offerPermit.HolderGeneration, key: senderPublic}
	if _, replayed, err := store.redeemOffer(context.Background(), offerPermit, op, route, request, authority, holders, directory, now); err != nil || replayed {
		t.Fatalf("offer replayed=%v err=%v", replayed, err)
	}
	assertTransferStatus(t, store, source.TransferID(), transferOffered)
	acceptPermit := permitForManifest(source.manifest, source.raw, now)
	acceptPermit.Operation, acceptPermit.HolderRole = permitOperationAccept, permitHolderRecipient
	acceptPermit.HolderDeviceID, acceptPermit.HolderGeneration = acceptPermit.RecipientDeviceID, acceptPermit.RecipientGeneration
	acceptPermit.Serial = testID(91)
	if err := SignPermit(&acceptPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := store.issuePermit(context.Background(), acceptPermit, authority, now); err != nil {
		t.Fatal(err)
	}
	path = fmt.Sprintf("/v3/attachments/%x/accept", acceptPermit.TransferID)
	route, request, err = NewAttachmentOperationRequest("POST", path, nonce[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	op = testOperation(acceptPermit, request, now)
	op.OperationID, op.IdempotencyKey = testID(92), testHash(92)
	if err := SignOperation(&op, recipientPrivate); err != nil {
		t.Fatal(err)
	}
	holders = operationHolderStub{device: acceptPermit.HolderDeviceID, generation: acceptPermit.HolderGeneration, key: recipientPublic}
	if _, replayed, err := store.redeemAccept(context.Background(), acceptPermit, op, route, request, authority, holders, directory, now); err != nil || replayed {
		t.Fatalf("accept replayed=%v err=%v", replayed, err)
	}
	assertTransferStatus(t, store, source.TransferID(), transferAccepted)
	beginPermit := acceptPermit
	beginPermit.Operation, beginPermit.AttemptGeneration, beginPermit.Serial = permitOperationBegin, 1, testID(93)
	if err := SignPermit(&beginPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := store.issuePermit(context.Background(), beginPermit, authority, now); err != nil {
		t.Fatal(err)
	}
	path = fmt.Sprintf("/v3/attachments/%x/attempts/1/begin", beginPermit.TransferID)
	route, request, err = NewAttachmentOperationRequest("POST", path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	op = testOperation(beginPermit, request, now)
	op.OperationID, op.IdempotencyKey = testID(94), testHash(94)
	if err := SignOperation(&op, recipientPrivate); err != nil {
		t.Fatal(err)
	}
	if _, replayed, err := store.redeemBegin(context.Background(), beginPermit, op, route, request, authority, holders, now); err != nil || replayed {
		t.Fatalf("begin replayed=%v err=%v", replayed, err)
	}
	assertTransferStatus(t, store, source.TransferID(), transferTransferring)
	downloadPermit := beginPermit
	downloadPermit.Operation, downloadPermit.Serial = permitOperationDownload, testID(95)
	if err := SignPermit(&downloadPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := store.issuePermit(context.Background(), downloadPermit, authority, now); err != nil {
		t.Fatal(err)
	}
	path = fmt.Sprintf("/v3/attachments/%x/chunks/0", downloadPermit.TransferID)
	route, request, err = NewAttachmentOperationRequest("GET", path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	op = testOperation(downloadPermit, request, now)
	op.OperationID, op.IdempotencyKey = testID(96), testHash(96)
	if err := SignOperation(&op, recipientPrivate); err != nil {
		t.Fatal(err)
	}
	downloadRoute, downloadRequest, downloadOperation := route, request, op
	ciphertext, _, replayed, err := store.redeemDownload(context.Background(), downloadPermit, op, route, request, authority, holders, now)
	if err != nil || replayed || !bytes.Equal(ciphertext, bytes.Repeat([]byte{1}, 20)) {
		t.Fatalf("download replayed=%v err=%v", replayed, err)
	}
	// The same signed operation may only replay the immutable bytes selected by
	// the store; callers have no response-byte input to substitute.
	ciphertext, _, replayed, err = store.redeemDownload(context.Background(), downloadPermit, downloadOperation, downloadRoute, downloadRequest, authority, holders, now)
	if err != nil || !replayed || !bytes.Equal(ciphertext, bytes.Repeat([]byte{1}, 20)) {
		t.Fatalf("download retry replayed=%v err=%v", replayed, err)
	}
	// A receiver can crash after the relay commits its receipt fence but before
	// the ciphertext reaches durable local storage. A newly issued, separately
	// signed recipient download is therefore allowed to fetch the same immutable
	// relay-selected bytes; it cannot replace the receipt commitment or access a
	// different chunk.
	recoveryPermit := downloadPermit
	recoveryPermit.Serial = testID(196)
	if err := SignPermit(&recoveryPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := store.issuePermit(context.Background(), recoveryPermit, authority, now); err != nil {
		t.Fatal(err)
	}
	recoveryOperation := testOperation(recoveryPermit, downloadRequest, now)
	recoveryOperation.OperationID, recoveryOperation.IdempotencyKey = testID(197), testHash(197)
	if err := SignOperation(&recoveryOperation, recipientPrivate); err != nil {
		t.Fatal(err)
	}
	ciphertext, _, replayed, err = store.redeemDownload(context.Background(), recoveryPermit, recoveryOperation, downloadRoute, downloadRequest, authority, holders, now)
	if err != nil || replayed || !bytes.Equal(ciphertext, bytes.Repeat([]byte{1}, 20)) {
		t.Fatalf("recovery download replayed=%v err=%v", replayed, err)
	}
	completePermit := beginPermit
	completePermit.Operation, completePermit.Serial = permitOperationComplete, testID(97)
	if err := SignPermit(&completePermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	if err := store.issuePermit(context.Background(), completePermit, authority, now); err != nil {
		t.Fatal(err)
	}
	path = fmt.Sprintf("/v3/attachments/%x/complete", completePermit.TransferID)
	route, request, err = NewAttachmentOperationRequest("POST", path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	op = testOperation(completePermit, request, now)
	op.OperationID, op.IdempotencyKey = testID(98), testHash(98)
	if err := SignOperation(&op, recipientPrivate); err != nil {
		t.Fatal(err)
	}
	if _, replayed, err := store.redeemComplete(context.Background(), completePermit, op, route, request, authority, holders, now); err != nil || replayed {
		t.Fatalf("complete replayed=%v err=%v", replayed, err)
	}
	assertTransferStatus(t, store, source.TransferID(), transferCompleted)
	// A completed source remains quota-accounted only through its short
	// manifest/permit lifetime so the exact signed download can be retried.
	ciphertext, _, replayed, err = store.redeemDownload(context.Background(), downloadPermit, downloadOperation, downloadRoute, downloadRequest, authority, holders, now)
	if err != nil || !replayed || !bytes.Equal(ciphertext, bytes.Repeat([]byte{1}, 20)) {
		t.Fatalf("post-completion download retry replayed=%v err=%v", replayed, err)
	}
	secondManifest := source.manifest
	secondManifest.TransferID, secondManifest.PlaintextCommitment = testID(199), testHash(199)
	second := verifiedSourceForManifest(t, secondManifest, now)
	if err := store.initialize(context.Background(), second, now); err == nil {
		t.Fatal("completed replay retention released relay capacity early")
	}
	if reaped, err := store.reapExpired(context.Background(), now.Add(time.Hour), 1); err != nil || reaped != 1 {
		t.Fatalf("reaped=%d err=%v", reaped, err)
	}
	assertTransferStatus(t, store, source.TransferID(), transferCompleted)
	if err := store.initialize(context.Background(), second, now); err != nil {
		t.Fatalf("completed reaper did not release relay capacity: %v", err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openSourceStore(pathDB, defaultSourceLimits())
	if err != nil {
		t.Fatalf("post-offer restart rejected tracked lifecycle: %v", err)
	}
	t.Cleanup(func() { _ = reopened.close() })
}
