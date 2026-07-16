package v3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestOutcomeRouteIsStrictGETAndCarriesNoPayload(t *testing.T) {
	path := "/v3/attachments/01000000000000000000000000000000/outcome"
	route, request, err := NewAttachmentOperationRequest(http.MethodGet, path, nil, nil)
	if err != nil || route.Operation != PermitOperationOutcome || route.AttemptGeneration != 0 {
		t.Fatalf("route=%+v err=%v", route, err)
	}
	if _, _, err := NewAttachmentOperationRequest(http.MethodGet, path, []byte("body"), nil); err == nil {
		t.Fatal("outcome accepted a request body")
	}
	if _, _, err := NewAttachmentOperationRequest(http.MethodPost, path, nil, nil); err == nil {
		t.Fatal("outcome accepted the wrong method")
	}
	if request.method == 0 {
		t.Fatal("outcome did not construct an operation request")
	}
}

func TestOutcomeRedemptionIsFreshAuthorizedAndExactReplay(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 16, 0, 0, 0, 0, time.UTC)
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
	permit.Operation = permitOperationOutcome
	if err := SignPermit(&permit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	authority := permitAuthorityStub{key: issuerPublic}
	if err := store.issuePermit(context.Background(), permit, authority, now); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/v3/attachments/%x/outcome", source.TransferID())
	route, request, err := NewAttachmentOperationRequest(http.MethodGet, path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	op := testOperation(permit, request, now)
	if err := SignOperation(&op, holderPrivate); err != nil {
		t.Fatal(err)
	}
	holders := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: holderPublic}
	raw, replayed, err := store.redeemOutcome(context.Background(), permit, op, route, request, authority, holders, now)
	if err != nil || replayed {
		t.Fatalf("replayed=%t err=%v", replayed, err)
	}
	result, err := DecodeTransferResult(raw)
	if err != nil || result.State != TransferStateSourceUploading || result.TransferID != source.TransferID() {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	raw, replayed, err = store.redeemOutcome(context.Background(), permit, op, route, request, authority, holders, now)
	if err != nil || !replayed {
		t.Fatalf("outcome replayed=%t err=%v", replayed, err)
	}
	if _, err := DecodeTransferResult(raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.redeemOutcome(context.Background(), permit, op, route, request, authority, holders, now.Add(31*time.Second)); err == nil {
		t.Fatal("expired outcome permit was accepted")
	}
}
