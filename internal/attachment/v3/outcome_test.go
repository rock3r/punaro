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
	original := permitForManifest(source.manifest, source.raw, now.Add(-31*time.Second))
	original.Serial = testID(77)
	original.Operation = permitOperationSourceInit
	original.ExpiresAt = uint64(now.Add(-1 * time.Second).Unix())
	if err := SignPermit(&original, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	journalSourceInitPermit(t, store, original)
	permit := permitForManifest(source.manifest, source.raw, now)
	permit.OutcomeOfSerial = original.Serial
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

func TestOutcomeTerminalizesExpiredSourceInitBeforeLateInitialization(t *testing.T) {
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 16, 1, 0, 0, 0, time.UTC)
	manifest := testManifest(now)
	manifestPrivate := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if err := SignManifest(&manifest, manifestPrivate); err != nil {
		t.Fatal(err)
	}
	rawManifest, err := EncodeManifest(manifest)
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
	original := permitForManifest(manifest, rawManifest, now.Add(-31*time.Second))
	original.Serial, original.Operation, original.MaxOperations = testID(74), permitOperationSourceInit, 1
	original.ExpiresAt = uint64(now.Add(-time.Second).Unix())
	if err := SignPermit(&original, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	journalSourceInitPermit(t, store, original)
	outcome := permitForManifest(manifest, rawManifest, now)
	outcome.Operation, outcome.MaxOperations, outcome.OutcomeOfSerial = permitOperationOutcome, 1, original.Serial
	if err := SignPermit(&outcome, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	authority := permitAuthorityStub{key: issuerPublic}
	if err := store.issuePermit(context.Background(), outcome, authority, now); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/v3/attachments/%x/outcome", manifest.TransferID)
	route, request, err := NewAttachmentOperationRequest(http.MethodGet, path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	op := testOperation(outcome, request, now)
	if err := SignOperation(&op, holderPrivate); err != nil {
		t.Fatal(err)
	}
	raw, replayed, err := store.redeemOutcome(context.Background(), outcome, op, route, request, authority, operationHolderStub{device: outcome.HolderDeviceID, generation: outcome.HolderGeneration, key: holderPublic}, now)
	if err != nil || replayed {
		t.Fatalf("outcome replayed=%t err=%v", replayed, err)
	}
	result, err := DecodeTransferResult(raw)
	if err != nil || result.State != TransferStateCancelled {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	// Rewind only the verifier clock to model a source-init request that was
	// in flight before expiry while the outcome won the serialized database
	// race. The durable fence must still prevent source resurrection.
	sourcePath := fmt.Sprintf("/v3/attachments/%x/source", manifest.TransferID)
	sourceRoute, sourceRequest, err := NewAttachmentOperationRequest(http.MethodPost, sourcePath, rawManifest, nil)
	if err != nil {
		t.Fatal(err)
	}
	late := testOperation(original, sourceRequest, now.Add(-2*time.Second))
	if err := SignOperation(&late, holderPrivate); err != nil {
		t.Fatal(err)
	}
	directory := manifestAuthorityStub{public: manifestPrivate.Public().(ed25519.PublicKey)}
	if _, _, err := store.redeemSourceInit(context.Background(), directory, original, late, sourceRoute, sourceRequest, authority, operationHolderStub{device: original.HolderDeviceID, generation: original.HolderGeneration, key: holderPublic}, now.Add(-2*time.Second)); err == nil {
		t.Fatal("terminal source-init fence allowed source resurrection")
	}
}
