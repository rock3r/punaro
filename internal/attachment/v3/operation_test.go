package v3

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestOperationRecordBindsV3RequestPermitAndStagedSource(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	permit := testPermit(now)
	permit.Operation = permitOperationSourceUpload
	route, request, err := NewAttachmentOperationRequest("PUT", "/v3/attachments/05000000000000000000000000000000/source/chunks/0", []byte("ciphertext"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttachmentRoute(route, permit); err != nil {
		t.Fatal(err)
	}
	record := testOperation(permit, request, now)
	if err := SignOperation(&record, private); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeOperation(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOperation(raw)
	if err != nil {
		t.Fatal(err)
	}
	holders := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: public}
	if bytes, chunks, err := VerifyAttachmentOperationRequest(decoded, permit, holders, route, request, now); err != nil || bytes != uint64(len("ciphertext")) || chunks != 1 {
		t.Fatalf("bytes=%d chunks=%d err=%v", bytes, chunks, err)
	}
	decoded.StagedManifestCommitment[0] ^= 1
	if err := VerifyOperation(decoded, permit, holders, now); err == nil {
		t.Fatal("changed staged manifest binding was accepted")
	}
}

func TestDownloadOperationAdmissionDoesNotTakeCiphertextFromCaller(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	permit := testPermit(now)
	permit.HolderRole, permit.HolderDeviceID, permit.HolderGeneration = permitHolderRecipient, permit.RecipientDeviceID, permit.RecipientGeneration
	permit.Operation, permit.AttemptGeneration = permitOperationDownload, 1
	route, request, err := NewAttachmentOperationRequest("GET", "/v3/attachments/05000000000000000000000000000000/chunks/0", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAttachmentRoute(route, permit); err != nil {
		t.Fatal(err)
	}
	record := testOperation(permit, request, now)
	if err := SignOperation(&record, private); err != nil {
		t.Fatal(err)
	}
	holders := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: public}
	if err := VerifyAttachmentOperationAdmission(record, permit, holders, route, request, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewAttachmentOperationRequest("GET", "/v3/attachments/05000000000000000000000000000000/chunks/0", nil, []byte("caller bytes")); err == nil {
		t.Fatal("download admission accepted caller-supplied response bytes")
	}
}

func TestOperationCannotPredatePermit(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	permit := testPermit(now)
	permit.Operation = permitOperationSourceUpload
	_, request, err := NewAttachmentOperationRequest("PUT", "/v3/attachments/05000000000000000000000000000000/source/chunks/0", []byte("ciphertext"), nil)
	if err != nil {
		t.Fatal(err)
	}
	record := testOperation(permit, request, now.Add(-time.Second))
	if err := SignOperation(&record, private); err != nil {
		t.Fatal(err)
	}
	holders := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: public}
	if err := VerifyOperation(record, permit, holders, now); err == nil {
		t.Fatal("operation predating permit accepted")
	}
}

func TestAttachmentOperationRejectsRequestForAnotherRoute(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	permit := testPermit(now)
	permit.Operation = permitOperationSourceUpload
	routeA, _, err := NewAttachmentOperationRequest("PUT", "/v3/attachments/05000000000000000000000000000000/source/chunks/0", []byte("ciphertext"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, requestB, err := NewAttachmentOperationRequest("PUT", "/v3/attachments/0c000000000000000000000000000000/source/chunks/0", []byte("ciphertext"), nil)
	if err != nil {
		t.Fatal(err)
	}
	record := testOperation(permit, requestB, now)
	if err := SignOperation(&record, private); err != nil {
		t.Fatal(err)
	}
	holders := operationHolderStub{device: permit.HolderDeviceID, generation: permit.HolderGeneration, key: public}
	if _, _, err := VerifyAttachmentOperationRequest(record, permit, holders, routeA, requestB, now); err == nil {
		t.Fatal("operation request for another route accepted")
	}
}

type operationHolderStub struct {
	device     [16]byte
	generation uint64
	key        ed25519.PublicKey
}

func (s operationHolderStub) CurrentDeviceSigningKey(deviceID [16]byte, generation uint64) (ed25519.PublicKey, error) {
	if deviceID != s.device || generation != s.generation {
		return nil, errUnknownOperationHolder
	}
	return s.key, nil
}

func testOperation(permit Permit, request OperationRequest, now time.Time) OperationRecord {
	path, target, body := operationRequestCommitments(request)
	return OperationRecord{PermitSerial: permit.Serial, OperationID: testID(20), Operation: permit.Operation, Method: request.method, PathCommitment: path, TargetCommitment: target, BodyCommitment: body, IdempotencyKey: testHash(24), IssuedAt: uint64(now.Unix()), ExpiresAt: uint64(now.Add(10 * time.Second).Unix()), StagedManifestCommitment: permit.StagedManifestCommitment}
}
