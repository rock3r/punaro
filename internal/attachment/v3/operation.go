package v3

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeebo/blake3"
)

const (
	maxOperationEncodedBytes = 4 << 10
	maxOperationPathBytes    = 4 << 10
	maxOperationTargetBytes  = 4 << 10
	maxCiphertextChunkBytes  = 256<<10 + 16

	operationSignatureDomain = "punaro/attachment/operation/v3\x00"
	operationPathDomain      = "punaro/attachment/operation-path/v3\x00"
	operationTargetDomain    = "punaro/attachment/operation-target/v3\x00"
	operationBodyDomain      = "punaro/attachment/operation-body/v3\x00"
)

var errUnknownOperationHolder = errors.New("unknown v3 operation holder")

// OperationHolderResolver resolves the currently authorized device signing key
// for a permit holder. It must fail closed for stale, revoked, or superseded
// device generations.
type OperationHolderResolver interface {
	CurrentDeviceSigningKey(deviceID [16]byte, generation uint64) (ed25519.PublicKey, error)
}

// OperationRecord binds one concrete HTTP operation to one v3 permit, its
// active holder and the immutable staged manifest selected by source init.
type OperationRecord struct {
	PermitSerial             [16]byte
	OperationID              [16]byte
	Operation                uint64
	Method                   uint64
	PathCommitment           [32]byte
	TargetCommitment         [32]byte
	BodyCommitment           [32]byte
	IdempotencyKey           [32]byte
	IssuedAt                 uint64
	ExpiresAt                uint64
	StagedManifestCommitment [32]byte
	Signature                [ed25519.SignatureSize]byte
}

// OperationRequest is the authoritative, bounded request representation
// produced by the HTTP schema decoder. Path is decoded without a query or
// fragment; Target is the canonical target identifier; Body is the exact raw
// request body. Downloads additionally carry the exact ciphertext selected by
// immutable relay storage for their response. Only source-upload and download
// consume a ciphertext chunk from their permit quota.
type OperationRequest struct {
	method             uint64
	path               string
	target             []byte
	body               []byte
	responseCiphertext []byte
}

// newOperationRecordRequest is only used after strict route parsing. It
// derives commitments from the decoded request rather than accepting them.
func newOperationRecordRequest(method uint64, path string, target, body []byte) (OperationRequest, error) {
	request := OperationRequest{method: method, path: path, target: append([]byte(nil), target...), body: append([]byte(nil), body...)}
	if err := validateOperationRequest(request); err != nil {
		return OperationRequest{}, err
	}
	return request, nil
}

func operationRequestCommitments(request OperationRequest) ([32]byte, [32]byte, [32]byte) {
	path := blake3.Sum256(append([]byte(operationPathDomain), []byte(request.path)...))
	target := blake3.Sum256(append([]byte(operationTargetDomain), request.target...))
	body := blake3.Sum256(append([]byte(operationBodyDomain), request.body...))
	return path, target, body
}

func validateOperationRequest(request OperationRequest) error {
	if request.method == 0 || len(request.path) == 0 || len(request.path) > maxOperationPathBytes || !strings.HasPrefix(request.path, "/") || strings.ContainsAny(request.path, "?#\x00") || len(request.target) == 0 || len(request.target) > maxOperationTargetBytes || len(request.body) > maxCiphertextChunkBytes || len(request.responseCiphertext) > maxCiphertextChunkBytes {
		return errors.New("invalid v3 operation request")
	}
	return nil
}

func operationUsage(operation uint64, request OperationRequest) (uint64, uint64, error) {
	if err := validateOperationRequest(request); err != nil {
		return 0, 0, err
	}
	switch operation {
	case permitOperationSourceUpload:
		if len(request.body) == 0 || len(request.responseCiphertext) != 0 {
			return 0, 0, errors.New("v3 ciphertext chunk is required")
		}
		return uint64(len(request.body)), 1, nil // #nosec G115 -- bounded above.
	case permitOperationDownload:
		if len(request.body) != 0 || len(request.responseCiphertext) == 0 {
			return 0, 0, errors.New("v3 stored ciphertext chunk is required")
		}
		return uint64(len(request.responseCiphertext)), 1, nil // #nosec G115 -- bounded above.
	default:
		if len(request.responseCiphertext) != 0 {
			return 0, 0, errors.New("unexpected v3 response ciphertext")
		}
		return 0, 0, nil
	}
}

type operationWire struct {
	Version                  uint64                      `cbor:"1,keyasint"`
	PermitSerial             [16]byte                    `cbor:"2,keyasint"`
	OperationID              [16]byte                    `cbor:"3,keyasint"`
	Operation                uint64                      `cbor:"4,keyasint"`
	Method                   uint64                      `cbor:"5,keyasint"`
	PathCommitment           [32]byte                    `cbor:"6,keyasint"`
	TargetCommitment         [32]byte                    `cbor:"7,keyasint"`
	BodyCommitment           [32]byte                    `cbor:"8,keyasint"`
	IdempotencyKey           [32]byte                    `cbor:"9,keyasint"`
	IssuedAt                 uint64                      `cbor:"10,keyasint"`
	ExpiresAt                uint64                      `cbor:"11,keyasint"`
	StagedManifestCommitment [32]byte                    `cbor:"24,keyasint"`
	Signature                [ed25519.SignatureSize]byte `cbor:"99,keyasint"`
}

func (r OperationRecord) wire() operationWire {
	return operationWire{Version: protocolVersion, PermitSerial: r.PermitSerial, OperationID: r.OperationID, Operation: r.Operation, Method: r.Method, PathCommitment: r.PathCommitment, TargetCommitment: r.TargetCommitment, BodyCommitment: r.BodyCommitment, IdempotencyKey: r.IdempotencyKey, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt, StagedManifestCommitment: r.StagedManifestCommitment, Signature: r.Signature}
}

func (r OperationRecord) signedBytes() ([]byte, error) {
	encoded, err := canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: r.PermitSerial, 3: r.OperationID, 4: r.Operation, 5: r.Method, 6: r.PathCommitment, 7: r.TargetCommitment, 8: r.BodyCommitment, 9: r.IdempotencyKey, 10: r.IssuedAt, 11: r.ExpiresAt, 24: r.StagedManifestCommitment})
	return append([]byte(operationSignatureDomain), encoded...), err
}

func validateOperation(r OperationRecord) error {
	if r.PermitSerial == [16]byte{} || r.OperationID == [16]byte{} || r.Operation < permitOperationSourceInit || r.Operation > permitOperationOutcome || r.Method == 0 || r.PathCommitment == [32]byte{} || r.TargetCommitment == [32]byte{} || r.BodyCommitment == [32]byte{} || r.IdempotencyKey == [32]byte{} || r.StagedManifestCommitment == [32]byte{} || r.ExpiresAt <= r.IssuedAt {
		return errors.New("invalid v3 operation record")
	}
	return nil
}

// SignOperation signs an already-derived exact operation with the active
// permit holder's device signing key.
func SignOperation(r *OperationRecord, private ed25519.PrivateKey) error {
	if r == nil || len(private) != ed25519.PrivateKeySize || validateOperation(*r) != nil {
		return errors.New("invalid v3 operation signer")
	}
	payload, err := r.signedBytes()
	if err != nil {
		return err
	}
	copy(r.Signature[:], ed25519.Sign(private, payload))
	return nil
}

// BuildSignedAttachmentOperation derives every operation commitment from the
// fixed v3 route and exact body, then signs it with the permit holder key.
// Callers provide only opaque per-operation identities and bounded timing;
// they cannot supply a target, path, or body commitment separately.
func BuildSignedAttachmentOperation(permit Permit, method, path string, body []byte, operationID [16]byte, idempotencyKey [32]byte, issuedAt, expiresAt uint64, private ed25519.PrivateKey) (OperationRecord, error) {
	if validatePermit(permit) != nil || operationID == [16]byte{} || idempotencyKey == [32]byte{} || issuedAt < permit.IssuedAt || expiresAt > permit.ExpiresAt || expiresAt <= issuedAt {
		return OperationRecord{}, errors.New("invalid v3 attachment operation input")
	}
	route, request, err := NewAttachmentOperationRequest(method, path, body, nil)
	if err != nil || VerifyAttachmentRoute(route, permit) != nil || verifyAttachmentRequestRoute(route, permit, request) != nil {
		return OperationRecord{}, errors.New("invalid v3 attachment operation route")
	}
	pathCommitment, targetCommitment, bodyCommitment := operationRequestCommitments(request)
	operation := OperationRecord{PermitSerial: permit.Serial, OperationID: operationID, Operation: permit.Operation, Method: request.method, PathCommitment: pathCommitment, TargetCommitment: targetCommitment, BodyCommitment: bodyCommitment, IdempotencyKey: idempotencyKey, IssuedAt: issuedAt, ExpiresAt: expiresAt, StagedManifestCommitment: permit.StagedManifestCommitment}
	if err := SignOperation(&operation, private); err != nil {
		return OperationRecord{}, err
	}
	return operation, nil
}

// VerifyOperation checks timing, permit binding, fresh holder authorization,
// staged source binding, and holder signature before state lookup/redemption.
func VerifyOperation(r OperationRecord, permit Permit, holders OperationHolderResolver, now time.Time) error {
	if holders == nil || validateOperation(r) != nil || validatePermit(permit) != nil || r.PermitSerial != permit.Serial || r.Operation != permit.Operation || r.StagedManifestCommitment != permit.StagedManifestCommitment || r.IssuedAt < permit.IssuedAt || r.ExpiresAt > permit.ExpiresAt {
		return errors.New("invalid v3 operation permit binding")
	}
	seconds := now.UTC().Unix()
	if seconds < 0 || r.IssuedAt > uint64(seconds) || r.ExpiresAt <= uint64(seconds) {
		return errors.New("expired v3 operation record")
	}
	holder, err := holders.CurrentDeviceSigningKey(permit.HolderDeviceID, permit.HolderGeneration)
	if err != nil || len(holder) != ed25519.PublicKeySize {
		return errUnknownOperationHolder
	}
	payload, err := r.signedBytes()
	if err != nil || !ed25519.Verify(holder, payload, r.Signature[:]) {
		return errors.New("invalid v3 operation signature")
	}
	return nil
}

// verifyOperationRequest checks an already route-admitted operation against
// its exact decoded request and returns authoritative permit usage.
func verifyOperationRequestAuthorization(r OperationRecord, permit Permit, holders OperationHolderResolver, request OperationRequest, now time.Time) error {
	if err := VerifyOperation(r, permit, holders, now); err != nil {
		return err
	}
	if err := validateOperationRequest(request); err != nil {
		return err
	}
	path, target, body := operationRequestCommitments(request)
	if r.Method != request.method || r.PathCommitment != path || r.TargetCommitment != target || r.BodyCommitment != body {
		return errors.New("v3 operation request commitment mismatch")
	}
	return nil
}

// VerifyAttachmentOperationAdmission authenticates the fixed route, permit
// holder, and signed request without reading or selecting a relay blob. It is
// used only for downloads, whose response bytes are selected atomically after
// this admission succeeds.
func VerifyAttachmentOperationAdmission(r OperationRecord, permit Permit, holders OperationHolderResolver, route AttachmentRoute, request OperationRequest, now time.Time) error {
	if err := VerifyAttachmentRoute(route, permit); err != nil {
		return err
	}
	if err := verifyAttachmentRequestRoute(route, permit, request); err != nil {
		return err
	}
	return verifyOperationRequestAuthorization(r, permit, holders, request, now)
}

// VerifyAttachmentOperationRequest is the only v3 HTTP-facing operation
// verifier. It binds the signed request to the fixed parsed route and permit
// before examining request commitments or charging permit quota.
func VerifyAttachmentOperationRequest(r OperationRecord, permit Permit, holders OperationHolderResolver, route AttachmentRoute, request OperationRequest, now time.Time) (uint64, uint64, error) {
	if err := VerifyAttachmentOperationAdmission(r, permit, holders, route, request, now); err != nil {
		return 0, 0, err
	}
	return operationUsage(r.Operation, request)
}

func EncodeOperation(r OperationRecord) ([]byte, error) {
	if err := validateOperation(r); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(r.wire())
}

func DecodeOperation(raw []byte) (OperationRecord, error) {
	if len(raw) == 0 || len(raw) > maxOperationEncodedBytes {
		return OperationRecord{}, errors.New("invalid v3 operation record size")
	}
	var wire operationWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil {
		return OperationRecord{}, fmt.Errorf("decode v3 operation record: %w", err)
	}
	if wire.Version != protocolVersion {
		return OperationRecord{}, errors.New("unsupported v3 operation record version")
	}
	r := OperationRecord{PermitSerial: wire.PermitSerial, OperationID: wire.OperationID, Operation: wire.Operation, Method: wire.Method, PathCommitment: wire.PathCommitment, TargetCommitment: wire.TargetCommitment, BodyCommitment: wire.BodyCommitment, IdempotencyKey: wire.IdempotencyKey, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt, StagedManifestCommitment: wire.StagedManifestCommitment, Signature: wire.Signature}
	if err := validateOperation(r); err != nil {
		return OperationRecord{}, err
	}
	canonical, err := EncodeOperation(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return OperationRecord{}, errors.New("non-canonical v3 operation record")
	}
	return r, nil
}
