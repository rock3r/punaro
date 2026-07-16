package v2

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
	operationSignatureDomain = "punaro/attachment/operation/v2\x00"
	operationPathDomain      = "punaro/attachment/operation-path/v2\x00"
	operationTargetDomain    = "punaro/attachment/operation-target/v2\x00"
	operationBodyDomain      = "punaro/attachment/operation-body/v2\x00"
	maxOperationPathBytes    = 4 << 10
	maxOperationTargetBytes  = 4 << 10
)

var errUnknownOperationHolder = errors.New("unknown operation holder")

// OperationHolderResolver resolves the currently authorized device signing key
// for a permit holder. It must fail closed for stale, revoked, or superseded
// device generations.
type OperationHolderResolver interface {
	CurrentDeviceSigningKey(deviceID [16]byte, generation uint64) (ed25519.PublicKey, error)
}

// OperationRecord binds one concrete HTTP operation to one permit and holder.
type OperationRecord struct {
	PermitSerial     [16]byte
	OperationID      [16]byte
	Operation        uint64
	Method           uint64
	PathCommitment   [32]byte
	TargetCommitment [32]byte
	BodyCommitment   [32]byte
	IdempotencyKey   [32]byte
	IssuedAt         uint64
	ExpiresAt        uint64
	Signature        [ed25519.SignatureSize]byte
}

// OperationRequest is the authoritative, bounded request representation
// produced by the HTTP schema decoder. Path is the decoded path without a
// query or fragment; Target is the canonical target identifier bytes; Body is
// the exact raw request body. A download also carries the exact bounded
// ciphertext selected by immutable relay storage for the response. Uploads and
// downloads each redeem one ciphertext chunk; other operations consume no
// ciphertext quota.
type OperationRequest struct {
	method             uint64
	path               string
	target             []byte
	body               []byte
	responseCiphertext []byte
}

// NewOperationRecordRequest derives the three signed commitments from the
// actual request data. Callers must not construct commitments independently.
func NewOperationRecordRequest(method uint64, path string, target, body []byte) (OperationRequest, error) {
	request := OperationRequest{method: method, path: path, target: append([]byte(nil), target...), body: append([]byte(nil), body...)}
	if err := validateOperationRequest(request); err != nil {
		return OperationRequest{}, err
	}
	return request, nil
}

// NewDownloadOperationRequest binds an empty-body download request to the
// exact ciphertext selected from immutable relay storage for its response. A
// caller cannot account a synthetic byte count: quota is derived from this
// bounded byte slice, while the signed HTTP-body commitment remains empty.
func NewDownloadOperationRequest(method uint64, path string, target, ciphertext []byte) (OperationRequest, error) {
	request, err := NewOperationRecordRequest(method, path, target, nil)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > 256<<10+16 {
		return OperationRequest{}, errors.New("invalid download operation request")
	}
	request.responseCiphertext = append([]byte(nil), ciphertext...)
	return request, nil
}

func operationRequestCommitments(request OperationRequest) ([32]byte, [32]byte, [32]byte) {
	path := blake3.Sum256(append([]byte(operationPathDomain), []byte(request.path)...))
	target := blake3.Sum256(append([]byte(operationTargetDomain), request.target...))
	body := blake3.Sum256(append([]byte(operationBodyDomain), request.body...))
	return path, target, body
}

func validateOperationRequest(request OperationRequest) error {
	if request.method == 0 || len(request.path) == 0 || len(request.path) > maxOperationPathBytes || !strings.HasPrefix(request.path, "/") || strings.ContainsAny(request.path, "?#\x00") || len(request.target) == 0 || len(request.target) > maxOperationTargetBytes || len(request.body) > 256<<10+16 || len(request.responseCiphertext) > 256<<10+16 {
		return errors.New("invalid operation request")
	}
	return nil
}

func operationUsage(operation uint64, request OperationRequest) (uint64, uint64, error) {
	if err := validateOperationRequest(request); err != nil {
		return 0, 0, err
	}
	switch operation {
	case PermitOperationUpload:
		if len(request.body) == 0 {
			return 0, 0, errors.New("ciphertext chunk is required")
		}
		return uint64(len(request.body)), 1, nil // #nosec G115 -- len is bounded above.
	case PermitOperationDownload:
		if len(request.body) != 0 || len(request.responseCiphertext) == 0 {
			return 0, 0, errors.New("stored ciphertext chunk is required")
		}
		return uint64(len(request.responseCiphertext)), 1, nil // #nosec G115 -- len is bounded above.
	default:
		return 0, 0, nil
	}
}

type operationWire struct {
	Version          uint64                      `cbor:"1,keyasint"`
	PermitSerial     [16]byte                    `cbor:"2,keyasint"`
	OperationID      [16]byte                    `cbor:"3,keyasint"`
	Operation        uint64                      `cbor:"4,keyasint"`
	Method           uint64                      `cbor:"5,keyasint"`
	PathCommitment   [32]byte                    `cbor:"6,keyasint"`
	TargetCommitment [32]byte                    `cbor:"7,keyasint"`
	BodyCommitment   [32]byte                    `cbor:"8,keyasint"`
	IdempotencyKey   [32]byte                    `cbor:"9,keyasint"`
	IssuedAt         uint64                      `cbor:"10,keyasint"`
	ExpiresAt        uint64                      `cbor:"11,keyasint"`
	Signature        [ed25519.SignatureSize]byte `cbor:"99,keyasint"`
}

func (r OperationRecord) wire() operationWire {
	return operationWire{Version: protocolVersion, PermitSerial: r.PermitSerial, OperationID: r.OperationID, Operation: r.Operation, Method: r.Method, PathCommitment: r.PathCommitment, TargetCommitment: r.TargetCommitment, BodyCommitment: r.BodyCommitment, IdempotencyKey: r.IdempotencyKey, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt, Signature: r.Signature}
}

func (r OperationRecord) signedBytes() ([]byte, error) {
	encoded, err := canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: r.PermitSerial, 3: r.OperationID, 4: r.Operation, 5: r.Method, 6: r.PathCommitment, 7: r.TargetCommitment, 8: r.BodyCommitment, 9: r.IdempotencyKey, 10: r.IssuedAt, 11: r.ExpiresAt})
	return append([]byte(operationSignatureDomain), encoded...), err
}

func validateOperation(r OperationRecord) error {
	if isZero16(r.PermitSerial) || isZero16(r.OperationID) || r.Operation < PermitOperationOffer || r.Operation > PermitOperationComplete || r.Method == 0 || isZero32(r.PathCommitment) || isZero32(r.TargetCommitment) || isZero32(r.BodyCommitment) || isZero32(r.IdempotencyKey) || r.ExpiresAt <= r.IssuedAt {
		return errors.New("invalid operation record")
	}
	return nil
}

// SignOperation validates and signs an exact operation request with the permit
// holder's device signing key.
func SignOperation(r *OperationRecord, private ed25519.PrivateKey) error {
	if r == nil || len(private) != ed25519.PrivateKeySize || validateOperation(*r) != nil {
		return errors.New("invalid operation signer")
	}
	payload, err := r.signedBytes()
	if err != nil {
		return err
	}
	copy(r.Signature[:], ed25519.Sign(private, payload))
	return nil
}

// VerifyOperation verifies timing, exact permit binding, active holder key,
// and holder signature before any state lookup or redemption.
func VerifyOperation(r OperationRecord, permit Permit, holders OperationHolderResolver, now time.Time) error {
	if holders == nil || validateOperation(r) != nil || validatePermit(permit) != nil || r.PermitSerial != permit.Serial || r.Operation != permit.Operation || r.ExpiresAt > permit.ExpiresAt {
		return errors.New("invalid operation permit binding")
	}
	seconds := now.UTC().Unix()
	if seconds < 0 || r.IssuedAt > uint64(seconds) || r.ExpiresAt <= uint64(seconds) {
		return errors.New("expired operation record")
	}
	holder, err := holders.CurrentDeviceSigningKey(permit.HolderDeviceID, permit.HolderGeneration)
	if err != nil || len(holder) != ed25519.PublicKeySize {
		return errUnknownOperationHolder
	}
	payload, err := r.signedBytes()
	if err != nil || !ed25519.Verify(holder, payload, r.Signature[:]) {
		return errors.New("invalid operation signature")
	}
	return nil
}

// VerifyOperationRequest requires a valid signed record to name the exact
// method, path, target, and raw body received by the relay. It returns the
// authoritative ciphertext quota consumed by this one redemption.
func VerifyOperationRequest(r OperationRecord, permit Permit, holders OperationHolderResolver, request OperationRequest, now time.Time) (uint64, uint64, error) {
	if err := VerifyOperation(r, permit, holders, now); err != nil {
		return 0, 0, err
	}
	if err := validateOperationRequest(request); err != nil {
		return 0, 0, err
	}
	path, target, body := operationRequestCommitments(request)
	if r.Method != request.method || r.PathCommitment != path || r.TargetCommitment != target || r.BodyCommitment != body {
		return 0, 0, errors.New("operation request commitment mismatch")
	}
	return operationUsage(r.Operation, request)
}

// EncodeOperation serializes a complete canonical operation record.
func EncodeOperation(r OperationRecord) ([]byte, error) {
	if err := validateOperation(r); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(r.wire())
}

// DecodeOperation accepts only a complete, strict, canonical operation record.
func DecodeOperation(raw []byte) (OperationRecord, error) {
	if len(raw) == 0 || len(raw) > maxOperationEncodedBytes {
		return OperationRecord{}, errors.New("invalid operation record size")
	}
	var wire operationWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil {
		return OperationRecord{}, fmt.Errorf("decode operation record: %w", err)
	}
	if wire.Version != protocolVersion {
		return OperationRecord{}, errors.New("unsupported operation record version")
	}
	r := OperationRecord{PermitSerial: wire.PermitSerial, OperationID: wire.OperationID, Operation: wire.Operation, Method: wire.Method, PathCommitment: wire.PathCommitment, TargetCommitment: wire.TargetCommitment, BodyCommitment: wire.BodyCommitment, IdempotencyKey: wire.IdempotencyKey, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt, Signature: wire.Signature}
	if err := validateOperation(r); err != nil {
		return OperationRecord{}, err
	}
	canonical, err := EncodeOperation(r)
	if err != nil || !bytes.Equal(raw, canonical) {
		return OperationRecord{}, errors.New("non-canonical operation record")
	}
	return r, nil
}
