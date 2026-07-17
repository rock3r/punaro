package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

const (
	maxPermitRequestEncodedBytes = 4 << 10
	permitRequestSignatureDomain = "punaro/attachment/permit-request/v3\x00"
	maxRetainedPermitRequests    = 3*4096 + 16
)

// PermitRequest is a holder-signed, retry-stable request for exactly one v3
// capability. The issuer, rather than the requester, derives all directory
// facts embedded in the resulting permit. StagedManifestCommitment is present
// even for source init, where the relay later compares it to the exact signed
// manifest body before creating any durable source state.
type PermitRequest struct {
	RequestID                [16]byte
	HolderDeviceID           [16]byte
	HolderGeneration         uint64
	HolderRole               uint64
	TransferID               [16]byte
	ConversationID           [16]byte
	SenderDeviceID           [16]byte
	SenderGeneration         uint64
	RecipientDeviceID        [16]byte
	RecipientGeneration      uint64
	AttemptGeneration        uint64
	Operation                uint64
	MembershipCommitment     [32]byte
	StagedManifestCommitment [32]byte
	OutcomeOfSerial          [16]byte
	IssuedAt                 uint64
	ExpiresAt                uint64
	MaxBytes                 uint64
	MaxChunks                uint64
	MaxOperations            uint64
	Signature                [ed25519.SignatureSize]byte
}

type permitRequestWire struct {
	Version                  uint64                      `cbor:"1,keyasint"`
	RequestID                [16]byte                    `cbor:"2,keyasint"`
	HolderDeviceID           [16]byte                    `cbor:"3,keyasint"`
	HolderGeneration         uint64                      `cbor:"4,keyasint"`
	HolderRole               uint64                      `cbor:"5,keyasint"`
	TransferID               [16]byte                    `cbor:"6,keyasint"`
	ConversationID           [16]byte                    `cbor:"7,keyasint"`
	SenderDeviceID           [16]byte                    `cbor:"8,keyasint"`
	SenderGeneration         uint64                      `cbor:"9,keyasint"`
	RecipientDeviceID        [16]byte                    `cbor:"10,keyasint"`
	RecipientGeneration      uint64                      `cbor:"11,keyasint"`
	AttemptGeneration        uint64                      `cbor:"12,keyasint"`
	Operation                uint64                      `cbor:"13,keyasint"`
	MembershipCommitment     [32]byte                    `cbor:"14,keyasint"`
	IssuedAt                 uint64                      `cbor:"15,keyasint"`
	ExpiresAt                uint64                      `cbor:"16,keyasint"`
	MaxBytes                 uint64                      `cbor:"17,keyasint"`
	MaxChunks                uint64                      `cbor:"18,keyasint"`
	MaxOperations            uint64                      `cbor:"19,keyasint"`
	StagedManifestCommitment [32]byte                    `cbor:"24,keyasint"`
	OutcomeOfSerial          [16]byte                    `cbor:"25,keyasint"`
	Signature                [ed25519.SignatureSize]byte `cbor:"99,keyasint"`
}

func (r PermitRequest) wire() permitRequestWire {
	return permitRequestWire{Version: protocolVersion, RequestID: r.RequestID, HolderDeviceID: r.HolderDeviceID, HolderGeneration: r.HolderGeneration, HolderRole: r.HolderRole, TransferID: r.TransferID, ConversationID: r.ConversationID, SenderDeviceID: r.SenderDeviceID, SenderGeneration: r.SenderGeneration, RecipientDeviceID: r.RecipientDeviceID, RecipientGeneration: r.RecipientGeneration, AttemptGeneration: r.AttemptGeneration, Operation: r.Operation, MembershipCommitment: r.MembershipCommitment, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt, MaxBytes: r.MaxBytes, MaxChunks: r.MaxChunks, MaxOperations: r.MaxOperations, StagedManifestCommitment: r.StagedManifestCommitment, OutcomeOfSerial: r.OutcomeOfSerial, Signature: r.Signature}
}

func (r PermitRequest) signedBytes() ([]byte, error) {
	raw, err := canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: r.RequestID, 3: r.HolderDeviceID, 4: r.HolderGeneration, 5: r.HolderRole, 6: r.TransferID, 7: r.ConversationID, 8: r.SenderDeviceID, 9: r.SenderGeneration, 10: r.RecipientDeviceID, 11: r.RecipientGeneration, 12: r.AttemptGeneration, 13: r.Operation, 14: r.MembershipCommitment, 15: r.IssuedAt, 16: r.ExpiresAt, 17: r.MaxBytes, 18: r.MaxChunks, 19: r.MaxOperations, 24: r.StagedManifestCommitment, 25: r.OutcomeOfSerial})
	return append([]byte(permitRequestSignatureDomain), raw...), err
}

func validatePermitRequest(r PermitRequest) error {
	if r.RequestID == [16]byte{} || r.HolderDeviceID == [16]byte{} || r.TransferID == [16]byte{} || r.ConversationID == [16]byte{} || r.SenderDeviceID == [16]byte{} || r.RecipientDeviceID == [16]byte{} || r.MembershipCommitment == [32]byte{} || r.StagedManifestCommitment == [32]byte{} || r.HolderGeneration == 0 || r.SenderGeneration == 0 || r.RecipientGeneration == 0 || r.HolderRole < permitHolderSender || r.HolderRole > permitHolderRecipient || r.Operation < permitOperationSourceInit || r.Operation > permitOperationOutcome || r.IssuedAt > math.MaxInt64 || r.ExpiresAt > math.MaxInt64 || r.ExpiresAt <= r.IssuedAt || r.ExpiresAt-r.IssuedAt > 30 || r.MaxBytes == 0 || r.MaxBytes > maxPermitCiphertextBytes || r.MaxChunks == 0 || r.MaxChunks > 4096 || r.MaxOperations == 0 || r.MaxOperations > 4096 || (r.Operation == permitOperationOutcome && r.OutcomeOfSerial == [16]byte{}) || (r.Operation != permitOperationOutcome && r.OutcomeOfSerial != [16]byte{}) {
		return errors.New("invalid v3 permit request")
	}
	if !validPermitOperation(Permit{HolderDeviceID: r.HolderDeviceID, HolderGeneration: r.HolderGeneration, HolderRole: r.HolderRole, SenderDeviceID: r.SenderDeviceID, SenderGeneration: r.SenderGeneration, RecipientDeviceID: r.RecipientDeviceID, RecipientGeneration: r.RecipientGeneration, AttemptGeneration: r.AttemptGeneration, Operation: r.Operation}) {
		return errors.New("invalid v3 permit request holder")
	}
	return nil
}

// SignPermitRequest signs one immutable issuance request with the current
// holder key. Network authentication remains a separate daemon obligation.
func SignPermitRequest(request *PermitRequest, private ed25519.PrivateKey) error {
	if request == nil || len(private) != ed25519.PrivateKeySize || validatePermitRequest(*request) != nil {
		return errors.New("invalid v3 permit request signer")
	}
	payload, err := request.signedBytes()
	if err != nil {
		return err
	}
	copy(request.Signature[:], ed25519.Sign(private, payload))
	return nil
}

// DirectoryPermitBinding is the short-lived authority fact copied from one
// fresh root-verified directory view into a newly signed permit.
type DirectoryPermitBinding struct {
	Audience        [32]byte
	DirectoryHead   [32]byte
	RevocationEpoch uint64
	ExpiresAt       uint64
}

// PermitIssuanceAuthority is a single fresh directory view. It is used to
// verify both the requesting holder and the authority facts in the result.
type PermitIssuanceAuthority interface {
	PermitAuthorityResolver
	OperationHolderResolver
	CurrentPermitIssuerKey([32]byte) (ed25519.PublicKey, error)
	CurrentPermitBinding(time.Time) (DirectoryPermitBinding, error)
}

// PermitIssuerOptions configures bounded permit issuance and its durable
// request ledger.
type PermitIssuerOptions struct {
	Store         *sourceStore
	IssuerKeyID   [32]byte
	PrivateKey    ed25519.PrivateKey
	MaxLifetime   time.Duration
	MaxBytes      uint64
	MaxChunks     uint64
	MaxOperations uint64
	MaxActive     uint64
	Now           func() time.Time
	Random        io.Reader
}

// PermitIssuer mints short-lived v3 permits and journals the exact signed
// request/permit pair in the private source store. A fresh directory advance
// replaces a stale prior grant for the same request ID; it never reuses a
// request ID for changed holder-controlled content.
type PermitIssuer struct {
	store         *sourceStore
	issuerKeyID   [32]byte
	privateKey    ed25519.PrivateKey
	maxLifetime   time.Duration
	maxBytes      uint64
	maxChunks     uint64
	maxOperations uint64
	maxActive     uint64
	now           func() time.Time
	random        io.Reader
}

// NewPermitIssuer constructs a permit issuer with bounded policy and a private
// durable source store.
func NewPermitIssuer(options PermitIssuerOptions) (*PermitIssuer, error) {
	if options.Store == nil || options.Store.db == nil || options.IssuerKeyID == [32]byte{} || len(options.PrivateKey) != ed25519.PrivateKeySize || options.MaxLifetime <= 0 || options.MaxLifetime > 30*time.Second || options.MaxBytes == 0 || options.MaxBytes > maxPermitCiphertextBytes || options.MaxChunks == 0 || options.MaxChunks > 4096 || options.MaxOperations == 0 || options.MaxOperations > 4096 || options.MaxActive == 0 || options.MaxActive > maxRetainedPermitRequests {
		return nil, errors.New("invalid v3 permit issuer configuration")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	return &PermitIssuer{store: options.Store, issuerKeyID: options.IssuerKeyID, privateKey: append(ed25519.PrivateKey(nil), options.PrivateKey...), maxLifetime: options.MaxLifetime, maxBytes: options.MaxBytes, maxChunks: options.MaxChunks, maxOperations: options.MaxOperations, maxActive: options.MaxActive, now: options.Now, random: options.Random}, nil
}

// Issue validates, signs, and durably records one permit request. Its boolean
// result reports whether an immutable prior issuance was replayed.
func (i *PermitIssuer) Issue(ctx context.Context, request PermitRequest, authority PermitIssuanceAuthority) (Permit, bool, error) {
	if i == nil || i.store == nil || authority == nil || validatePermitRequest(request) != nil {
		return Permit{}, false, errors.New("invalid v3 permit issuance")
	}
	now := i.now().UTC()
	nowUnix := now.Unix()
	if nowUnix < 0 {
		return Permit{}, false, errors.New("invalid v3 permit request time")
	}
	if !issuedWithinClockSkew(request.IssuedAt, nowUnix) {
		return Permit{}, false, errors.New("invalid v3 permit request time")
	}
	nowSeconds := uint64(nowUnix)
	holder, err := authority.CurrentDeviceSigningKey(request.HolderDeviceID, request.HolderGeneration)
	if err != nil || len(holder) != ed25519.PublicKeySize {
		return Permit{}, false, errors.New("unknown v3 permit request holder")
	}
	payload, err := request.signedBytes()
	if err != nil || !ed25519.Verify(holder, payload, request.Signature[:]) {
		return Permit{}, false, errors.New("invalid v3 permit request signature")
	}
	rawRequest, err := EncodePermitRequest(request)
	if err != nil {
		return Permit{}, false, err
	}
	// A request ID is an immutable issuance receipt. After a crash between
	// relay issuance and local persistence, returning the original (possibly
	// expired) permit gives the controller the precise serial needed for an
	// outcome query. Replacing it with a fresh serial would strand a committed
	// source-init behind an unrecoverable ambiguity.
	if request.ExpiresAt <= nowSeconds {
		stored, found, err := i.existingRequest(ctx, request.RequestID, rawRequest)
		if err != nil {
			return Permit{}, false, err
		}
		if found {
			return stored, true, nil
		}
		return Permit{}, false, errors.New("expired v3 permit request")
	}
	binding, err := authority.CurrentPermitBinding(now)
	if err != nil {
		return Permit{}, false, errors.New("fresh v3 permit directory authority is unavailable")
	}
	issuer, err := authority.CurrentPermitIssuerKey(i.issuerKeyID)
	if err != nil || !bytes.Equal(issuer, i.privateKey.Public().(ed25519.PublicKey)) {
		return Permit{}, false, errors.New("v3 permit issuer is not directory-authorized")
	}
	issuerExpiry := now.Add(i.maxLifetime).Unix()
	if issuerExpiry < 0 {
		return Permit{}, false, errors.New("invalid v3 issuer clock")
	}
	expiresAt := minPermitExpiry(request.ExpiresAt, binding.ExpiresAt, uint64(issuerExpiry))
	if expiresAt <= nowSeconds || request.MaxBytes > i.maxBytes || request.MaxChunks > i.maxChunks || request.MaxOperations > i.maxOperations {
		return Permit{}, false, errors.New("v3 permit request exceeds issuer policy")
	}
	for attempt := 0; attempt < 8; attempt++ {
		var serial [16]byte
		if _, err := io.ReadFull(i.random, serial[:]); err != nil || serial == [16]byte{} {
			return Permit{}, false, errors.New("generate v3 permit serial")
		}
		permit := Permit{Audience: binding.Audience, Serial: serial, IssuerKeyID: i.issuerKeyID, HolderDeviceID: request.HolderDeviceID, HolderGeneration: request.HolderGeneration, HolderRole: request.HolderRole, TransferID: request.TransferID, ConversationID: request.ConversationID, SenderDeviceID: request.SenderDeviceID, SenderGeneration: request.SenderGeneration, RecipientDeviceID: request.RecipientDeviceID, RecipientGeneration: request.RecipientGeneration, AttemptGeneration: request.AttemptGeneration, Operation: request.Operation, DirectoryHead: binding.DirectoryHead, MembershipCommitment: request.MembershipCommitment, RevocationEpoch: binding.RevocationEpoch, IssuedAt: nowSeconds, ExpiresAt: expiresAt, MaxBytes: request.MaxBytes, MaxChunks: request.MaxChunks, MaxOperations: request.MaxOperations, StagedManifestCommitment: request.StagedManifestCommitment, OutcomeOfSerial: request.OutcomeOfSerial}
		if err := SignPermit(&permit, i.privateKey); err != nil || VerifyPermit(permit, authority, now) != nil {
			return Permit{}, false, errors.New("issuer generated an invalid v3 permit")
		}
		stored, replayed, collision, err := i.persistRequest(ctx, request, rawRequest, permit, now)
		if err != nil {
			return Permit{}, false, err
		}
		if collision {
			continue
		}
		return stored, replayed, nil
	}
	return Permit{}, false, errors.New("v3 permit serial collision limit exceeded")
}

func (i *PermitIssuer) persistRequest(ctx context.Context, request PermitRequest, rawRequest []byte, permit Permit, now time.Time) (Permit, bool, bool, error) {
	rawPermit, err := EncodePermit(permit)
	if err != nil {
		return Permit{}, false, false, err
	}
	tx, err := i.store.db.BeginTx(ctx, nil)
	if err != nil {
		return Permit{}, false, false, err
	}
	defer func() { _ = tx.Rollback() }()
	cutoff := now.Unix()
	if cutoff < 0 {
		return Permit{}, false, false, errors.New("invalid v3 issuer clock")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_permit_requests WHERE retain_until <= ?`, cutoff); err != nil {
		return Permit{}, false, false, err
	}
	var storedRequest, storedPermit []byte
	err = tx.QueryRowContext(ctx, `SELECT request, permit FROM v3_permit_requests WHERE request_id = ?`, request.RequestID[:]).Scan(&storedRequest, &storedPermit)
	if err == nil {
		if !bytes.Equal(storedRequest, rawRequest) {
			return Permit{}, false, false, errors.New("changed v3 permit issuance request")
		}
		previous, decodeErr := DecodePermit(storedPermit)
		if decodeErr != nil {
			return Permit{}, false, false, errors.New("invalid stored v3 permit")
		}
		return previous, true, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Permit{}, false, false, err
	}
	var active uint64
	// Request identities remain authoritative through their bounded tombstone
	// retention. Count them too: counting only live permits lets one enrolled
	// holder turn short-lived requests into unbounded retained SQLite state.
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v3_permit_requests WHERE holder_device_id = ?`, request.HolderDeviceID[:]).Scan(&active); err != nil {
		return Permit{}, false, false, err
	}
	if active >= i.maxActive {
		return Permit{}, false, false, errors.New("active v3 permit quota exhausted")
	}
	var issued []byte
	lookupErr := tx.QueryRowContext(ctx, `SELECT permit FROM v3_issued_permits WHERE serial = ?`, permit.Serial[:]).Scan(&issued)
	if lookupErr == nil {
		return Permit{}, false, true, nil
	}
	if !errors.Is(lookupErr, sql.ErrNoRows) {
		return Permit{}, false, false, lookupErr
	}
	retainUntil, err := permitRequestRetention(i.store, permit, now)
	if err != nil {
		return Permit{}, false, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_permit_requests(request_id, request, permit, permit_serial, holder_device_id, expires_at, retain_until) VALUES (?, ?, ?, ?, ?, ?, ?)`, request.RequestID[:], rawRequest, rawPermit, permit.Serial[:], request.HolderDeviceID[:], permit.ExpiresAt, retainUntil); err != nil {
		return Permit{}, false, false, fmt.Errorf("record v3 permit issuance: %w", err)
	}
	return permit, false, false, tx.Commit()
}

func (i *PermitIssuer) existingRequest(ctx context.Context, requestID [16]byte, rawRequest []byte) (Permit, bool, error) {
	var storedRequest, storedPermit []byte
	err := i.store.db.QueryRowContext(ctx, `SELECT request, permit FROM v3_permit_requests WHERE request_id = ?`, requestID[:]).Scan(&storedRequest, &storedPermit)
	if errors.Is(err, sql.ErrNoRows) {
		return Permit{}, false, nil
	}
	if err != nil || !bytes.Equal(storedRequest, rawRequest) {
		if err != nil {
			return Permit{}, false, err
		}
		return Permit{}, false, errors.New("changed v3 permit issuance request")
	}
	permit, err := DecodePermit(storedPermit)
	if err != nil {
		return Permit{}, false, errors.New("invalid stored v3 permit")
	}
	return permit, true, nil
}

func permitRequestRetention(store *sourceStore, permit Permit, now time.Time) (int64, error) {
	permitExpiry, err := unixSeconds(permit.ExpiresAt)
	if err != nil {
		return 0, err
	}
	retainUntil := now.UTC().Add(store.limits.TombstoneRetention).Unix()
	if retainUntil < permitExpiry {
		return permitExpiry, nil
	}
	return retainUntil, nil
}

func minPermitExpiry(values ...uint64) uint64 {
	minimum := values[0]
	for _, value := range values[1:] {
		if value < minimum {
			minimum = value
		}
	}
	return minimum
}

// EncodePermitRequest returns the canonical wire encoding of a valid request.
func EncodePermitRequest(request PermitRequest) ([]byte, error) {
	if err := validatePermitRequest(request); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(request.wire())
}

// DecodePermitRequest accepts only a bounded canonical permit request.
func DecodePermitRequest(raw []byte) (PermitRequest, error) {
	if len(raw) == 0 || len(raw) > maxPermitRequestEncodedBytes {
		return PermitRequest{}, errors.New("invalid v3 permit request")
	}
	var wire permitRequestWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil || wire.Version != protocolVersion {
		return PermitRequest{}, errors.New("invalid v3 permit request")
	}
	request := PermitRequest{RequestID: wire.RequestID, HolderDeviceID: wire.HolderDeviceID, HolderGeneration: wire.HolderGeneration, HolderRole: wire.HolderRole, TransferID: wire.TransferID, ConversationID: wire.ConversationID, SenderDeviceID: wire.SenderDeviceID, SenderGeneration: wire.SenderGeneration, RecipientDeviceID: wire.RecipientDeviceID, RecipientGeneration: wire.RecipientGeneration, AttemptGeneration: wire.AttemptGeneration, Operation: wire.Operation, MembershipCommitment: wire.MembershipCommitment, StagedManifestCommitment: wire.StagedManifestCommitment, OutcomeOfSerial: wire.OutcomeOfSerial, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt, MaxBytes: wire.MaxBytes, MaxChunks: wire.MaxChunks, MaxOperations: wire.MaxOperations, Signature: wire.Signature}
	canonical, err := EncodePermitRequest(request)
	if err != nil || !bytes.Equal(raw, canonical) {
		return PermitRequest{}, errors.New("non-canonical v3 permit request")
	}
	return request, nil
}
