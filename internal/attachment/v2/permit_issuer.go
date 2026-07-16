package v2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

const permitRequestSignatureDomain = "punaro/attachment/permit-request/v2\x00"

// PermitRequest is the holder-signed, retry-stable request to mint one
// operation-specific permit. Directory bindings are deliberately absent: the
// issuer derives them from a fresh verified authority at issuance time.
type PermitRequest struct {
	RequestID            [16]byte
	HolderDeviceID       [16]byte
	HolderGeneration     uint64
	HolderRole           uint64
	TransferID           [16]byte
	ConversationID       [16]byte
	SenderDeviceID       [16]byte
	SenderGeneration     uint64
	RecipientDeviceID    [16]byte
	RecipientGeneration  uint64
	AttemptGeneration    uint64
	Operation            uint64
	MembershipCommitment [32]byte
	IssuedAt             uint64
	ExpiresAt            uint64
	MaxBytes             uint64
	MaxChunks            uint64
	MaxOperations        uint64
	Signature            [ed25519.SignatureSize]byte
}

type permitRequestWire struct {
	Version              uint64                      `cbor:"1,keyasint"`
	RequestID            [16]byte                    `cbor:"2,keyasint"`
	HolderDeviceID       [16]byte                    `cbor:"3,keyasint"`
	HolderGeneration     uint64                      `cbor:"4,keyasint"`
	HolderRole           uint64                      `cbor:"5,keyasint"`
	TransferID           [16]byte                    `cbor:"6,keyasint"`
	ConversationID       [16]byte                    `cbor:"7,keyasint"`
	SenderDeviceID       [16]byte                    `cbor:"8,keyasint"`
	SenderGeneration     uint64                      `cbor:"9,keyasint"`
	RecipientDeviceID    [16]byte                    `cbor:"10,keyasint"`
	RecipientGeneration  uint64                      `cbor:"11,keyasint"`
	AttemptGeneration    uint64                      `cbor:"12,keyasint"`
	Operation            uint64                      `cbor:"13,keyasint"`
	MembershipCommitment [32]byte                    `cbor:"14,keyasint"`
	IssuedAt             uint64                      `cbor:"15,keyasint"`
	ExpiresAt            uint64                      `cbor:"16,keyasint"`
	MaxBytes             uint64                      `cbor:"17,keyasint"`
	MaxChunks            uint64                      `cbor:"18,keyasint"`
	MaxOperations        uint64                      `cbor:"19,keyasint"`
	Signature            [ed25519.SignatureSize]byte `cbor:"99,keyasint"`
}

func (r PermitRequest) wire() permitRequestWire {
	return permitRequestWire{Version: protocolVersion, RequestID: r.RequestID, HolderDeviceID: r.HolderDeviceID, HolderGeneration: r.HolderGeneration, HolderRole: r.HolderRole, TransferID: r.TransferID, ConversationID: r.ConversationID, SenderDeviceID: r.SenderDeviceID, SenderGeneration: r.SenderGeneration, RecipientDeviceID: r.RecipientDeviceID, RecipientGeneration: r.RecipientGeneration, AttemptGeneration: r.AttemptGeneration, Operation: r.Operation, MembershipCommitment: r.MembershipCommitment, IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt, MaxBytes: r.MaxBytes, MaxChunks: r.MaxChunks, MaxOperations: r.MaxOperations, Signature: r.Signature}
}

func (r PermitRequest) signedBytes() ([]byte, error) {
	raw, err := canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: r.RequestID, 3: r.HolderDeviceID, 4: r.HolderGeneration, 5: r.HolderRole, 6: r.TransferID, 7: r.ConversationID, 8: r.SenderDeviceID, 9: r.SenderGeneration, 10: r.RecipientDeviceID, 11: r.RecipientGeneration, 12: r.AttemptGeneration, 13: r.Operation, 14: r.MembershipCommitment, 15: r.IssuedAt, 16: r.ExpiresAt, 17: r.MaxBytes, 18: r.MaxChunks, 19: r.MaxOperations})
	return append([]byte(permitRequestSignatureDomain), raw...), err
}

func validatePermitRequest(r PermitRequest) error {
	if isZero16(r.RequestID) || isZero16(r.HolderDeviceID) || isZero16(r.TransferID) || isZero16(r.ConversationID) || isZero16(r.SenderDeviceID) || isZero16(r.RecipientDeviceID) || isZero32(r.MembershipCommitment) || r.HolderGeneration == 0 || r.SenderGeneration == 0 || r.RecipientGeneration == 0 || r.AttemptGeneration == 0 || r.HolderRole < PermitHolderSender || r.HolderRole > PermitHolderRelay || r.Operation < PermitOperationOffer || r.Operation > PermitOperationComplete || r.ExpiresAt <= r.IssuedAt || r.ExpiresAt-r.IssuedAt > 60 || r.MaxBytes > 64<<20 || r.MaxChunks > 4096 || r.MaxOperations == 0 || r.MaxOperations > 4096 {
		return errors.New("invalid permit request")
	}
	if !validPermitHolder(Permit{HolderDeviceID: r.HolderDeviceID, HolderGeneration: r.HolderGeneration, HolderRole: r.HolderRole, SenderDeviceID: r.SenderDeviceID, SenderGeneration: r.SenderGeneration, RecipientDeviceID: r.RecipientDeviceID, RecipientGeneration: r.RecipientGeneration}) {
		return errors.New("invalid permit request holder")
	}
	return nil
}

// SignPermitRequest signs the immutable requested capability with the active
// holder device key.
func SignPermitRequest(request *PermitRequest, private ed25519.PrivateKey) error {
	if request == nil || len(private) != ed25519.PrivateKeySize || validatePermitRequest(*request) != nil {
		return errors.New("invalid permit request signer")
	}
	payload, err := request.signedBytes()
	if err != nil {
		return err
	}
	copy(request.Signature[:], ed25519.Sign(private, payload))
	return nil
}

// PermitIssuanceAuthority is one fresh directory view used for both holder
// request verification and the newly minted permit's root-authorized fields.
type PermitIssuanceAuthority interface {
	PermitAuthorityResolver
	OperationHolderResolver
	CurrentPermitIssuerKey([32]byte) (ed25519.PublicKey, error)
	CurrentPermitBinding(time.Time) (DirectoryPermitBinding, error)
}

// PermitIssuerOptions provide the non-secret issuer identity plus the private
// signing key and explicit, server-side resource limits.
type PermitIssuerOptions struct {
	Ledger        *SQLitePermitLedger
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

// PermitIssuer mints bounded, fresh-directory-bound permits for holder-signed
// requests. It has no HTTP surface; the daemon must still authenticate and
// obtain a fresh authority before calling Issue.
type PermitIssuer struct {
	ledger        *SQLitePermitLedger
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

// NewPermitIssuer creates an issuer that never grants an implicit default
// quota. Operators must choose every bound explicitly.
func NewPermitIssuer(options PermitIssuerOptions) (*PermitIssuer, error) {
	if options.Ledger == nil || isZero32(options.IssuerKeyID) || len(options.PrivateKey) != ed25519.PrivateKeySize || options.MaxLifetime <= 0 || options.MaxLifetime > 60*time.Second || options.MaxBytes == 0 || options.MaxBytes > 64<<20 || options.MaxChunks == 0 || options.MaxChunks > 4096 || options.MaxOperations == 0 || options.MaxOperations > 4096 || options.MaxActive == 0 || options.MaxActive > 4096 {
		return nil, errors.New("invalid permit issuer configuration")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	return &PermitIssuer{ledger: options.Ledger, issuerKeyID: options.IssuerKeyID, privateKey: append(ed25519.PrivateKey(nil), options.PrivateKey...), maxLifetime: options.MaxLifetime, maxBytes: options.MaxBytes, maxChunks: options.MaxChunks, maxOperations: options.MaxOperations, maxActive: options.MaxActive, now: options.Now, random: options.Random}, nil
}

// Issue verifies a signed request against a fresh directory, derives the
// directory fields itself, signs a bounded permit, and durably returns the
// exact prior permit for an identical issuance retry.
func (i *PermitIssuer) Issue(ctx context.Context, request PermitRequest, authority PermitIssuanceAuthority) (Permit, bool, error) {
	if i == nil || authority == nil || validatePermitRequest(request) != nil {
		return Permit{}, false, errors.New("invalid permit issuance")
	}
	now := i.now().UTC()
	nowUnix := now.Unix()
	if nowUnix < 0 || request.IssuedAt > uint64(nowUnix) || request.ExpiresAt <= uint64(nowUnix) {
		return Permit{}, false, errors.New("expired permit request")
	}
	holder, err := authority.CurrentDeviceSigningKey(request.HolderDeviceID, request.HolderGeneration)
	if err != nil || len(holder) != ed25519.PublicKeySize {
		return Permit{}, false, errors.New("unknown permit request holder")
	}
	payload, err := request.signedBytes()
	if err != nil || !ed25519.Verify(holder, payload, request.Signature[:]) {
		return Permit{}, false, errors.New("invalid permit request signature")
	}
	binding, err := authority.CurrentPermitBinding(now)
	if err != nil {
		return Permit{}, false, errors.New("fresh permit directory authority is unavailable")
	}
	issuer, err := authority.CurrentPermitIssuerKey(i.issuerKeyID)
	if err != nil || !bytes.Equal(issuer, i.privateKey.Public().(ed25519.PublicKey)) {
		return Permit{}, false, errors.New("permit issuer is not directory-authorized")
	}
	issuerExpiry := now.Add(i.maxLifetime).Unix()
	if issuerExpiry < 0 {
		return Permit{}, false, errors.New("invalid issuer clock")
	}
	expiresAt := minPermitExpiry(request.ExpiresAt, binding.ExpiresAt, uint64(issuerExpiry))
	if expiresAt <= uint64(nowUnix) || request.MaxBytes > i.maxBytes || request.MaxChunks > i.maxChunks || request.MaxOperations > i.maxOperations {
		return Permit{}, false, errors.New("permit request exceeds issuer policy")
	}
	previous, found, err := i.ledger.LoadIssuedForRequest(ctx, request)
	if err != nil {
		return Permit{}, false, err
	}
	if found && VerifyPermit(previous, authority, now) == nil {
		return previous, true, nil
	}
	for attempts := 0; attempts < 8; attempts++ {
		var serial [16]byte
		if _, err := io.ReadFull(i.random, serial[:]); err != nil || isZero16(serial) {
			return Permit{}, false, errors.New("generate permit serial")
		}
		permit := Permit{Audience: binding.Audience, Serial: serial, IssuerKeyID: i.issuerKeyID, HolderDeviceID: request.HolderDeviceID, HolderGeneration: request.HolderGeneration, HolderRole: request.HolderRole, TransferID: request.TransferID, ConversationID: request.ConversationID, SenderDeviceID: request.SenderDeviceID, SenderGeneration: request.SenderGeneration, RecipientDeviceID: request.RecipientDeviceID, RecipientGeneration: request.RecipientGeneration, AttemptGeneration: request.AttemptGeneration, Operation: request.Operation, DirectoryHead: binding.DirectoryHead, MembershipCommitment: request.MembershipCommitment, RevocationEpoch: binding.RevocationEpoch, IssuedAt: uint64(nowUnix), ExpiresAt: expiresAt, MaxBytes: request.MaxBytes, MaxChunks: request.MaxChunks, MaxOperations: request.MaxOperations}
		if err := SignPermit(&permit, i.privateKey); err != nil {
			return Permit{}, false, err
		}
		if err := VerifyPermit(permit, authority, now); err != nil {
			return Permit{}, false, errors.New("issuer generated an invalid permit")
		}
		if found {
			refreshed, refreshErr := i.ledger.RefreshIssuedForRequest(ctx, request, previous, permit)
			if refreshErr == nil && refreshed {
				return permit, false, nil
			}
			if refreshErr != nil && !errors.Is(refreshErr, errPermitSerialCollision) {
				return Permit{}, false, refreshErr
			}
		} else {
			stored, replayed, issueErr := i.ledger.IssueForRequestBounded(ctx, request, permit, i.maxActive, now)
			if issueErr == nil {
				return stored, replayed, nil
			}
			if !errors.Is(issueErr, errPermitSerialCollision) {
				if prior, lookupFound, lookupErr := i.ledger.LoadIssuedForRequest(ctx, request); lookupErr == nil && lookupFound && VerifyPermit(prior, authority, now) == nil {
					return prior, true, nil
				}
				return Permit{}, false, issueErr
			}
		}
		if prior, lookupFound, lookupErr := i.ledger.LoadIssuedForRequest(ctx, request); lookupErr == nil && lookupFound && VerifyPermit(prior, authority, now) == nil {
			return prior, true, nil
		}
	}
	return Permit{}, false, errors.New("permit serial collision limit exceeded")
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

// EncodePermitRequest serializes the complete canonical holder request.
func EncodePermitRequest(request PermitRequest) ([]byte, error) {
	if err := validatePermitRequest(request); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(request.wire())
}

// DecodePermitRequest accepts only a canonical complete holder request.
func DecodePermitRequest(raw []byte) (PermitRequest, error) {
	if len(raw) == 0 || len(raw) > maxPermitEncodedBytes {
		return PermitRequest{}, errors.New("invalid permit request")
	}
	var wire permitRequestWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil || wire.Version != protocolVersion {
		return PermitRequest{}, errors.New("invalid permit request")
	}
	request := PermitRequest{RequestID: wire.RequestID, HolderDeviceID: wire.HolderDeviceID, HolderGeneration: wire.HolderGeneration, HolderRole: wire.HolderRole, TransferID: wire.TransferID, ConversationID: wire.ConversationID, SenderDeviceID: wire.SenderDeviceID, SenderGeneration: wire.SenderGeneration, RecipientDeviceID: wire.RecipientDeviceID, RecipientGeneration: wire.RecipientGeneration, AttemptGeneration: wire.AttemptGeneration, Operation: wire.Operation, MembershipCommitment: wire.MembershipCommitment, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt, MaxBytes: wire.MaxBytes, MaxChunks: wire.MaxChunks, MaxOperations: wire.MaxOperations, Signature: wire.Signature}
	canonical, err := EncodePermitRequest(request)
	if err != nil || !bytes.Equal(raw, canonical) {
		return PermitRequest{}, fmt.Errorf("invalid permit request")
	}
	return request, nil
}
