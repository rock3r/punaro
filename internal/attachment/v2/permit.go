package v2

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

const (
	maxPermitEncodedBytes = 4 << 10
	permitSignatureDomain = "punaro/attachment/permit/v2\x00"

	// PermitHolderSender authorizes the source device role.
	PermitHolderSender uint64 = 1
	// PermitHolderRecipient authorizes the recipient device role.
	PermitHolderRecipient uint64 = 2
	// PermitHolderRelay authorizes the relay role.
	PermitHolderRelay uint64 = 3

	// PermitOperationOffer authorizes offer creation.
	PermitOperationOffer uint64 = 1
	// PermitOperationAccept authorizes acceptance.
	PermitOperationAccept uint64 = 2
	// PermitOperationUpload authorizes ciphertext upload.
	PermitOperationUpload uint64 = 3
	// PermitOperationDownload authorizes ciphertext download.
	PermitOperationDownload uint64 = 4
	// PermitOperationSignal authorizes bounded transport signaling.
	PermitOperationSignal uint64 = 5
	// PermitOperationComplete authorizes completion acknowledgement.
	PermitOperationComplete uint64 = 6
)

var errUnknownPermitIssuer = errors.New("unknown permit issuer")

// PermitAuthorityResolver validates every permit binding against one fresh,
// current root-signed directory snapshot before returning the issuer key. It
// must reject a stale directory, revoked membership or device, any superseded
// generation, and a permit that outlives its bound directory head.
type PermitAuthorityResolver interface {
	ValidatePermitAuthority(permit Permit, now time.Time) (ed25519.PublicKey, error)
}

// Permit is one short-lived, operation-specific relay authorization.
type Permit struct {
	Audience             [32]byte
	Serial               [16]byte
	IssuerKeyID          [32]byte
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
	DirectoryHead        [32]byte
	MembershipCommitment [32]byte
	RevocationEpoch      uint64
	IssuedAt             uint64
	ExpiresAt            uint64
	MaxBytes             uint64
	MaxChunks            uint64
	MaxOperations        uint64
	Signature            [ed25519.SignatureSize]byte
}

type permitWire struct {
	Version              uint64                      `cbor:"1,keyasint"`
	Audience             [32]byte                    `cbor:"2,keyasint"`
	Serial               [16]byte                    `cbor:"3,keyasint"`
	IssuerKeyID          [32]byte                    `cbor:"4,keyasint"`
	HolderDeviceID       [16]byte                    `cbor:"5,keyasint"`
	HolderGeneration     uint64                      `cbor:"6,keyasint"`
	HolderRole           uint64                      `cbor:"7,keyasint"`
	TransferID           [16]byte                    `cbor:"8,keyasint"`
	ConversationID       [16]byte                    `cbor:"9,keyasint"`
	SenderDeviceID       [16]byte                    `cbor:"10,keyasint"`
	SenderGeneration     uint64                      `cbor:"11,keyasint"`
	RecipientDeviceID    [16]byte                    `cbor:"12,keyasint"`
	RecipientGeneration  uint64                      `cbor:"13,keyasint"`
	AttemptGeneration    uint64                      `cbor:"14,keyasint"`
	Operation            uint64                      `cbor:"15,keyasint"`
	DirectoryHead        [32]byte                    `cbor:"16,keyasint"`
	MembershipCommitment [32]byte                    `cbor:"17,keyasint"`
	RevocationEpoch      uint64                      `cbor:"18,keyasint"`
	IssuedAt             uint64                      `cbor:"19,keyasint"`
	ExpiresAt            uint64                      `cbor:"20,keyasint"`
	MaxBytes             uint64                      `cbor:"21,keyasint"`
	MaxChunks            uint64                      `cbor:"22,keyasint"`
	MaxOperations        uint64                      `cbor:"23,keyasint"`
	Signature            [ed25519.SignatureSize]byte `cbor:"99,keyasint"`
}

func (p Permit) wire() permitWire {
	return permitWire{Version: protocolVersion, Audience: p.Audience, Serial: p.Serial, IssuerKeyID: p.IssuerKeyID, HolderDeviceID: p.HolderDeviceID, HolderGeneration: p.HolderGeneration, HolderRole: p.HolderRole, TransferID: p.TransferID, ConversationID: p.ConversationID, SenderDeviceID: p.SenderDeviceID, SenderGeneration: p.SenderGeneration, RecipientDeviceID: p.RecipientDeviceID, RecipientGeneration: p.RecipientGeneration, AttemptGeneration: p.AttemptGeneration, Operation: p.Operation, DirectoryHead: p.DirectoryHead, MembershipCommitment: p.MembershipCommitment, RevocationEpoch: p.RevocationEpoch, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt, MaxBytes: p.MaxBytes, MaxChunks: p.MaxChunks, MaxOperations: p.MaxOperations, Signature: p.Signature}
}

func (p Permit) signedBytes() ([]byte, error) {
	encoded, err := canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: p.Audience, 3: p.Serial, 4: p.IssuerKeyID, 5: p.HolderDeviceID, 6: p.HolderGeneration, 7: p.HolderRole, 8: p.TransferID, 9: p.ConversationID, 10: p.SenderDeviceID, 11: p.SenderGeneration, 12: p.RecipientDeviceID, 13: p.RecipientGeneration, 14: p.AttemptGeneration, 15: p.Operation, 16: p.DirectoryHead, 17: p.MembershipCommitment, 18: p.RevocationEpoch, 19: p.IssuedAt, 20: p.ExpiresAt, 21: p.MaxBytes, 22: p.MaxChunks, 23: p.MaxOperations})
	return append([]byte(permitSignatureDomain), encoded...), err
}

func validatePermit(p Permit) error {
	if isZero32(p.Audience) || isZero16(p.Serial) || isZero32(p.IssuerKeyID) || isZero16(p.HolderDeviceID) || isZero16(p.TransferID) || isZero16(p.ConversationID) || isZero16(p.SenderDeviceID) || isZero16(p.RecipientDeviceID) || isZero32(p.DirectoryHead) || isZero32(p.MembershipCommitment) {
		return errors.New("missing permit binding")
	}
	if p.HolderGeneration == 0 || p.HolderRole < PermitHolderSender || p.HolderRole > PermitHolderRelay || p.SenderGeneration == 0 || p.RecipientGeneration == 0 || p.AttemptGeneration == 0 || p.Operation < PermitOperationOffer || p.Operation > PermitOperationComplete || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > 60 || p.MaxBytes > 64<<20 || p.MaxChunks > 4096 || p.MaxOperations == 0 || p.MaxOperations > 4096 {
		return errors.New("invalid permit bounds")
	}
	return nil
}

// SignPermit validates and signs a relay permit with an authorized issuer key.
func SignPermit(p *Permit, private ed25519.PrivateKey) error {
	if p == nil || len(private) != ed25519.PrivateKeySize || validatePermit(*p) != nil {
		return errors.New("invalid permit signer")
	}
	payload, err := p.signedBytes()
	if err != nil {
		return err
	}
	copy(p.Signature[:], ed25519.Sign(private, payload))
	return nil
}

// VerifyPermit validates time, canonical bindings, the fresh issuer resolver,
// and the issuer signature. State-machine redemption is deliberately separate.
func VerifyPermit(p Permit, authority PermitAuthorityResolver, now time.Time) error {
	if authority == nil || validatePermit(p) != nil {
		return errors.New("invalid permit")
	}
	seconds := now.UTC().Unix()
	if seconds < 0 || p.IssuedAt > uint64(seconds) || p.ExpiresAt <= uint64(seconds) {
		return errors.New("expired permit")
	}
	issuer, err := authority.ValidatePermitAuthority(p, now)
	if err != nil || len(issuer) != ed25519.PublicKeySize {
		return errUnknownPermitIssuer
	}
	payload, err := p.signedBytes()
	if err != nil || !ed25519.Verify(issuer, payload, p.Signature[:]) {
		return errors.New("invalid permit signature")
	}
	return nil
}

// EncodePermit serializes a complete canonical permit.
func EncodePermit(p Permit) ([]byte, error) {
	if err := validatePermit(p); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(p.wire())
}

// DecodePermit accepts only a complete, strict, canonical permit record.
func DecodePermit(raw []byte) (Permit, error) {
	if len(raw) == 0 || len(raw) > maxPermitEncodedBytes {
		return Permit{}, errors.New("invalid permit size")
	}
	var wire permitWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil {
		return Permit{}, fmt.Errorf("decode permit: %w", err)
	}
	if wire.Version != protocolVersion {
		return Permit{}, errors.New("unsupported permit version")
	}
	p := Permit{Audience: wire.Audience, Serial: wire.Serial, IssuerKeyID: wire.IssuerKeyID, HolderDeviceID: wire.HolderDeviceID, HolderGeneration: wire.HolderGeneration, HolderRole: wire.HolderRole, TransferID: wire.TransferID, ConversationID: wire.ConversationID, SenderDeviceID: wire.SenderDeviceID, SenderGeneration: wire.SenderGeneration, RecipientDeviceID: wire.RecipientDeviceID, RecipientGeneration: wire.RecipientGeneration, AttemptGeneration: wire.AttemptGeneration, Operation: wire.Operation, DirectoryHead: wire.DirectoryHead, MembershipCommitment: wire.MembershipCommitment, RevocationEpoch: wire.RevocationEpoch, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt, MaxBytes: wire.MaxBytes, MaxChunks: wire.MaxChunks, MaxOperations: wire.MaxOperations, Signature: wire.Signature}
	if err := validatePermit(p); err != nil {
		return Permit{}, err
	}
	canonical, err := EncodePermit(p)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Permit{}, errors.New("non-canonical permit")
	}
	return p, nil
}
