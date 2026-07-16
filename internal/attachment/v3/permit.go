package v3

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	maxPermitEncodedBytes              = 4 << 10
	maxPermitCiphertextBytes           = 64<<20 + 4096*16
	permitSignatureDomain              = "punaro/attachment/permit/v3\x00"
	permitHolderSender          uint64 = 1
	permitHolderRecipient       uint64 = 2
	permitOperationSourceInit   uint64 = 1
	permitOperationSourceUpload uint64 = 2
	permitOperationOffer        uint64 = 3
	permitOperationAccept       uint64 = 4
	permitOperationDownload     uint64 = 5
	permitOperationBegin        uint64 = 6
	permitOperationComplete     uint64 = 7
	permitOperationCancel       uint64 = 8
	permitOperationOutcome      uint64 = 9
)

// Public protocol identifiers let adapters construct holder-signed requests
// without duplicating wire numbers. They are intentionally values, not open
// extension points: validation still rejects every unknown operation.
const (
	PermitHolderSender    = permitHolderSender
	PermitHolderRecipient = permitHolderRecipient

	PermitOperationSourceInit   = permitOperationSourceInit
	PermitOperationSourceUpload = permitOperationSourceUpload
	PermitOperationOffer        = permitOperationOffer
	PermitOperationAccept       = permitOperationAccept
	PermitOperationDownload     = permitOperationDownload
	PermitOperationBegin        = permitOperationBegin
	PermitOperationComplete     = permitOperationComplete
	PermitOperationCancel       = permitOperationCancel
	PermitOperationOutcome      = permitOperationOutcome
)

// PermitAuthorityResolver fresh-validates the audience, issuer key, directory
// head, membership, active device generations, revocation epoch and expiry.
type PermitAuthorityResolver interface {
	ValidatePermitAuthority(Permit, time.Time) (ed25519.PublicKey, error)
}
type Permit struct {
	Audience                 [32]byte
	Serial                   [16]byte
	IssuerKeyID              [32]byte
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
	DirectoryHead            [32]byte
	MembershipCommitment     [32]byte
	RevocationEpoch          uint64
	IssuedAt                 uint64
	ExpiresAt                uint64
	MaxBytes                 uint64
	MaxChunks                uint64
	MaxOperations            uint64
	StagedManifestCommitment [32]byte
	// OutcomeOfSerial binds an outcome query to the exact expired operation it
	// reconciles. It is populated only for PermitOperationOutcome.
	OutcomeOfSerial [16]byte
	Signature       [ed25519.SignatureSize]byte
}
type permitWire struct {
	Version                  uint64                      `cbor:"1,keyasint"`
	Audience                 [32]byte                    `cbor:"2,keyasint"`
	Serial                   [16]byte                    `cbor:"3,keyasint"`
	IssuerKeyID              [32]byte                    `cbor:"4,keyasint"`
	HolderDeviceID           [16]byte                    `cbor:"5,keyasint"`
	HolderGeneration         uint64                      `cbor:"6,keyasint"`
	HolderRole               uint64                      `cbor:"7,keyasint"`
	TransferID               [16]byte                    `cbor:"8,keyasint"`
	ConversationID           [16]byte                    `cbor:"9,keyasint"`
	SenderDeviceID           [16]byte                    `cbor:"10,keyasint"`
	SenderGeneration         uint64                      `cbor:"11,keyasint"`
	RecipientDeviceID        [16]byte                    `cbor:"12,keyasint"`
	RecipientGeneration      uint64                      `cbor:"13,keyasint"`
	AttemptGeneration        uint64                      `cbor:"14,keyasint"`
	Operation                uint64                      `cbor:"15,keyasint"`
	DirectoryHead            [32]byte                    `cbor:"16,keyasint"`
	MembershipCommitment     [32]byte                    `cbor:"17,keyasint"`
	RevocationEpoch          uint64                      `cbor:"18,keyasint"`
	IssuedAt                 uint64                      `cbor:"19,keyasint"`
	ExpiresAt                uint64                      `cbor:"20,keyasint"`
	MaxBytes                 uint64                      `cbor:"21,keyasint"`
	MaxChunks                uint64                      `cbor:"22,keyasint"`
	MaxOperations            uint64                      `cbor:"23,keyasint"`
	StagedManifestCommitment [32]byte                    `cbor:"24,keyasint"`
	OutcomeOfSerial          [16]byte                    `cbor:"25,keyasint"`
	Signature                [ed25519.SignatureSize]byte `cbor:"99,keyasint"`
}

func (p Permit) wire() permitWire {
	return permitWire{Version: protocolVersion, Audience: p.Audience, Serial: p.Serial, IssuerKeyID: p.IssuerKeyID, HolderDeviceID: p.HolderDeviceID, HolderGeneration: p.HolderGeneration, HolderRole: p.HolderRole, TransferID: p.TransferID, ConversationID: p.ConversationID, SenderDeviceID: p.SenderDeviceID, SenderGeneration: p.SenderGeneration, RecipientDeviceID: p.RecipientDeviceID, RecipientGeneration: p.RecipientGeneration, AttemptGeneration: p.AttemptGeneration, Operation: p.Operation, DirectoryHead: p.DirectoryHead, MembershipCommitment: p.MembershipCommitment, RevocationEpoch: p.RevocationEpoch, IssuedAt: p.IssuedAt, ExpiresAt: p.ExpiresAt, MaxBytes: p.MaxBytes, MaxChunks: p.MaxChunks, MaxOperations: p.MaxOperations, StagedManifestCommitment: p.StagedManifestCommitment, OutcomeOfSerial: p.OutcomeOfSerial, Signature: p.Signature}
}
func (p Permit) signedBytes() ([]byte, error) {
	raw, err := canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: p.Audience, 3: p.Serial, 4: p.IssuerKeyID, 5: p.HolderDeviceID, 6: p.HolderGeneration, 7: p.HolderRole, 8: p.TransferID, 9: p.ConversationID, 10: p.SenderDeviceID, 11: p.SenderGeneration, 12: p.RecipientDeviceID, 13: p.RecipientGeneration, 14: p.AttemptGeneration, 15: p.Operation, 16: p.DirectoryHead, 17: p.MembershipCommitment, 18: p.RevocationEpoch, 19: p.IssuedAt, 20: p.ExpiresAt, 21: p.MaxBytes, 22: p.MaxChunks, 23: p.MaxOperations, 24: p.StagedManifestCommitment, 25: p.OutcomeOfSerial})
	return append([]byte(permitSignatureDomain), raw...), err
}
func validatePermit(p Permit) error {
	if p.Audience == [32]byte{} || p.Serial == [16]byte{} || p.IssuerKeyID == [32]byte{} || p.HolderDeviceID == [16]byte{} || p.TransferID == [16]byte{} || p.ConversationID == [16]byte{} || p.SenderDeviceID == [16]byte{} || p.RecipientDeviceID == [16]byte{} || p.DirectoryHead == [32]byte{} || p.MembershipCommitment == [32]byte{} || p.StagedManifestCommitment == [32]byte{} || p.HolderGeneration == 0 || p.SenderGeneration == 0 || p.RecipientGeneration == 0 || p.HolderRole < permitHolderSender || p.HolderRole > permitHolderRecipient || p.Operation < permitOperationSourceInit || p.Operation > permitOperationOutcome || p.IssuedAt > math.MaxInt64 || p.ExpiresAt > math.MaxInt64 || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > 30 || p.MaxBytes > maxPermitCiphertextBytes || p.MaxChunks > 4096 || p.MaxOperations == 0 || p.MaxOperations > 4096 || (p.Operation == permitOperationOutcome && p.OutcomeOfSerial == [16]byte{}) || (p.Operation != permitOperationOutcome && p.OutcomeOfSerial != [16]byte{}) {
		return errors.New("invalid v3 permit")
	}
	if p.HolderRole == permitHolderSender && (p.HolderDeviceID != p.SenderDeviceID || p.HolderGeneration != p.SenderGeneration) {
		return errors.New("invalid sender permit holder")
	}
	if p.HolderRole == permitHolderRecipient && (p.HolderDeviceID != p.RecipientDeviceID || p.HolderGeneration != p.RecipientGeneration) {
		return errors.New("invalid recipient permit holder")
	}
	if !validPermitOperation(p) {
		return errors.New("invalid permit operation binding")
	}
	return nil
}

func validPermitOperation(p Permit) bool {
	switch p.Operation {
	case permitOperationSourceInit, permitOperationSourceUpload, permitOperationOffer, permitOperationCancel:
		return p.HolderRole == permitHolderSender && p.AttemptGeneration == 0
	case permitOperationAccept:
		return p.HolderRole == permitHolderRecipient && p.AttemptGeneration == 0
	case permitOperationBegin, permitOperationDownload, permitOperationComplete:
		return p.HolderRole == permitHolderRecipient && p.AttemptGeneration == 1
	case permitOperationOutcome:
		return (p.HolderRole == permitHolderSender || p.HolderRole == permitHolderRecipient) && p.AttemptGeneration == 0
	default:
		return false
	}
}
func SignPermit(p *Permit, private ed25519.PrivateKey) error {
	if p == nil || len(private) != ed25519.PrivateKeySize || validatePermit(*p) != nil {
		return errors.New("invalid permit signer")
	}
	raw, err := p.signedBytes()
	if err != nil {
		return err
	}
	copy(p.Signature[:], ed25519.Sign(private, raw))
	return nil
}
func VerifyPermit(p Permit, authority PermitAuthorityResolver, now time.Time) error {
	if authority == nil || validatePermit(p) != nil {
		return errors.New("invalid permit")
	}
	seconds := now.UTC().Unix()
	if seconds < 0 || p.IssuedAt > uint64(seconds) || p.ExpiresAt <= uint64(seconds) {
		return errors.New("expired permit")
	}
	key, err := authority.ValidatePermitAuthority(p, now)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("unknown permit issuer")
	}
	raw, err := p.signedBytes()
	if err != nil || !ed25519.Verify(key, raw, p.Signature[:]) {
		return errors.New("invalid permit signature")
	}
	return nil
}
func EncodePermit(p Permit) ([]byte, error) {
	if err := validatePermit(p); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(p.wire())
}
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
	p := Permit{Audience: wire.Audience, Serial: wire.Serial, IssuerKeyID: wire.IssuerKeyID, HolderDeviceID: wire.HolderDeviceID, HolderGeneration: wire.HolderGeneration, HolderRole: wire.HolderRole, TransferID: wire.TransferID, ConversationID: wire.ConversationID, SenderDeviceID: wire.SenderDeviceID, SenderGeneration: wire.SenderGeneration, RecipientDeviceID: wire.RecipientDeviceID, RecipientGeneration: wire.RecipientGeneration, AttemptGeneration: wire.AttemptGeneration, Operation: wire.Operation, DirectoryHead: wire.DirectoryHead, MembershipCommitment: wire.MembershipCommitment, RevocationEpoch: wire.RevocationEpoch, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt, MaxBytes: wire.MaxBytes, MaxChunks: wire.MaxChunks, MaxOperations: wire.MaxOperations, StagedManifestCommitment: wire.StagedManifestCommitment, OutcomeOfSerial: wire.OutcomeOfSerial, Signature: wire.Signature}
	if err := validatePermit(p); err != nil {
		return Permit{}, err
	}
	canonical, err := EncodePermit(p)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Permit{}, errors.New("non-canonical permit")
	}
	return p, nil
}
