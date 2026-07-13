// Package v2 implements the offline, fail-closed Attachment v2 protocol core.
// It must not be mounted by punarod until every release gate is satisfied.
package v2

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	protocolVersion         = 2
	maxManifestEncodedBytes = 4 << 10
	manifestSignatureDomain = "punaro/attachment/manifest/v2\x00"
)

var (
	canonicalEncoding cbor.EncMode
	strictDecoding    cbor.DecMode
)

func init() {
	options := cbor.CoreDetEncOptions()
	options.TagsMd = cbor.TagsForbidden
	var err error
	canonicalEncoding, err = options.EncMode()
	if err != nil {
		panic(fmt.Sprintf("configure canonical CBOR: %v", err))
	}
	strictDecoding, err = (cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   4,
		MaxArrayElements:  16,
		MaxMapPairs:       32,
	}).DecMode()
	if err != nil {
		panic(fmt.Sprintf("configure strict CBOR: %v", err))
	}
}

// Manifest is the signed, immutable record described by the v2 RFC.
type Manifest struct {
	Audience             [32]byte
	TransferID           [16]byte
	ConversationID       [16]byte
	SenderDeviceID       [16]byte
	SenderGeneration     uint64
	RecipientDeviceID    [16]byte
	RecipientGeneration  uint64
	DirectoryHead        [32]byte
	MembershipCommitment [32]byte
	RevocationEpoch      uint64
	IssuedAt             uint64
	ExpiresAt            uint64
	ContentSalt          [32]byte
	PlaintextCommitment  [32]byte
	ChunkSize            uint64
	ChunkCount           uint64
	PlaintextSize        uint64
	SignerKeyID          [32]byte
	Signature            [ed25519.SignatureSize]byte
}

type manifestWire struct {
	Version              uint64                      `cbor:"1,keyasint"`
	Audience             [32]byte                    `cbor:"2,keyasint"`
	TransferID           [16]byte                    `cbor:"3,keyasint"`
	ConversationID       [16]byte                    `cbor:"4,keyasint"`
	SenderDeviceID       [16]byte                    `cbor:"5,keyasint"`
	SenderGeneration     uint64                      `cbor:"6,keyasint"`
	RecipientDeviceID    [16]byte                    `cbor:"7,keyasint"`
	RecipientGeneration  uint64                      `cbor:"8,keyasint"`
	DirectoryHead        [32]byte                    `cbor:"9,keyasint"`
	MembershipCommitment [32]byte                    `cbor:"10,keyasint"`
	RevocationEpoch      uint64                      `cbor:"11,keyasint"`
	IssuedAt             uint64                      `cbor:"12,keyasint"`
	ExpiresAt            uint64                      `cbor:"13,keyasint"`
	ContentSalt          [32]byte                    `cbor:"14,keyasint"`
	PlaintextCommitment  [32]byte                    `cbor:"15,keyasint"`
	ChunkSize            uint64                      `cbor:"16,keyasint"`
	ChunkCount           uint64                      `cbor:"17,keyasint"`
	PlaintextSize        uint64                      `cbor:"18,keyasint"`
	SignerKeyID          [32]byte                    `cbor:"19,keyasint"`
	SignatureAlgorithm   uint64                      `cbor:"20,keyasint"`
	Signature            [ed25519.SignatureSize]byte `cbor:"99,keyasint"`
}

func (m Manifest) wire() manifestWire {
	return manifestWire{Version: protocolVersion, Audience: m.Audience, TransferID: m.TransferID, ConversationID: m.ConversationID, SenderDeviceID: m.SenderDeviceID, SenderGeneration: m.SenderGeneration, RecipientDeviceID: m.RecipientDeviceID, RecipientGeneration: m.RecipientGeneration, DirectoryHead: m.DirectoryHead, MembershipCommitment: m.MembershipCommitment, RevocationEpoch: m.RevocationEpoch, IssuedAt: m.IssuedAt, ExpiresAt: m.ExpiresAt, ContentSalt: m.ContentSalt, PlaintextCommitment: m.PlaintextCommitment, ChunkSize: m.ChunkSize, ChunkCount: m.ChunkCount, PlaintextSize: m.PlaintextSize, SignerKeyID: m.SignerKeyID, SignatureAlgorithm: 1, Signature: m.Signature}
}

func (m Manifest) signedBytes() ([]byte, error) {
	encoded, err := canonicalEncoding.Marshal(manifestSigningMap(m))
	return append([]byte(manifestSignatureDomain), encoded...), err
}

func manifestSigningMap(m Manifest) map[uint64]any {
	return map[uint64]any{1: uint64(protocolVersion), 2: m.Audience, 3: m.TransferID, 4: m.ConversationID, 5: m.SenderDeviceID, 6: m.SenderGeneration, 7: m.RecipientDeviceID, 8: m.RecipientGeneration, 9: m.DirectoryHead, 10: m.MembershipCommitment, 11: m.RevocationEpoch, 12: m.IssuedAt, 13: m.ExpiresAt, 14: m.ContentSalt, 15: m.PlaintextCommitment, 16: m.ChunkSize, 17: m.ChunkCount, 18: m.PlaintextSize, 19: m.SignerKeyID, 20: uint64(1)}
}

func validateManifest(m Manifest) error {
	if isZero16(m.TransferID) || isZero16(m.ConversationID) || isZero16(m.SenderDeviceID) || isZero16(m.RecipientDeviceID) || isZero32(m.Audience) || isZero32(m.DirectoryHead) || isZero32(m.MembershipCommitment) || isZero32(m.ContentSalt) || isZero32(m.PlaintextCommitment) || isZero32(m.SignerKeyID) {
		return errors.New("missing manifest binding")
	}
	if m.SenderGeneration == 0 || m.RecipientGeneration == 0 || m.ExpiresAt <= m.IssuedAt || m.ChunkSize == 0 || m.ChunkSize > 256<<10 || m.ChunkCount == 0 || m.ChunkCount > 4096 || m.PlaintextSize > 64<<20 {
		return errors.New("invalid manifest bounds")
	}
	fullChunksBeforeLast := m.ChunkSize * (m.ChunkCount - 1)
	if m.PlaintextSize == 0 && m.ChunkCount == 1 {
		return nil
	}
	if m.PlaintextSize <= fullChunksBeforeLast || m.PlaintextSize > m.ChunkSize*m.ChunkCount {
		return errors.New("inconsistent manifest chunk geometry")
	}
	return nil
}

func isZero16(value [16]byte) bool { return value == [16]byte{} }
func isZero32(value [32]byte) bool { return value == [32]byte{} }

// SignManifest validates and signs an immutable manifest with an Ed25519 key.
func SignManifest(m *Manifest, private ed25519.PrivateKey) error {
	if m == nil || len(private) != ed25519.PrivateKeySize {
		return errors.New("invalid manifest signer")
	}
	if err := validateManifest(*m); err != nil {
		return err
	}
	payload, err := m.signedBytes()
	if err != nil {
		return err
	}
	copy(m.Signature[:], ed25519.Sign(private, payload))
	return nil
}

// VerifyManifest checks an Ed25519 signature after validating manifest bounds.
func VerifyManifest(m Manifest, public ed25519.PublicKey) bool {
	if len(public) != ed25519.PublicKeySize || validateManifest(m) != nil {
		return false
	}
	payload, err := m.signedBytes()
	return err == nil && ed25519.Verify(public, payload, m.Signature[:])
}

// EncodeManifest serializes a complete manifest with canonical CBOR.
func EncodeManifest(m Manifest) ([]byte, error) {
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(m.wire())
}

// DecodeManifest accepts only a complete, strict, canonical manifest record.
func DecodeManifest(raw []byte) (Manifest, error) {
	if len(raw) == 0 || len(raw) > maxManifestEncodedBytes {
		return Manifest{}, errors.New("invalid manifest size")
	}
	var wire manifestWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if wire.Version != protocolVersion || wire.SignatureAlgorithm != 1 {
		return Manifest{}, errors.New("unsupported manifest algorithm")
	}
	m := Manifest{Audience: wire.Audience, TransferID: wire.TransferID, ConversationID: wire.ConversationID, SenderDeviceID: wire.SenderDeviceID, SenderGeneration: wire.SenderGeneration, RecipientDeviceID: wire.RecipientDeviceID, RecipientGeneration: wire.RecipientGeneration, DirectoryHead: wire.DirectoryHead, MembershipCommitment: wire.MembershipCommitment, RevocationEpoch: wire.RevocationEpoch, IssuedAt: wire.IssuedAt, ExpiresAt: wire.ExpiresAt, ContentSalt: wire.ContentSalt, PlaintextCommitment: wire.PlaintextCommitment, ChunkSize: wire.ChunkSize, ChunkCount: wire.ChunkCount, PlaintextSize: wire.PlaintextSize, SignerKeyID: wire.SignerKeyID, Signature: wire.Signature}
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	canonical, err := EncodeManifest(m)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Manifest{}, errors.New("non-canonical manifest")
	}
	return m, nil
}
