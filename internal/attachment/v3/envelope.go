package v3

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/zeebo/blake3"
)

const (
	envelopeSignatureDomain = "punaro/attachment/envelope/v3\x00"
	maxEnvelopeEncodedBytes = 16 << 10
	hpkeKEMID               = 0x0020
	hpkeKDFID               = 0x0001
	hpkeAEADID              = 0x0003
)

// Envelope is the immutable recipient record carried by a v3 offer. Its
// signature is verified against the fresh manifest signer at offer admission;
// its HPKE open/seal lifecycle is deliberately separate from this strict wire
// decoder.
type Envelope struct {
	Audience            [32]byte
	TransferID          [16]byte
	ConversationID      [16]byte
	SenderDeviceID      [16]byte
	SenderGeneration    uint64
	RecipientDeviceID   [16]byte
	RecipientGeneration uint64
	RecipientHPKEKeyID  [32]byte
	ManifestCommitment  [32]byte
	EncapsulatedKey     [32]byte
	Ciphertext          []byte
	SignerKeyID         [32]byte
	Signature           [ed25519.SignatureSize]byte
}

type envelopeWire struct {
	Version             uint64                      `cbor:"1,keyasint"`
	Audience            [32]byte                    `cbor:"2,keyasint"`
	TransferID          [16]byte                    `cbor:"3,keyasint"`
	ConversationID      [16]byte                    `cbor:"4,keyasint"`
	SenderDeviceID      [16]byte                    `cbor:"5,keyasint"`
	SenderGeneration    uint64                      `cbor:"6,keyasint"`
	RecipientDeviceID   [16]byte                    `cbor:"7,keyasint"`
	RecipientGeneration uint64                      `cbor:"8,keyasint"`
	RecipientHPKEKeyID  [32]byte                    `cbor:"9,keyasint"`
	ManifestCommitment  [32]byte                    `cbor:"10,keyasint"`
	KEMID               uint64                      `cbor:"11,keyasint"`
	KDFID               uint64                      `cbor:"12,keyasint"`
	AEADID              uint64                      `cbor:"13,keyasint"`
	EncapsulatedKey     [32]byte                    `cbor:"14,keyasint"`
	Ciphertext          []byte                      `cbor:"15,keyasint"`
	SignerKeyID         [32]byte                    `cbor:"16,keyasint"`
	SignatureAlgorithm  uint64                      `cbor:"17,keyasint"`
	Signature           [ed25519.SignatureSize]byte `cbor:"99,keyasint"`
}

func (e Envelope) wire() envelopeWire {
	return envelopeWire{Version: protocolVersion, Audience: e.Audience, TransferID: e.TransferID, ConversationID: e.ConversationID, SenderDeviceID: e.SenderDeviceID, SenderGeneration: e.SenderGeneration, RecipientDeviceID: e.RecipientDeviceID, RecipientGeneration: e.RecipientGeneration, RecipientHPKEKeyID: e.RecipientHPKEKeyID, ManifestCommitment: e.ManifestCommitment, KEMID: hpkeKEMID, KDFID: hpkeKDFID, AEADID: hpkeAEADID, EncapsulatedKey: e.EncapsulatedKey, Ciphertext: append([]byte(nil), e.Ciphertext...), SignerKeyID: e.SignerKeyID, SignatureAlgorithm: 1, Signature: e.Signature}
}

func (e Envelope) signedBytes() ([]byte, error) {
	raw, err := canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: e.Audience, 3: e.TransferID, 4: e.ConversationID, 5: e.SenderDeviceID, 6: e.SenderGeneration, 7: e.RecipientDeviceID, 8: e.RecipientGeneration, 9: e.RecipientHPKEKeyID, 10: e.ManifestCommitment, 11: uint64(hpkeKEMID), 12: uint64(hpkeKDFID), 13: uint64(hpkeAEADID), 14: e.EncapsulatedKey, 15: e.Ciphertext, 16: e.SignerKeyID, 17: uint64(1)})
	return append([]byte(envelopeSignatureDomain), raw...), err
}

func validateEnvelope(e Envelope) error {
	if e.Audience == [32]byte{} || e.TransferID == [16]byte{} || e.ConversationID == [16]byte{} || e.SenderDeviceID == [16]byte{} || e.SenderGeneration == 0 || e.RecipientDeviceID == [16]byte{} || e.RecipientGeneration == 0 || e.RecipientHPKEKeyID == [32]byte{} || e.ManifestCommitment == [32]byte{} || e.SignerKeyID == [32]byte{} || len(e.Ciphertext) < 16 || len(e.Ciphertext) > 256 {
		return errors.New("invalid v3 envelope")
	}
	return nil
}

func manifestCommitment(raw []byte) [32]byte { return blake3.Sum256(raw) }

func sameEnvelopeManifestBinding(e Envelope, m Manifest, raw []byte) bool {
	return e.Audience == m.Audience && e.TransferID == m.TransferID && e.ConversationID == m.ConversationID && e.SenderDeviceID == m.SenderDeviceID && e.SenderGeneration == m.SenderGeneration && e.RecipientDeviceID == m.RecipientDeviceID && e.RecipientGeneration == m.RecipientGeneration && e.ManifestCommitment == manifestCommitment(raw) && e.SignerKeyID == m.SignerKeyID
}

func SignEnvelope(e *Envelope, private ed25519.PrivateKey) error {
	if e == nil || len(private) != ed25519.PrivateKeySize || validateEnvelope(*e) != nil {
		return errors.New("invalid v3 envelope signer")
	}
	payload, err := e.signedBytes()
	if err != nil {
		return err
	}
	copy(e.Signature[:], ed25519.Sign(private, payload))
	return nil
}

func EncodeEnvelope(e Envelope) ([]byte, error) {
	if err := validateEnvelope(e); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(e.wire())
}

func DecodeEnvelope(raw []byte) (Envelope, error) {
	if len(raw) == 0 || len(raw) > maxEnvelopeEncodedBytes {
		return Envelope{}, errors.New("invalid v3 envelope size")
	}
	var wire envelopeWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil {
		return Envelope{}, fmt.Errorf("decode v3 envelope: %w", err)
	}
	if wire.Version != protocolVersion || wire.KEMID != hpkeKEMID || wire.KDFID != hpkeKDFID || wire.AEADID != hpkeAEADID || wire.SignatureAlgorithm != 1 {
		return Envelope{}, errors.New("unsupported v3 envelope algorithm")
	}
	e := Envelope{Audience: wire.Audience, TransferID: wire.TransferID, ConversationID: wire.ConversationID, SenderDeviceID: wire.SenderDeviceID, SenderGeneration: wire.SenderGeneration, RecipientDeviceID: wire.RecipientDeviceID, RecipientGeneration: wire.RecipientGeneration, RecipientHPKEKeyID: wire.RecipientHPKEKeyID, ManifestCommitment: wire.ManifestCommitment, EncapsulatedKey: wire.EncapsulatedKey, Ciphertext: append([]byte(nil), wire.Ciphertext...), SignerKeyID: wire.SignerKeyID, Signature: wire.Signature}
	if err := validateEnvelope(e); err != nil {
		return Envelope{}, err
	}
	canonical, err := EncodeEnvelope(e)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Envelope{}, errors.New("non-canonical v3 envelope")
	}
	return e, nil
}
