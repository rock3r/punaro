package v3

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"errors"
	"fmt"
	"time"

	"github.com/zeebo/blake3"
)

const (
	envelopeInfo             = "punaro/attachment-envelope/v3/base"
	envelopeSignatureDomain  = "punaro/attachment/envelope/v3\x00"
	maxEnvelopeEncodedBytes  = 16 << 10
	maxEnvelopePlaintextSize = 160
	hpkeKEMID                = 0x0020
	hpkeKDFID                = 0x0001
	hpkeAEADID               = 0x0003
)

// EnvelopeDirectoryKeyResolver adds the current recipient HPKE-key view to
// the fresh manifest authority. Callers must not substitute a cached key.
type EnvelopeDirectoryKeyResolver interface {
	DirectoryKeyResolver
	CurrentRecipientHPKEKey(deviceID [16]byte, generation uint64) ([32]byte, *ecdh.PublicKey, error)
	ResolveRecipientHPKEKey(deviceID [16]byte, generation uint64, keyID [32]byte) (*ecdh.PublicKey, error)
}

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

func verifyEnvelope(e Envelope, m Manifest, raw []byte, signer ed25519.PublicKey) bool {
	if len(signer) != ed25519.PublicKeySize || validateEnvelope(e) != nil || !sameEnvelopeManifestBinding(e, m, raw) {
		return false
	}
	payload, err := e.signedBytes()
	return err == nil && ed25519.Verify(signer, payload, e.Signature[:])
}

func envelopeAAD(e Envelope) ([]byte, error) {
	return canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: e.Audience, 3: e.TransferID, 4: e.ConversationID, 5: e.RecipientDeviceID, 6: e.RecipientGeneration, 7: e.ManifestCommitment, 8: uint64(hpkeKEMID), 9: uint64(hpkeKDFID), 10: uint64(hpkeAEADID)})
}

type envelopePlaintext struct {
	FileKey             [32]byte `cbor:"1,keyasint"`
	ManifestCommitment  [32]byte `cbor:"2,keyasint"`
	RecipientHPKEKeyID  [32]byte `cbor:"3,keyasint"`
	RecipientGeneration uint64   `cbor:"4,keyasint"`
}

func SealRecipientEnvelope(source VerifiedSource, directory EnvelopeDirectoryKeyResolver, fileKey [32]byte, signer ed25519.PrivateKey, now time.Time) (Envelope, error) {
	if directory == nil || fileKey == [32]byte{} || len(signer) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid v3 envelope key binding")
	}
	fresh, err := DecodeAndVerifySourceInit(source.raw, directory, now)
	if err != nil || fresh.commitment != source.commitment {
		return Envelope{}, errors.New("invalid v3 envelope key binding")
	}
	manifestSigner, err := directory.ValidateManifestAuthority(fresh.manifest, now.UTC())
	if err != nil || !bytes.Equal(signer.Public().(ed25519.PublicKey), manifestSigner) {
		return Envelope{}, errors.New("invalid v3 envelope key binding")
	}
	keyID, recipient, err := directory.CurrentRecipientHPKEKey(fresh.manifest.RecipientDeviceID, fresh.manifest.RecipientGeneration)
	if err != nil || recipient == nil || keyID == [32]byte{} {
		return Envelope{}, errors.New("invalid v3 recipient directory key")
	}
	e := Envelope{Audience: fresh.manifest.Audience, TransferID: fresh.manifest.TransferID, ConversationID: fresh.manifest.ConversationID, SenderDeviceID: fresh.manifest.SenderDeviceID, SenderGeneration: fresh.manifest.SenderGeneration, RecipientDeviceID: fresh.manifest.RecipientDeviceID, RecipientGeneration: fresh.manifest.RecipientGeneration, RecipientHPKEKeyID: keyID, ManifestCommitment: fresh.commitment, SignerKeyID: fresh.manifest.SignerKeyID}
	aad, err := envelopeAAD(e)
	if err != nil {
		return Envelope{}, err
	}
	plain, err := canonicalEncoding.Marshal(envelopePlaintext{FileKey: fileKey, ManifestCommitment: e.ManifestCommitment, RecipientHPKEKeyID: keyID, RecipientGeneration: e.RecipientGeneration})
	if err != nil || len(plain) > maxEnvelopePlaintextSize {
		return Envelope{}, errors.New("invalid v3 envelope plaintext")
	}
	pub, err := hpke.NewDHKEMPublicKey(recipient)
	if err != nil {
		return Envelope{}, err
	}
	enc, sender, err := hpke.NewSender(pub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(envelopeInfo))
	if err != nil || len(enc) != 32 {
		return Envelope{}, errors.New("create v3 envelope HPKE sender")
	}
	copy(e.EncapsulatedKey[:], enc)
	e.Ciphertext, err = sender.Seal(aad, plain)
	if err != nil || validateEnvelope(e) != nil {
		return Envelope{}, errors.New("seal v3 envelope")
	}
	if err := SignEnvelope(&e, signer); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

// OpenRecipientEnvelope verifies the current directory, outer signature, and
// inner HPKE context before releasing the per-artifact file key.
func OpenRecipientEnvelope(rawEnvelope []byte, source VerifiedSource, directory EnvelopeDirectoryKeyResolver, private *ecdh.PrivateKey, now time.Time) ([32]byte, error) {
	e, err := DecodeEnvelope(rawEnvelope)
	if err != nil || directory == nil || private == nil {
		return [32]byte{}, errors.New("invalid v3 envelope")
	}
	fresh, err := DecodeAndVerifySourceInit(source.raw, directory, now)
	if err != nil || fresh.commitment != source.commitment {
		return [32]byte{}, errors.New("invalid v3 envelope binding")
	}
	signer, err := directory.ValidateManifestAuthority(fresh.manifest, now.UTC())
	if err != nil || !verifyEnvelope(e, fresh.manifest, fresh.raw, signer) {
		return [32]byte{}, errors.New("invalid v3 envelope binding")
	}
	expected, err := directory.ResolveRecipientHPKEKey(e.RecipientDeviceID, e.RecipientGeneration, e.RecipientHPKEKeyID)
	if err != nil || expected == nil || !private.PublicKey().Equal(expected) {
		return [32]byte{}, errors.New("invalid v3 recipient directory key")
	}
	aad, err := envelopeAAD(e)
	if err != nil {
		return [32]byte{}, err
	}
	key, err := hpke.NewDHKEMPrivateKey(private)
	if err != nil {
		return [32]byte{}, errors.New("invalid v3 recipient HPKE key")
	}
	recipient, err := hpke.NewRecipient(e.EncapsulatedKey[:], key, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(envelopeInfo))
	if err != nil {
		return [32]byte{}, errors.New("open v3 envelope recipient")
	}
	plain, err := recipient.Open(aad, e.Ciphertext)
	if err != nil || len(plain) > maxEnvelopePlaintextSize {
		return [32]byte{}, errors.New("open v3 envelope")
	}
	var decoded envelopePlaintext
	if err := strictDecoding.Unmarshal(plain, &decoded); err != nil {
		return [32]byte{}, errors.New("invalid v3 envelope plaintext")
	}
	canonical, err := canonicalEncoding.Marshal(decoded)
	if err != nil || !bytes.Equal(plain, canonical) || decoded.FileKey == [32]byte{} || decoded.ManifestCommitment != e.ManifestCommitment || decoded.RecipientHPKEKeyID != e.RecipientHPKEKeyID || decoded.RecipientGeneration != e.RecipientGeneration {
		return [32]byte{}, errors.New("invalid v3 envelope plaintext binding")
	}
	return decoded.FileKey, nil
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
