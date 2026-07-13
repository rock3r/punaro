package v2

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
	envelopeInfo             = "punaro/attachment-envelope/v2/base"
	envelopeSignatureDomain  = "punaro/attachment/envelope/v2\x00"
	maxEnvelopeEncodedBytes  = 16 << 10
	maxEnvelopePlaintextSize = 160
	hpkeKEMID                = 0x0020
	hpkeKDFID                = 0x0001
	hpkeAEADID               = 0x0003
)

// VerifiedManifest is a manifest verified against a directory-resolved signer
// key.  It cannot be constructed by external callers: use
// DecodeAndVerifyManifest after checking the directory record and its key-ID
// association.
type VerifiedManifest struct {
	manifest   Manifest
	commitment [32]byte
	signer     ed25519.PublicKey
}

// DirectoryKeyResolver is the sole authority boundary between v2 records and
// a fresh, authenticated device directory.  Implementations must reject stale,
// revoked, or membership-incompatible keys before returning them.
type DirectoryKeyResolver interface {
	ValidateManifestAuthority(manifest Manifest, now time.Time) (ed25519.PublicKey, error)
	CurrentRecipientHPKEKey(deviceID [16]byte, generation uint64) ([32]byte, *ecdh.PublicKey, error)
	ResolveRecipientHPKEKey(deviceID [16]byte, generation uint64, keyID [32]byte) (*ecdh.PublicKey, error)
}

// DecodeAndVerifyManifest is the receive-side entry point.  It first enforces
// the strict canonical wire format, then resolves and verifies the signer
// through the authenticated directory boundary.
func DecodeAndVerifyManifest(raw []byte, directory DirectoryKeyResolver) (VerifiedManifest, error) {
	m, err := DecodeManifest(raw)
	if err != nil {
		return VerifiedManifest{}, err
	}
	return verifyManifestFromDirectory(m, directory)
}

// verifyManifestFromDirectory asks the directory to validate the complete
// signed manifest against its fresh audience, membership, device-generation,
// revocation, head, and time state before verifying the resolved signer.
func verifyManifestFromDirectory(m Manifest, directory DirectoryKeyResolver) (VerifiedManifest, error) {
	if directory == nil {
		return VerifiedManifest{}, errors.New("missing directory resolver")
	}
	signer, err := directory.ValidateManifestAuthority(m, time.Now().UTC())
	if err != nil || !VerifyManifest(m, signer) {
		return VerifiedManifest{}, errors.New("invalid manifest signer binding")
	}
	commitment, err := manifestCommitment(m)
	if err != nil {
		return VerifiedManifest{}, err
	}
	return VerifiedManifest{manifest: m, commitment: commitment, signer: append(ed25519.PublicKey(nil), signer...)}, nil
}

func (v VerifiedManifest) valid() bool {
	if !VerifyManifest(v.manifest, v.signer) {
		return false
	}
	commitment, err := manifestCommitment(v.manifest)
	return err == nil && commitment == v.commitment
}

// Manifest returns an immutable-copy view of the verified manifest.
func (v VerifiedManifest) Manifest() Manifest { return v.manifest }

// manifestCommitment is BLAKE3-256 of a complete canonical signed manifest.
// It is deliberately private: callers must obtain commitments through a
// VerifiedManifest, which proves signature and directory-key binding first.
func manifestCommitment(m Manifest) ([32]byte, error) {
	b, err := EncodeManifest(m)
	if err != nil {
		return [32]byte{}, err
	}
	return blake3.Sum256(b), nil
}

// Envelope is the recipient-specific immutable record defined in the v2 RFC.
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
	return envelopeWire{
		Version: protocolVersion, Audience: e.Audience, TransferID: e.TransferID,
		ConversationID: e.ConversationID, SenderDeviceID: e.SenderDeviceID,
		SenderGeneration: e.SenderGeneration, RecipientDeviceID: e.RecipientDeviceID,
		RecipientGeneration: e.RecipientGeneration, RecipientHPKEKeyID: e.RecipientHPKEKeyID,
		ManifestCommitment: e.ManifestCommitment, KEMID: hpkeKEMID, KDFID: hpkeKDFID,
		AEADID: hpkeAEADID, EncapsulatedKey: e.EncapsulatedKey, Ciphertext: e.Ciphertext,
		SignerKeyID: e.SignerKeyID, SignatureAlgorithm: 1, Signature: e.Signature,
	}
}

func envelopeSigningMap(e Envelope) map[uint64]any {
	return map[uint64]any{
		1: uint64(protocolVersion), 2: e.Audience, 3: e.TransferID, 4: e.ConversationID,
		5: e.SenderDeviceID, 6: e.SenderGeneration, 7: e.RecipientDeviceID,
		8: e.RecipientGeneration, 9: e.RecipientHPKEKeyID, 10: e.ManifestCommitment,
		11: uint64(hpkeKEMID), 12: uint64(hpkeKDFID), 13: uint64(hpkeAEADID),
		14: e.EncapsulatedKey, 15: e.Ciphertext, 16: e.SignerKeyID, 17: uint64(1),
	}
}

func (e Envelope) signedBytes() ([]byte, error) {
	payload, err := canonicalEncoding.Marshal(envelopeSigningMap(e))
	if err != nil {
		return nil, err
	}
	return append([]byte(envelopeSignatureDomain), payload...), nil
}

func validateEnvelope(e Envelope) error {
	if isZero32(e.Audience) || isZero16(e.TransferID) || isZero16(e.ConversationID) ||
		isZero16(e.SenderDeviceID) || e.SenderGeneration == 0 || isZero16(e.RecipientDeviceID) ||
		e.RecipientGeneration == 0 || isZero32(e.RecipientHPKEKeyID) ||
		isZero32(e.ManifestCommitment) || isZero32(e.SignerKeyID) {
		return errors.New("missing envelope binding")
	}
	if len(e.Ciphertext) < 16 || len(e.Ciphertext) > 256 {
		return errors.New("invalid envelope ciphertext size")
	}
	return nil
}

func envelopeAAD(e Envelope) ([]byte, error) {
	return canonicalEncoding.Marshal(map[uint64]any{
		1: uint64(protocolVersion), 2: e.Audience, 3: e.TransferID, 4: e.ConversationID,
		5: e.RecipientDeviceID, 6: e.RecipientGeneration, 7: e.ManifestCommitment,
		8: uint64(hpkeKEMID), 9: uint64(hpkeKDFID), 10: uint64(hpkeAEADID),
	})
}

type envelopePlaintext struct {
	FileKey             [32]byte `cbor:"1,keyasint"`
	ManifestCommitment  [32]byte `cbor:"2,keyasint"`
	RecipientHPKEKeyID  [32]byte `cbor:"3,keyasint"`
	RecipientGeneration uint64   `cbor:"4,keyasint"`
}

func encodeEnvelopePlaintext(value envelopePlaintext) ([]byte, error) {
	return canonicalEncoding.Marshal(value)
}

func decodeEnvelopePlaintext(raw []byte) (envelopePlaintext, error) {
	if len(raw) == 0 || len(raw) > maxEnvelopePlaintextSize {
		return envelopePlaintext{}, errors.New("invalid envelope plaintext size")
	}
	var value envelopePlaintext
	if err := strictDecoding.Unmarshal(raw, &value); err != nil {
		return envelopePlaintext{}, fmt.Errorf("decode envelope plaintext: %w", err)
	}
	canonical, err := encodeEnvelopePlaintext(value)
	if err != nil || !bytes.Equal(raw, canonical) {
		return envelopePlaintext{}, errors.New("non-canonical envelope plaintext")
	}
	return value, nil
}

func sameEnvelopeManifestBinding(e Envelope, v VerifiedManifest) bool {
	m := v.manifest
	return e.Audience == m.Audience && e.TransferID == m.TransferID &&
		e.ConversationID == m.ConversationID && e.SenderDeviceID == m.SenderDeviceID &&
		e.SenderGeneration == m.SenderGeneration && e.RecipientDeviceID == m.RecipientDeviceID &&
		e.RecipientGeneration == m.RecipientGeneration && e.ManifestCommitment == v.commitment &&
		e.SignerKeyID == m.SignerKeyID
}

// SealRecipientEnvelope creates the canonical recipient envelope for a
// directory-verified manifest.  The private signing key must match that
// verified manifest's directory-resolved public key.
func SealRecipientEnvelope(v VerifiedManifest, directory DirectoryKeyResolver, fileKey [32]byte, signer ed25519.PrivateKey) (Envelope, error) {
	fresh, err := verifyManifestFromDirectory(v.manifest, directory)
	if err != nil || fresh.commitment != v.commitment || !v.valid() || directory == nil || len(signer) != ed25519.PrivateKeySize ||
		!bytes.Equal(signer.Public().(ed25519.PublicKey), v.signer) {
		return Envelope{}, errors.New("invalid envelope key binding")
	}
	v = fresh
	recipientKeyID, recipient, err := directory.CurrentRecipientHPKEKey(v.manifest.RecipientDeviceID, v.manifest.RecipientGeneration)
	if err != nil || recipient == nil || isZero32(recipientKeyID) {
		return Envelope{}, errors.New("invalid recipient directory key")
	}
	e := Envelope{
		Audience: v.manifest.Audience, TransferID: v.manifest.TransferID,
		ConversationID: v.manifest.ConversationID, SenderDeviceID: v.manifest.SenderDeviceID,
		SenderGeneration: v.manifest.SenderGeneration, RecipientDeviceID: v.manifest.RecipientDeviceID,
		RecipientGeneration: v.manifest.RecipientGeneration, RecipientHPKEKeyID: recipientKeyID,
		ManifestCommitment: v.commitment, SignerKeyID: v.manifest.SignerKeyID,
	}
	aad, err := envelopeAAD(e)
	if err != nil {
		return Envelope{}, err
	}
	plaintext, err := encodeEnvelopePlaintext(envelopePlaintext{
		FileKey: fileKey, ManifestCommitment: e.ManifestCommitment,
		RecipientHPKEKeyID: recipientKeyID, RecipientGeneration: e.RecipientGeneration,
	})
	if err != nil || len(plaintext) > maxEnvelopePlaintextSize {
		return Envelope{}, errors.New("invalid envelope plaintext")
	}
	pk, err := hpke.NewDHKEMPublicKey(recipient)
	if err != nil {
		return Envelope{}, err
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(envelopeInfo))
	if err != nil || len(enc) != len(e.EncapsulatedKey) {
		return Envelope{}, errors.New("create envelope HPKE sender")
	}
	copy(e.EncapsulatedKey[:], enc)
	e.Ciphertext, err = sender.Seal(aad, plaintext)
	if err != nil {
		return Envelope{}, errors.New("seal envelope")
	}
	if err := validateEnvelope(e); err != nil {
		return Envelope{}, err
	}
	payload, err := e.signedBytes()
	if err != nil {
		return Envelope{}, err
	}
	copy(e.Signature[:], ed25519.Sign(signer, payload))
	return e, nil
}

// VerifyEnvelope authenticates a record and all of its bindings to a verified
// manifest before HPKE processing.
func verifyEnvelope(e Envelope, v VerifiedManifest) bool {
	if !v.valid() || validateEnvelope(e) != nil || !sameEnvelopeManifestBinding(e, v) {
		return false
	}
	payload, err := e.signedBytes()
	return err == nil && ed25519.Verify(v.signer, payload, e.Signature[:])
}

// OpenRecipientEnvelope validates every record binding before decrypting and
// checks the encrypted inner context after decrypting.
func OpenRecipientEnvelope(rawEnvelope []byte, v VerifiedManifest, directory DirectoryKeyResolver, private *ecdh.PrivateKey) ([32]byte, error) {
	e, err := DecodeEnvelope(rawEnvelope)
	if err != nil {
		return [32]byte{}, errors.New("decode envelope")
	}
	fresh, err := verifyManifestFromDirectory(v.manifest, directory)
	if err != nil || fresh.commitment != v.commitment || private == nil || directory == nil || !verifyEnvelope(e, fresh) {
		return [32]byte{}, errors.New("envelope binding mismatch")
	}
	expectedPublic, err := directory.ResolveRecipientHPKEKey(e.RecipientDeviceID, e.RecipientGeneration, e.RecipientHPKEKeyID)
	if err != nil || expectedPublic == nil || !private.PublicKey().Equal(expectedPublic) {
		return [32]byte{}, errors.New("invalid recipient directory key")
	}
	aad, err := envelopeAAD(e)
	if err != nil {
		return [32]byte{}, err
	}
	sk, err := hpke.NewDHKEMPrivateKey(private)
	if err != nil {
		return [32]byte{}, errors.New("invalid recipient HPKE key")
	}
	recipient, err := hpke.NewRecipient(e.EncapsulatedKey[:], sk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(envelopeInfo))
	if err != nil {
		return [32]byte{}, errors.New("open envelope recipient")
	}
	raw, err := recipient.Open(aad, e.Ciphertext)
	if err != nil {
		return [32]byte{}, errors.New("open envelope")
	}
	plaintext, err := decodeEnvelopePlaintext(raw)
	if err != nil || plaintext.ManifestCommitment != e.ManifestCommitment ||
		plaintext.RecipientHPKEKeyID != e.RecipientHPKEKeyID ||
		plaintext.RecipientGeneration != e.RecipientGeneration {
		return [32]byte{}, errors.New("invalid envelope plaintext binding")
	}
	return plaintext.FileKey, nil
}

// EncodeEnvelope serializes a full canonical envelope record.
func EncodeEnvelope(e Envelope) ([]byte, error) {
	if err := validateEnvelope(e); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(e.wire())
}

// DecodeEnvelope accepts only a complete, strict, canonical envelope record.
func DecodeEnvelope(raw []byte) (Envelope, error) {
	if len(raw) == 0 || len(raw) > maxEnvelopeEncodedBytes {
		return Envelope{}, errors.New("invalid envelope size")
	}
	var wire envelopeWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil {
		return Envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	if wire.Version != protocolVersion || wire.KEMID != hpkeKEMID || wire.KDFID != hpkeKDFID ||
		wire.AEADID != hpkeAEADID || wire.SignatureAlgorithm != 1 {
		return Envelope{}, errors.New("unsupported envelope algorithm")
	}
	e := Envelope{
		Audience: wire.Audience, TransferID: wire.TransferID, ConversationID: wire.ConversationID,
		SenderDeviceID: wire.SenderDeviceID, SenderGeneration: wire.SenderGeneration,
		RecipientDeviceID: wire.RecipientDeviceID, RecipientGeneration: wire.RecipientGeneration,
		RecipientHPKEKeyID: wire.RecipientHPKEKeyID, ManifestCommitment: wire.ManifestCommitment,
		EncapsulatedKey: wire.EncapsulatedKey, Ciphertext: wire.Ciphertext,
		SignerKeyID: wire.SignerKeyID, Signature: wire.Signature,
	}
	if err := validateEnvelope(e); err != nil {
		return Envelope{}, err
	}
	canonical, err := EncodeEnvelope(e)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Envelope{}, errors.New("non-canonical envelope")
	}
	return e, nil
}
