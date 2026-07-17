package v3

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/zeebo/blake3"
)

const (
	protocolVersion         = 3
	maxManifestEncodedBytes = 4 << 10
	manifestSignatureDomain = "punaro/attachment/manifest/v3\x00"
	// MaxManifestLifetime bounds immutable v3 transfer state. Directory heads
	// and operation permits remain independently short-lived (at most 30s).
	MaxManifestLifetime = 10 * time.Minute
	// MaxFutureClockSkew tolerates ordinary NTP convergence and scheduling
	// differences between enrolled machines. It never extends an expiry and is
	// not a substitute for normal time synchronization.
	MaxFutureClockSkew = time.Minute
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
		DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden,
		TagsMd: cbor.TagsForbidden, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8: cbor.UTF8RejectInvalid, MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 32,
	}).DecMode()
	if err != nil {
		panic(fmt.Sprintf("configure strict CBOR: %v", err))
	}
}

// Manifest is the canonical, signed v3 source description.
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
	encoded, err := canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: m.Audience, 3: m.TransferID, 4: m.ConversationID, 5: m.SenderDeviceID, 6: m.SenderGeneration, 7: m.RecipientDeviceID, 8: m.RecipientGeneration, 9: m.DirectoryHead, 10: m.MembershipCommitment, 11: m.RevocationEpoch, 12: m.IssuedAt, 13: m.ExpiresAt, 14: m.ContentSalt, 15: m.PlaintextCommitment, 16: m.ChunkSize, 17: m.ChunkCount, 18: m.PlaintextSize, 19: m.SignerKeyID, 20: uint64(1)})
	return append([]byte(manifestSignatureDomain), encoded...), err
}

func validateManifest(m Manifest) error {
	if m.TransferID == [16]byte{} || m.ConversationID == [16]byte{} || m.SenderDeviceID == [16]byte{} || m.RecipientDeviceID == [16]byte{} || m.Audience == [32]byte{} || m.DirectoryHead == [32]byte{} || m.MembershipCommitment == [32]byte{} || m.ContentSalt == [32]byte{} || m.PlaintextCommitment == [32]byte{} || m.SignerKeyID == [32]byte{} {
		return errors.New("missing manifest binding")
	}
	if m.SenderGeneration == 0 || m.RecipientGeneration == 0 || m.ExpiresAt <= m.IssuedAt || m.ExpiresAt > math.MaxInt64 || m.ExpiresAt-m.IssuedAt > uint64(MaxManifestLifetime/time.Second) || m.ChunkSize == 0 || m.ChunkSize > 256<<10 || m.ChunkCount == 0 || m.ChunkCount > 4096 || m.PlaintextSize > 64<<20 {
		return errors.New("invalid manifest bounds")
	}
	if m.PlaintextSize == 0 && m.ChunkCount == 1 {
		return nil
	}
	fullChunksBeforeLast := m.ChunkSize * (m.ChunkCount - 1)
	if m.PlaintextSize <= fullChunksBeforeLast || m.PlaintextSize > m.ChunkSize*m.ChunkCount {
		return errors.New("inconsistent manifest chunk geometry")
	}
	return nil
}

// SignManifest adds the source device signature to a valid manifest.
func SignManifest(m *Manifest, private ed25519.PrivateKey) error {
	if m == nil || len(private) != ed25519.PrivateKeySize || validateManifest(*m) != nil {
		return errors.New("invalid manifest signer")
	}
	payload, err := m.signedBytes()
	if err != nil {
		return err
	}
	copy(m.Signature[:], ed25519.Sign(private, payload))
	return nil
}

// VerifyManifest reports whether a valid manifest has the supplied signature.
func VerifyManifest(m Manifest, public ed25519.PublicKey) bool {
	if len(public) != ed25519.PublicKeySize || validateManifest(m) != nil {
		return false
	}
	payload, err := m.signedBytes()
	return err == nil && ed25519.Verify(public, payload, m.Signature[:])
}

// EncodeManifest returns the canonical wire encoding of a valid manifest.
func EncodeManifest(m Manifest) ([]byte, error) {
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(m.wire())
}

// DecodeManifest accepts only a bounded canonical manifest encoding.
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

// DirectoryKeyResolver verifies the signer against a fresh authenticated v3 directory.
type DirectoryKeyResolver interface {
	ValidateManifestAuthority(Manifest, time.Time) (ed25519.PublicKey, error)
}

// RetainedManifestAuthorityResolver validates a manifest already admitted by
// source-init against a fresh current directory view. Unlike strict initial
// admission it permits directory-head rollover, but it still requires the
// original transfer identities, membership, sender key, and revocation state
// to remain current and active.
type RetainedManifestAuthorityResolver interface {
	ValidateRetainedManifestAuthority(Manifest, time.Time) (ed25519.PublicKey, error)
}

// VerifiedSource cannot be constructed by a network caller. It contains only
// values derived from a canonical manifest after fresh directory verification.
type VerifiedSource struct {
	manifest   Manifest
	raw        []byte
	commitment [32]byte
}

// DecodeAndVerifySourceInit decodes a canonical manifest and verifies its
// signer against a fresh directory view.
func DecodeAndVerifySourceInit(raw []byte, directory DirectoryKeyResolver, now time.Time) (VerifiedSource, error) {
	if directory == nil {
		return VerifiedSource{}, errors.New("missing directory resolver")
	}
	m, err := DecodeManifest(raw)
	if err != nil {
		return VerifiedSource{}, err
	}
	if err := validateManifestTime(m, now); err != nil {
		return VerifiedSource{}, err
	}
	public, err := directory.ValidateManifestAuthority(m, now.UTC())
	if err != nil || !VerifyManifest(m, public) {
		return VerifiedSource{}, errors.New("invalid manifest signer binding")
	}
	return VerifiedSource{manifest: m, raw: append([]byte(nil), raw...), commitment: blake3.Sum256(raw)}, nil
}

// DecodeAndVerifyRetainedSource verifies an already source-init-admitted
// manifest with fresh current authority. It deliberately does not require the
// current directory head or revocation epoch to equal the immutable manifest:
// a new short-lived permit carries those current values. The resolver must
// instead reject any changed membership, device generation/key, or revocation.
func DecodeAndVerifyRetainedSource(raw []byte, directory RetainedManifestAuthorityResolver, now time.Time) (VerifiedSource, error) {
	if directory == nil {
		return VerifiedSource{}, errors.New("missing retained directory resolver")
	}
	m, err := DecodeManifest(raw)
	if err != nil {
		return VerifiedSource{}, err
	}
	if err := validateManifestTime(m, now); err != nil {
		return VerifiedSource{}, err
	}
	public, err := directory.ValidateRetainedManifestAuthority(m, now.UTC())
	if err != nil || !VerifyManifest(m, public) {
		return VerifiedSource{}, errors.New("invalid retained manifest authority")
	}
	return VerifiedSource{manifest: m, raw: append([]byte(nil), raw...), commitment: blake3.Sum256(raw)}, nil
}

func (v VerifiedSource) valid(now time.Time) bool {
	return len(v.raw) > 0 && v.commitment != [32]byte{} &&
		v.commitment == blake3.Sum256(v.raw) && validateManifest(v.manifest) == nil &&
		validateManifestTime(v.manifest, now) == nil
}

// TransferID returns the verified source's immutable transfer ID.
func (v VerifiedSource) TransferID() [16]byte { return v.manifest.TransferID }

// ManifestCommitment returns the canonical manifest commitment.
func (v VerifiedSource) ManifestCommitment() [32]byte { return v.commitment }

// ChunkSize returns the verified source's ciphertext chunk size.
func (v VerifiedSource) ChunkSize() uint64 { return v.manifest.ChunkSize }

// ChunkCount returns the verified source's bounded chunk count.
func (v VerifiedSource) ChunkCount() uint64 { return v.manifest.ChunkCount }

// PlaintextSize returns the verified source's original byte count.
func (v VerifiedSource) PlaintextSize() uint64 { return v.manifest.PlaintextSize }

func validateManifestTime(m Manifest, now time.Time) error {
	seconds := now.UTC().Unix()
	if seconds < 0 || !issuedWithinClockSkew(m.IssuedAt, seconds) || m.ExpiresAt > math.MaxInt64 {
		return errors.New("invalid manifest time")
	}
	if uint64(seconds) >= m.ExpiresAt {
		return errors.New("expired manifest")
	}
	return nil
}

func issuedWithinClockSkew(issued uint64, nowUnix int64) bool {
	return nowUnix >= 0 && issued <= uint64(nowUnix)+uint64(MaxFutureClockSkew/time.Second)
}
