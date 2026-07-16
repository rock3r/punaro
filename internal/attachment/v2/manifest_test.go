package v2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestManifestFixedCDEVector(t *testing.T) {
	expectedHash, err := os.ReadFile("testdata/cde/manifest-v2-positive.sha256")
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	if err := SignManifest(&manifest, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x0a}, ed25519.SeedSize))); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != strings.TrimSpace(string(expectedHash)) {
		t.Fatalf("fixed CDE vector hash = %s", got)
	}
	decoded, err := DecodeManifest(raw)
	if err != nil || !VerifyManifest(decoded, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x0a}, ed25519.SeedSize)).Public().(ed25519.PublicKey)) {
		t.Fatal("fixed vector signature did not verify")
	}
	encoded, err := EncodeManifest(decoded)
	if err != nil || !bytes.Equal(encoded, raw) {
		t.Fatal("fixed vector did not retain canonical bytes")
	}
}

func TestManifestFixedNegativeCDEVectors(t *testing.T) {
	rawVectors, err := os.ReadFile("testdata/cde/manifest-v2-negative.hex")
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range strings.Fields(string(rawVectors)) {
		raw, err := hex.DecodeString(vector)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeManifest(raw); err == nil {
			t.Fatalf("DecodeManifest accepted fixed malformed vector %q", vector)
		}
	}
}

func TestManifestCanonicalRoundTripAndSignatureBinding(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	if err := SignManifest(&manifest, private); err != nil {
		t.Fatalf("SignManifest() error = %v", err)
	}
	encoded, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeManifest() error = %v", err)
	}
	decoded, err := DecodeManifest(encoded)
	if err != nil {
		t.Fatalf("DecodeManifest() error = %v", err)
	}
	if !VerifyManifest(decoded, public) {
		t.Fatal("VerifyManifest() rejected round-tripped manifest")
	}
	reencoded, err := EncodeManifest(decoded)
	if err != nil {
		t.Fatalf("EncodeManifest(decoded) error = %v", err)
	}
	if string(reencoded) != string(encoded) {
		t.Fatal("manifest did not retain its exact canonical encoding")
	}
	decoded.Audience[0] ^= 1
	if VerifyManifest(decoded, public) {
		t.Fatal("signature accepted a manifest with a changed audience")
	}
}

func TestManifestSignaturePreimageOmitsSignatureField(t *testing.T) {
	manifest := sampleManifest()
	payload, err := manifest.signedBytes()
	if err != nil {
		t.Fatal(err)
	}
	encoded := bytes.TrimPrefix(payload, []byte(manifestSignatureDomain))
	var fields map[uint64]any
	if err := strictDecoding.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, found := fields[99]; found {
		t.Fatal("manifest signature preimage included field 99")
	}
}

func TestDecodeManifestRejectsTrailingAndOversizedInput(t *testing.T) {
	manifest := sampleManifest()
	encoded, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeManifest() error = %v", err)
	}
	if _, err := DecodeManifest(append(encoded, 0xf6)); err == nil {
		t.Fatal("DecodeManifest accepted a trailing CBOR item")
	}
	if _, err := DecodeManifest(make([]byte, maxManifestEncodedBytes+1)); err == nil {
		t.Fatal("DecodeManifest accepted an oversized record")
	}
}

func TestManifestRejectsMissingRequiredBindings(t *testing.T) {
	manifest := sampleManifest()
	manifest.TransferID = [16]byte{}
	if _, err := EncodeManifest(manifest); err == nil {
		t.Fatal("EncodeManifest accepted an absent transfer binding")
	}
}

func TestManifestRejectsInconsistentChunkGeometry(t *testing.T) {
	manifest := sampleManifest()
	manifest.ChunkSize = 1024
	manifest.ChunkCount = 2
	manifest.PlaintextSize = 1024
	if _, err := EncodeManifest(manifest); err == nil {
		t.Fatal("EncodeManifest accepted a zero-length final chunk")
	}
	manifest.PlaintextSize = 2049
	if _, err := EncodeManifest(manifest); err == nil {
		t.Fatal("EncodeManifest accepted plaintext beyond declared chunks")
	}
}

func TestManifestRejectsLifetimeLongerThanThirtySeconds(t *testing.T) {
	manifest := sampleManifest()
	manifest.ExpiresAt = manifest.IssuedAt + 31
	if _, err := EncodeManifest(manifest); err == nil {
		t.Fatal("EncodeManifest accepted a manifest lifetime longer than 30 seconds")
	}
}

func TestManifestAllowsEmptyArtifactWithOneEmptyChunk(t *testing.T) {
	manifest := sampleManifest()
	manifest.ChunkCount = 1
	manifest.PlaintextSize = 0
	if _, err := EncodeManifest(manifest); err != nil {
		t.Fatalf("EncodeManifest() rejected empty artifact: %v", err)
	}
}

func sampleManifest() Manifest {
	return Manifest{
		Audience:             bytes32(1),
		TransferID:           bytes16(2),
		ConversationID:       bytes16(3),
		SenderDeviceID:       bytes16(4),
		SenderGeneration:     1,
		RecipientDeviceID:    bytes16(5),
		RecipientGeneration:  2,
		DirectoryHead:        bytes32(6),
		MembershipCommitment: bytes32(7),
		RevocationEpoch:      3,
		IssuedAt:             1_700_000_000,
		ExpiresAt:            1_700_000_030,
		ContentSalt:          bytes32(8),
		PlaintextCommitment:  bytes32(9),
		ChunkSize:            4096,
		ChunkCount:           1,
		PlaintextSize:        42,
		SignerKeyID:          bytes32(10),
	}
}

func bytes16(value byte) [16]byte {
	var result [16]byte
	for index := range result {
		result[index] = value
	}
	return result
}

func bytes32(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}
