package v3

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestPrepareSourceArtifactReservesV3MaterialBeforeEncrypting(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := openSourceStore(privateDatabase(t), defaultSourceLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	manifest := testManifest(now)
	manifest.ContentSalt, manifest.PlaintextCommitment = [32]byte{}, [32]byte{}
	manifest.ChunkSize, manifest.ChunkCount, manifest.PlaintextSize = 5, 0, 0
	artifact, fileKey, err := prepareSourceArtifact([]byte("a v3 source artifact"), manifest, signer, store)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := DecodeAndVerifySourceInit(mustEncodeManifest(t, artifact.Manifest), manifestAuthorityStub{public: signer.Public().(ed25519.PublicKey)}, now)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openSourceArtifact(verified, artifact.Chunks, fileKey, now)
	if err != nil || !bytes.Equal(opened, []byte("a v3 source artifact")) {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
	if _, err := store.db.ExecContext(context.Background(), `SELECT 1 FROM v3_source_file_keys LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	if err := store.reserveCrypto(fileKey, mustEncodeManifest(t, artifact.Manifest), artifact.ManifestCommitment); err != nil {
		t.Fatalf("exact crash replay of cryptographic material rejected: %v", err)
	}
	if _, err := openSourceArtifact(verified, artifact.Chunks, testHash(99), now); err == nil {
		t.Fatal("wrong file key decrypted artifact")
	}
}

func TestPublicArtifactStoreRoundTripsOnlyVerifiedEncryptedArtifact(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenArtifactStore(privateDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	manifest := testManifest(now)
	manifest.ContentSalt, manifest.PlaintextCommitment = [32]byte{}, [32]byte{}
	manifest.ChunkSize, manifest.ChunkCount, manifest.PlaintextSize = 5, 0, 0
	artifact, fileKey, err := PrepareSourceArtifact([]byte("public artifact"), manifest, signer, store)
	if err != nil {
		t.Fatal(err)
	}
	raw := mustEncodeManifest(t, artifact.Manifest)
	opened, err := OpenSourceArtifact(raw, artifact.Chunks, fileKey, manifestAuthorityStub{public: signer.Public().(ed25519.PublicKey)}, now)
	if err != nil || !bytes.Equal(opened, []byte("public artifact")) {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
}

func TestPrepareSourceArtifactBoundsPermanentCryptoReservations(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	limits := defaultSourceLimits()
	limits.Relay.CryptoReservations = 3
	store, err := openSourceStore(privateDatabase(t), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	manifest := testManifest(now)
	manifest.ContentSalt, manifest.PlaintextCommitment = [32]byte{}, [32]byte{}
	manifest.ChunkSize, manifest.ChunkCount, manifest.PlaintextSize = 8, 0, 0
	if _, _, err := prepareSourceArtifact([]byte("x"), manifest, signer, store); err != nil {
		t.Fatal(err)
	}
	manifest.TransferID = testID(88)
	if _, _, err := prepareSourceArtifact([]byte("y"), manifest, signer, store); err == nil {
		t.Fatal("crypto reservation budget did not bound prepare-discard growth")
	}
}

func TestPreparedSourceArtifactCanReplaySameDurablyIdentifiedMaterial(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenArtifactStore(privateDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
	manifest := testManifest(now)
	manifest.ContentSalt, manifest.PlaintextCommitment = [32]byte{}, [32]byte{}
	manifest.ChunkSize, manifest.ChunkCount, manifest.PlaintextSize = 5, 0, 0
	material := SourceArtifactMaterial{FileKey: testHash(91), ContentSalt: testHash(92)}
	prepared, commitment, err := PrepareSourceManifest([]byte("replay-safe artifact"), manifest, signer, material)
	if err != nil {
		t.Fatal(err)
	}
	first, err := EncryptPreparedSourceArtifact([]byte("replay-safe artifact"), prepared, commitment, material.FileKey, store)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptPreparedSourceArtifact([]byte("replay-safe artifact"), prepared, commitment, material.FileKey, store)
	if err != nil {
		t.Fatalf("same prepared material could not replay after crash boundary: %v", err)
	}
	if !bytes.Equal(first.Chunks[0].Ciphertext, second.Chunks[0].Ciphertext) || first.ManifestCommitment != second.ManifestCommitment {
		t.Fatal("replay changed encrypted source artifact")
	}
}

func mustEncodeManifest(t *testing.T, manifest Manifest) []byte {
	t.Helper()
	raw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
