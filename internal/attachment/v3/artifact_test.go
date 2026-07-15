package v3

import (
	"bytes"
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
	if _, err := store.db.Exec(`SELECT 1 FROM v3_source_file_keys LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	if err := store.reserveCrypto(fileKey, artifact.Manifest, mustEncodeManifest(t, artifact.Manifest), artifact.ManifestCommitment); err == nil {
		t.Fatal("reused cryptographic material accepted")
	}
	if _, err := openSourceArtifact(verified, artifact.Chunks, testHash(99), now); err == nil {
		t.Fatal("wrong file key decrypted artifact")
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

func mustEncodeManifest(t *testing.T, manifest Manifest) []byte {
	t.Helper()
	raw, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
