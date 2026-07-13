package v2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestPrepareSourceArtifactReservesBeforeEncryptingAndBindsEveryChunk(t *testing.T) {
	t.Parallel()
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	manifest.ContentSalt = [32]byte{}
	manifest.PlaintextCommitment = [32]byte{}
	manifest.ChunkSize = 5
	manifest.ChunkCount = 0
	manifest.PlaintextSize = 0
	store := &recordingReservationStore{}
	plaintext := []byte("a full source artifact")

	artifact, fileKey, err := PrepareSourceArtifact(plaintext, manifest, signer, store)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || store.fileKeyCommitment != fileKeyCommitment(fileKey) || store.contentSaltCommitment != contentSaltCommitment(artifact.Manifest.ContentSalt) {
		t.Fatalf("reservation calls=%d key=%x salt=%x", store.calls, store.fileKeyCommitment, store.contentSaltCommitment)
	}
	if len(store.nonces) != len(artifact.Chunks) || artifact.Manifest.ChunkCount != uint64(len(artifact.Chunks)) {
		t.Fatalf("nonce/chunk count=%d/%d manifest=%d", len(store.nonces), len(artifact.Chunks), artifact.Manifest.ChunkCount)
	}
	commitment, err := manifestCommitment(artifact.Manifest)
	if err != nil || artifact.ManifestCommitment != commitment {
		t.Fatalf("manifest commitment=%x err=%v", artifact.ManifestCommitment, err)
	}
	for index, nonce := range store.nonces {
		if nonce.TransferID != artifact.Manifest.TransferID || nonce.ManifestCommitment != artifact.ManifestCommitment || nonce.ChunkIndex != uint64(index) {
			t.Fatalf("nonce tuple %d was not manifest-bound: %#v", index, nonce)
		}
	}
	opened, err := OpenSourceArtifact(artifact.Manifest, artifact.ManifestCommitment, artifact.Chunks, fileKey)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
	artifact.Chunks[0].Ciphertext[0] ^= 1
	if _, err := OpenSourceArtifact(artifact.Manifest, artifact.ManifestCommitment, artifact.Chunks, fileKey); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestPrepareSourceArtifactDoesNotEncryptWhenDurableReservationFails(t *testing.T) {
	t.Parallel()
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := sampleManifest()
	manifest.ContentSalt = [32]byte{}
	manifest.PlaintextCommitment = [32]byte{}
	manifest.ChunkSize = 5
	manifest.ChunkCount = 0
	manifest.PlaintextSize = 0
	store := &recordingReservationStore{err: errors.New("durable store unavailable")}
	artifact, _, err := PrepareSourceArtifact([]byte("never encrypt"), manifest, signer, store)
	if err == nil || store.calls != 1 || len(artifact.Chunks) != 0 {
		t.Fatalf("artifact=%#v calls=%d err=%v", artifact, store.calls, err)
	}
}

type recordingReservationStore struct {
	calls                 int
	fileKeyCommitment     [32]byte
	contentSaltCommitment [32]byte
	nonces                []NonceReservation
	err                   error
}

func (s *recordingReservationStore) Reserve(fileKeyCommitment, contentSaltCommitment [32]byte, nonces []NonceReservation) error {
	s.calls++
	s.fileKeyCommitment = fileKeyCommitment
	s.contentSaltCommitment = contentSaltCommitment
	s.nonces = append([]NonceReservation(nil), nonces...)
	return s.err
}
