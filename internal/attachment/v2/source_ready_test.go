package v2

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteSourceReadyStoreAtomicallyPersistsVerifiedArtifactAndEnvelope(t *testing.T) {
	t.Parallel()
	signerPublic, signerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	draft := sampleManifest()
	draft.ContentSalt, draft.PlaintextCommitment = [32]byte{}, [32]byte{}
	draft.ChunkSize, draft.ChunkCount, draft.PlaintextSize = 8, 0, 0
	draft.IssuedAt, draft.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(20*time.Second))
	directory := directoryStub{signerID: draft.SignerKeyID, signer: signerPublic, recipientID: bytes32(30), recipient: recipientPrivate.PublicKey()}
	artifact, fileKey, err := PrepareSourceArtifact([]byte("source ready bytes"), draft, signerPrivate, &recordingReservationStore{})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyManifestFromDirectory(artifact.Manifest, directory)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealRecipientEnvelope(verified, directory, fileKey, signerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSQLiteSourceReadyStore(filepath.Join(parent, "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CommitSourceReady(artifact, envelope, directory); err != nil {
		t.Fatal(err)
	}
	loaded, loadedEnvelope, found, err := store.LoadSourceReady(artifact.ManifestCommitment)
	if err != nil || !found || loaded.ManifestCommitment != artifact.ManifestCommitment || len(loaded.Chunks) != len(artifact.Chunks) || loadedEnvelope.ManifestCommitment != artifact.ManifestCommitment {
		t.Fatalf("loaded=%#v envelope=%#v found=%v err=%v", loaded, loadedEnvelope, found, err)
	}
}

func TestSQLiteSourceReadyStoreRejectsCorruptStoredChunk(t *testing.T) {
	t.Parallel()
	signerPublic, signerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	draft := sampleManifest()
	draft.ContentSalt, draft.PlaintextCommitment = [32]byte{}, [32]byte{}
	draft.ChunkSize, draft.ChunkCount, draft.PlaintextSize = 8, 0, 0
	draft.IssuedAt, draft.ExpiresAt = testUnix(t, clock.Add(-time.Second)), testUnix(t, clock.Add(20*time.Second))
	directory := directoryStub{signerID: draft.SignerKeyID, signer: signerPublic, recipientID: bytes32(30), recipient: recipientPrivate.PublicKey()}
	artifact, fileKey, err := PrepareSourceArtifact([]byte("source ready bytes"), draft, signerPrivate, &recordingReservationStore{})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifyManifestFromDirectory(artifact.Manifest, directory)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealRecipientEnvelope(verified, directory, fileKey, signerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenSQLiteSourceReadyStore(filepath.Join(parent, "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.CommitSourceReady(artifact, envelope, directory); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), "UPDATE source_ready_chunks SET ciphertext = ? WHERE manifest_commitment = ? AND chunk_index = ?", []byte("corrupt"), artifact.ManifestCommitment[:], uint64Bytes(0)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.LoadSourceReady(artifact.ManifestCommitment); err == nil {
		t.Fatal("corrupt source-ready chunk was accepted")
	}
}
