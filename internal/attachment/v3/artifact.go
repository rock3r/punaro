package v3

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	plaintextCommitmentDomain   = "punaro/attachment/plaintext/v3\x00"
	fileKeyCommitmentDomain     = "punaro/attachment/file-key/v3\x00"
	contentSaltCommitmentDomain = "punaro/attachment/content-salt/v3\x00"
	chunkKeyDomain              = "punaro/attachment/chunk-key/v3\x00"
	chunkNonceDomain            = "punaro/attachment/chunk-nonce/v3\x00"
)

// EncryptedChunk is one opaque encrypted source frame. It is never plaintext
// and is safe to pass only to the v3 relay data-plane route selected by its
// manifest and permit.
type EncryptedChunk struct {
	Index                uint64
	Ciphertext           []byte
	CiphertextCommitment [32]byte
}

// SourceArtifact is the sender-local encrypted representation of one file.
// FileKey is intentionally returned separately so callers can place it only
// in a recipient HPKE envelope, never in the relay upload payload.
type SourceArtifact struct {
	Manifest           Manifest
	ManifestCommitment [32]byte
	Chunks             []EncryptedChunk
}

// SourceArtifactMaterial is generated once by the local sender and then kept
// in its own durable, host-protected staging record. Reusing it is permitted
// only for replaying the exact same signed manifest after a crash; it must
// never be generated from caller-controlled values.
type SourceArtifactMaterial struct {
	FileKey     [32]byte
	ContentSalt [32]byte
}

type encryptedChunk = EncryptedChunk
type sourceArtifact = SourceArtifact

// ArtifactStore durably reserves the sender's file-key, content-salt and
// nonce tuples before encryption. It is local client state, not a relay API;
// callers must use a private non-symlinked parent directory.
type ArtifactStore struct{ store *sourceStore }

func OpenArtifactStore(path string) (*ArtifactStore, error) {
	store, err := openSourceStore(path, defaultSourceLimits())
	if err != nil {
		return nil, err
	}
	return &ArtifactStore{store: store}, nil
}

func (s *ArtifactStore) Close() error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.close()
}

// PrepareSourceArtifact encrypts a bounded file after first reserving every
// reusable cryptographic input in the caller's durable ArtifactStore.
func PrepareSourceArtifact(plaintext []byte, manifest Manifest, signer ed25519.PrivateKey, store *ArtifactStore) (SourceArtifact, [32]byte, error) {
	if store == nil {
		return SourceArtifact{}, [32]byte{}, errors.New("missing v3 artifact store")
	}
	var material SourceArtifactMaterial
	if _, err := rand.Read(material.FileKey[:]); err != nil {
		return SourceArtifact{}, [32]byte{}, fmt.Errorf("generate file key: %w", err)
	}
	if _, err := rand.Read(material.ContentSalt[:]); err != nil {
		return SourceArtifact{}, [32]byte{}, fmt.Errorf("generate content salt: %w", err)
	}
	prepared, commitment, err := PrepareSourceManifest(plaintext, manifest, signer, material)
	if err != nil {
		return SourceArtifact{}, [32]byte{}, err
	}
	artifact, err := EncryptPreparedSourceArtifact(plaintext, prepared, commitment, material.FileKey, store)
	return artifact, material.FileKey, err
}

// PrepareSourceManifest turns random source material into the one signed
// manifest which is safe to persist as a sender stage intent before any
// cryptographic reservation or ciphertext write occurs.
func PrepareSourceManifest(plaintext []byte, manifest Manifest, signer ed25519.PrivateKey, material SourceArtifactMaterial) (Manifest, [32]byte, error) {
	if len(signer) != ed25519.PrivateKeySize || material.FileKey == [32]byte{} || material.ContentSalt == [32]byte{} || manifest.ContentSalt != [32]byte{} || manifest.PlaintextCommitment != [32]byte{} || manifest.ChunkCount != 0 || manifest.PlaintextSize != 0 || manifest.Signature != [ed25519.SignatureSize]byte{} || manifest.ChunkSize == 0 || manifest.ChunkSize > 256<<10 || uint64(len(plaintext)) > 64<<20 {
		return Manifest{}, [32]byte{}, errors.New("invalid prepared source manifest input")
	}
	chunkCount := uint64(len(plaintext)) / manifest.ChunkSize
	if uint64(len(plaintext))%manifest.ChunkSize != 0 || chunkCount == 0 {
		chunkCount++
	}
	if chunkCount > 4096 {
		return Manifest{}, [32]byte{}, errors.New("invalid prepared source manifest chunks")
	}
	manifest.ContentSalt = material.ContentSalt
	manifest.PlaintextSize, manifest.ChunkCount = uint64(len(plaintext)), chunkCount
	manifest.PlaintextCommitment = plaintextCommitment(manifest.ContentSalt, manifest.PlaintextSize, plaintext)
	if err := SignManifest(&manifest, signer); err != nil {
		return Manifest{}, [32]byte{}, err
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
		return Manifest{}, [32]byte{}, err
	}
	return manifest, blake3.Sum256(raw), nil
}

// EncryptPreparedSourceArtifact reserves and encrypts one manifest previously
// produced by PrepareSourceManifest. Replaying that exact tuple is safe and
// yields byte-identical chunks; changed plaintext or manifest bytes fail
// before the reservation is touched.
func EncryptPreparedSourceArtifact(plaintext []byte, manifest Manifest, commitment [32]byte, fileKey [32]byte, store *ArtifactStore) (SourceArtifact, error) {
	if store == nil {
		return SourceArtifact{}, errors.New("missing v3 artifact store")
	}
	return encryptPreparedSourceArtifact(plaintext, manifest, commitment, fileKey, store.store)
}

// OpenSourceArtifact verifies and decrypts a fetched artifact with the file
// key recovered from a valid recipient envelope. The caller supplies the same
// fresh directory authority used to verify the manifest before decryption.
func OpenSourceArtifact(rawManifest []byte, chunks []EncryptedChunk, fileKey [32]byte, directory DirectoryKeyResolver, now time.Time) ([]byte, error) {
	source, err := DecodeAndVerifySourceInit(rawManifest, directory, now)
	if err != nil {
		return nil, err
	}
	return openSourceArtifact(source, chunks, fileKey, now)
}

// prepareSourceArtifact reserves every reusable cryptographic input durably
// before it encrypts a single frame. Its private API prevents accidental use
// as an unauthenticated relay operation.
func prepareSourceArtifact(plaintext []byte, manifest Manifest, signer ed25519.PrivateKey, store *sourceStore) (sourceArtifact, [32]byte, error) {
	if store == nil {
		return sourceArtifact{}, [32]byte{}, errors.New("missing v3 artifact store")
	}
	var material SourceArtifactMaterial
	if _, err := rand.Read(material.FileKey[:]); err != nil {
		return sourceArtifact{}, [32]byte{}, fmt.Errorf("generate file key: %w", err)
	}
	if _, err := rand.Read(material.ContentSalt[:]); err != nil {
		return sourceArtifact{}, [32]byte{}, fmt.Errorf("generate content salt: %w", err)
	}
	prepared, commitment, err := PrepareSourceManifest(plaintext, manifest, signer, material)
	if err != nil {
		return sourceArtifact{}, [32]byte{}, err
	}
	artifact, err := encryptPreparedSourceArtifact(plaintext, prepared, commitment, material.FileKey, store)
	return artifact, material.FileKey, err
}

func encryptPreparedSourceArtifact(plaintext []byte, manifest Manifest, commitment [32]byte, fileKey [32]byte, store *sourceStore) (sourceArtifact, error) {
	if store == nil || fileKey == [32]byte{} || manifest.ContentSalt == [32]byte{} || manifest.ChunkSize == 0 || manifest.ChunkCount == 0 || manifest.PlaintextSize != uint64(len(plaintext)) || manifest.PlaintextCommitment != plaintextCommitment(manifest.ContentSalt, manifest.PlaintextSize, plaintext) || uint64(len(plaintext)) > 64<<20 {
		return sourceArtifact{}, errors.New("invalid prepared source artifact")
	}
	raw, err := EncodeManifest(manifest)
	if err != nil || blake3.Sum256(raw) != commitment {
		return sourceArtifact{}, errors.New("invalid prepared source manifest")
	}
	if err := store.reserveCrypto(fileKey, raw, commitment); err != nil {
		return sourceArtifact{}, fmt.Errorf("reserve source cryptographic material: %w", err)
	}
	key, err := chunkKey(fileKey, manifest.ContentSalt, commitment)
	if err != nil {
		return sourceArtifact{}, err
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return sourceArtifact{}, err
	}
	chunks := make([]encryptedChunk, 0, manifest.ChunkCount)
	for index := uint64(0); index < manifest.ChunkCount; index++ {
		start, end := index*manifest.ChunkSize, (index+1)*manifest.ChunkSize
		if end > manifest.PlaintextSize {
			end = manifest.PlaintextSize
		}
		nonce := chunkNonce(manifest.TransferID, commitment, index)
		aad, err := chunkAAD(manifest, commitment, index, end-start)
		if err != nil {
			return sourceArtifact{}, err
		}
		ciphertext := aead.Seal(nil, nonce[:], plaintext[start:end], aad) // #nosec G407 -- tuple was durably reserved before encryption.
		chunks = append(chunks, encryptedChunk{Index: index, Ciphertext: ciphertext, CiphertextCommitment: ciphertextCommitment(ciphertext)})
	}
	return sourceArtifact{Manifest: manifest, ManifestCommitment: commitment, Chunks: chunks}, nil
}

// openSourceArtifact accepts only a source that was verified against a fresh
// directory at the receive boundary; self-consistent unsigned manifests are
// not an authenticated input to this helper.
func openSourceArtifact(source VerifiedSource, chunks []encryptedChunk, fileKey [32]byte, now time.Time) ([]byte, error) {
	manifest, commitment := source.manifest, source.commitment
	if !source.valid(now) || uint64(len(chunks)) != manifest.ChunkCount {
		return nil, errors.New("invalid source artifact")
	}
	key, err := chunkKey(fileKey, manifest.ContentSalt, commitment)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 0, manifest.PlaintextSize)
	for index := uint64(0); index < manifest.ChunkCount; index++ {
		chunk := chunks[index]
		if chunk.Index != index || chunk.CiphertextCommitment != ciphertextCommitment(chunk.Ciphertext) {
			return nil, errors.New("invalid source artifact chunk")
		}
		length := manifest.ChunkSize
		if index == manifest.ChunkCount-1 {
			length = manifest.PlaintextSize - manifest.ChunkSize*(manifest.ChunkCount-1)
		}
		nonce := chunkNonce(manifest.TransferID, commitment, index)
		aad, err := chunkAAD(manifest, commitment, index, length)
		if err != nil {
			return nil, err
		}
		part, err := aead.Open(nil, nonce[:], chunk.Ciphertext, aad)
		if err != nil || uint64(len(part)) != length {
			return nil, errors.New("invalid source artifact ciphertext")
		}
		plaintext = append(plaintext, part...)
	}
	if uint64(len(plaintext)) != manifest.PlaintextSize || plaintextCommitment(manifest.ContentSalt, manifest.PlaintextSize, plaintext) != manifest.PlaintextCommitment {
		return nil, errors.New("invalid source artifact plaintext")
	}
	return plaintext, nil
}

func (s *sourceStore) reserveCrypto(fileKey [32]byte, raw []byte, commitment [32]byte) error {
	manifest, err := DecodeManifest(raw)
	if s == nil || s.db == nil || err != nil || fileKey == [32]byte{} || manifest.ContentSalt == [32]byte{} || manifest.TransferID == [16]byte{} || commitment == [32]byte{} || manifest.ChunkCount == 0 || manifest.ChunkCount > 4096 || blake3.Sum256(raw) != commitment {
		return errors.New("invalid cryptographic reservation")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	fileKeyCommitment := fileKeyCommitment(fileKey)
	// A controller crash may leave the local stage intent but no ciphertext
	// journal. Replaying the exact already-reserved tuple is safe; any partial
	// or mismatched tuple remains a hard failure. This check happens before
	// admission accounting so retries cannot exhaust the permanent budget.
	var existing int
	err = tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM v3_source_file_keys WHERE commitment=?`, fileKeyCommitment[:]).Scan(&existing)
	if err != nil {
		return err
	}
	if existing != 0 {
		contentSaltCommitment := contentSaltCommitment(manifest.ContentSalt)
		var salts, nonces int
		if err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM v3_source_content_salts WHERE commitment=?`, contentSaltCommitment[:]).Scan(&salts); err != nil {
			return err
		}
		if err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM v3_source_nonce_tuples WHERE transfer_id=? AND manifest_commitment=?`, manifest.TransferID[:], commitment[:]).Scan(&nonces); err != nil {
			return err
		}
		if salts != 1 || nonces != int(manifest.ChunkCount) {
			return errors.New("incomplete source cryptographic reservation")
		}
		return nil
	}
	if err := s.admitCryptoTx(tx, sourceSpec{Manifest: raw}, manifest.ChunkCount+2); err != nil {
		return err
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO v3_source_file_keys(commitment) VALUES (?)`, fileKeyCommitment[:]); err != nil {
		return errors.New("source file key already reserved")
	}
	contentSaltCommitment := contentSaltCommitment(manifest.ContentSalt)
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO v3_source_content_salts(commitment) VALUES (?)`, contentSaltCommitment[:]); err != nil {
		return errors.New("source content salt already reserved")
	}
	for index := uint64(0); index < manifest.ChunkCount; index++ {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO v3_source_nonce_tuples(transfer_id, manifest_commitment, chunk_index) VALUES (?, ?, ?)`, manifest.TransferID[:], commitment[:], index); err != nil {
			return errors.New("source nonce already reserved")
		}
	}
	return tx.Commit()
}

func plaintextCommitment(salt [32]byte, size uint64, plaintext []byte) [32]byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], size)
	return blake3.Sum256(append(append(append([]byte(plaintextCommitmentDomain), salt[:]...), encoded[:]...), plaintext...))
}
func fileKeyCommitment(fileKey [32]byte) [32]byte {
	return blake3.Sum256(append([]byte(fileKeyCommitmentDomain), fileKey[:]...))
}
func contentSaltCommitment(salt [32]byte) [32]byte {
	return blake3.Sum256(append([]byte(contentSaltCommitmentDomain), salt[:]...))
}
func chunkKey(fileKey, salt, commitment [32]byte) ([32]byte, error) {
	material, err := hkdf.Key(sha256.New, fileKey[:], salt[:], string(append([]byte(chunkKeyDomain), commitment[:]...)), chacha20poly1305.KeySize)
	if err != nil {
		return [32]byte{}, err
	}
	var key [32]byte
	copy(key[:], material)
	return key, nil
}
func chunkNonce(transferID [16]byte, commitment [32]byte, index uint64) [chacha20poly1305.NonceSizeX]byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], index)
	digest := blake3.Sum256(append(append(append([]byte(chunkNonceDomain), transferID[:]...), commitment[:]...), encoded[:]...))
	var nonce [chacha20poly1305.NonceSizeX]byte
	copy(nonce[:], digest[:])
	return nonce
}
func chunkAAD(manifest Manifest, commitment [32]byte, index, plainLength uint64) ([]byte, error) {
	return canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: manifest.TransferID, 3: commitment, 4: index, 5: manifest.ChunkCount, 6: plainLength})
}
