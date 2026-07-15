package v3

import (
	"bytes"
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

type encryptedChunk struct {
	Index                uint64
	Ciphertext           []byte
	CiphertextCommitment [32]byte
}

type sourceArtifact struct {
	Manifest           Manifest
	ManifestCommitment [32]byte
	Chunks             []encryptedChunk
}

// prepareSourceArtifact reserves every reusable cryptographic input durably
// before it encrypts a single frame. Its private API prevents accidental use
// as an unauthenticated relay operation.
func prepareSourceArtifact(plaintext []byte, manifest Manifest, signer ed25519.PrivateKey, store *sourceStore) (sourceArtifact, [32]byte, error) {
	if store == nil || len(signer) != ed25519.PrivateKeySize || manifest.ContentSalt != [32]byte{} || manifest.PlaintextCommitment != [32]byte{} || manifest.ChunkCount != 0 || manifest.PlaintextSize != 0 || manifest.Signature != [ed25519.SignatureSize]byte{} || manifest.ChunkSize == 0 || manifest.ChunkSize > 256<<10 || uint64(len(plaintext)) > 64<<20 {
		return sourceArtifact{}, [32]byte{}, errors.New("invalid source artifact input")
	}
	chunkCount := uint64(len(plaintext)) / manifest.ChunkSize
	if uint64(len(plaintext))%manifest.ChunkSize != 0 || chunkCount == 0 {
		chunkCount++
	}
	if chunkCount > 4096 {
		return sourceArtifact{}, [32]byte{}, errors.New("invalid source artifact chunk count")
	}
	if _, err := rand.Read(manifest.ContentSalt[:]); err != nil {
		return sourceArtifact{}, [32]byte{}, fmt.Errorf("generate content salt: %w", err)
	}
	var fileKey [32]byte
	if _, err := rand.Read(fileKey[:]); err != nil {
		return sourceArtifact{}, [32]byte{}, fmt.Errorf("generate file key: %w", err)
	}
	manifest.PlaintextSize, manifest.ChunkCount = uint64(len(plaintext)), chunkCount
	manifest.PlaintextCommitment = plaintextCommitment(manifest.ContentSalt, manifest.PlaintextSize, plaintext)
	if err := SignManifest(&manifest, signer); err != nil {
		return sourceArtifact{}, [32]byte{}, err
	}
	raw, err := EncodeManifest(manifest)
	if err != nil {
		return sourceArtifact{}, [32]byte{}, err
	}
	commitment := blake3.Sum256(raw)
	if err := store.reserveCrypto(fileKey, manifest, raw, commitment); err != nil {
		return sourceArtifact{}, [32]byte{}, fmt.Errorf("reserve source cryptographic material: %w", err)
	}
	key, err := chunkKey(fileKey, manifest.ContentSalt, commitment)
	if err != nil {
		return sourceArtifact{}, [32]byte{}, err
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return sourceArtifact{}, [32]byte{}, err
	}
	chunks := make([]encryptedChunk, 0, chunkCount)
	for index := uint64(0); index < chunkCount; index++ {
		start, end := index*manifest.ChunkSize, (index+1)*manifest.ChunkSize
		if end > manifest.PlaintextSize {
			end = manifest.PlaintextSize
		}
		nonce := chunkNonce(manifest.TransferID, commitment, index)
		aad, err := chunkAAD(manifest, commitment, index, end-start)
		if err != nil {
			return sourceArtifact{}, [32]byte{}, err
		}
		ciphertext := aead.Seal(nil, nonce[:], plaintext[start:end], aad) // #nosec G407 -- tuple was durably reserved before encryption.
		chunks = append(chunks, encryptedChunk{Index: index, Ciphertext: ciphertext, CiphertextCommitment: ciphertextCommitment(ciphertext)})
	}
	return sourceArtifact{Manifest: manifest, ManifestCommitment: commitment, Chunks: chunks}, fileKey, nil
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
	for index, chunk := range chunks {
		if chunk.Index != uint64(index) || chunk.CiphertextCommitment != ciphertextCommitment(chunk.Ciphertext) {
			return nil, errors.New("invalid source artifact chunk")
		}
		length := manifest.ChunkSize
		if uint64(index) == manifest.ChunkCount-1 {
			length = manifest.PlaintextSize - manifest.ChunkSize*(manifest.ChunkCount-1)
		}
		nonce := chunkNonce(manifest.TransferID, commitment, uint64(index))
		aad, err := chunkAAD(manifest, commitment, uint64(index), length)
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

func (s *sourceStore) reserveCrypto(fileKey [32]byte, manifest Manifest, raw []byte, commitment [32]byte) error {
	expectedRaw, err := EncodeManifest(manifest)
	if s == nil || s.db == nil || err != nil || !bytes.Equal(raw, expectedRaw) || fileKey == [32]byte{} || manifest.ContentSalt == [32]byte{} || manifest.TransferID == [16]byte{} || commitment == [32]byte{} || manifest.ChunkCount == 0 || manifest.ChunkCount > 4096 || blake3.Sum256(raw) != commitment {
		return errors.New("invalid cryptographic reservation")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.admitCryptoTx(tx, sourceSpec{Manifest: raw}, manifest.ChunkCount+2); err != nil {
		return err
	}
	fileKeyCommitment := fileKeyCommitment(fileKey)
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
