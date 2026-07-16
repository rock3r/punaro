package v2

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	plaintextCommitmentDomain   = "punaro/attachment/plaintext/v2\x00"
	fileKeyCommitmentDomain     = "punaro/attachment/file-key/v2\x00"
	contentSaltCommitmentDomain = "punaro/attachment/content-salt/v2\x00"
	chunkKeyDomain              = "punaro/attachment/chunk-key/v2\x00"
	chunkNonceDomain            = "punaro/attachment/chunk-nonce/v2\x00"
	ciphertextCommitmentDomain  = "punaro/attachment/ciphertext/v2\x00"
)

// NonceReservation is a durable uniqueness tuple. A store must retain every
// accepted tuple permanently, including when later encryption or upload fails.
type NonceReservation struct {
	TransferID         [16]byte
	ManifestCommitment [32]byte
	ChunkIndex         uint64
}

// SourceReservationStore durably reserves a file-key fingerprint and every
// chunk nonce tuple in one all-or-nothing operation before encryption starts.
// A collision must be rejected; callers must never retry it with the same
// material after a failed or indeterminate reservation.
type SourceReservationStore interface {
	Reserve(fileKeyCommitment, contentSaltCommitment [32]byte, nonces []NonceReservation) error
}

// EncryptedChunk is one immutable, manifest-bound ciphertext frame.
type EncryptedChunk struct {
	Index                uint64
	Ciphertext           []byte
	CiphertextCommitment [32]byte
}

// SourceArtifact is the complete source-ready artifact. FileKey is returned
// separately for immediate recipient-envelope sealing and is never retained in
// this value or written to a relay artifact store.
type SourceArtifact struct {
	Manifest           Manifest
	ManifestCommitment [32]byte
	Chunks             []EncryptedChunk
}

// PrepareSourceArtifact fills and signs an otherwise unsigned manifest,
// reserves all cryptographic uniqueness material durably, then encrypts every
// chunk. The returned source artifact is suitable for an atomic source-ready
// transition once its manifest, envelope, and ciphertext are durably stored.
func PrepareSourceArtifact(plaintext []byte, manifest Manifest, signer ed25519.PrivateKey, reservations SourceReservationStore) (SourceArtifact, [32]byte, error) {
	if reservations == nil || len(signer) != ed25519.PrivateKeySize || !isZero32(manifest.ContentSalt) || !isZero32(manifest.PlaintextCommitment) || manifest.ChunkCount != 0 || manifest.PlaintextSize != 0 || manifest.Signature != [ed25519.SignatureSize]byte{} || manifest.ChunkSize == 0 || manifest.ChunkSize > 256<<10 || uint64(len(plaintext)) > 64<<20 {
		return SourceArtifact{}, [32]byte{}, errors.New("invalid source artifact input")
	}
	chunkCount := uint64(len(plaintext)) / manifest.ChunkSize
	if uint64(len(plaintext))%manifest.ChunkSize != 0 || chunkCount == 0 {
		chunkCount++
	}
	if chunkCount > 4096 {
		return SourceArtifact{}, [32]byte{}, errors.New("invalid source artifact chunk count")
	}
	if _, err := rand.Read(manifest.ContentSalt[:]); err != nil {
		return SourceArtifact{}, [32]byte{}, fmt.Errorf("generate content salt: %w", err)
	}
	var fileKey [32]byte
	if _, err := rand.Read(fileKey[:]); err != nil {
		return SourceArtifact{}, [32]byte{}, fmt.Errorf("generate file key: %w", err)
	}
	manifest.PlaintextSize = uint64(len(plaintext))
	manifest.ChunkCount = chunkCount
	manifest.PlaintextCommitment = plaintextCommitment(manifest.ContentSalt, manifest.PlaintextSize, plaintext)
	if err := SignManifest(&manifest, signer); err != nil {
		return SourceArtifact{}, [32]byte{}, fmt.Errorf("sign source manifest: %w", err)
	}
	commitment, err := manifestCommitment(manifest)
	if err != nil {
		return SourceArtifact{}, [32]byte{}, err
	}
	nonces := make([]NonceReservation, chunkCount)
	for index := uint64(0); index < chunkCount; index++ {
		nonces[index] = NonceReservation{TransferID: manifest.TransferID, ManifestCommitment: commitment, ChunkIndex: index}
	}
	if err := reservations.Reserve(fileKeyCommitment(fileKey), contentSaltCommitment(manifest.ContentSalt), nonces); err != nil {
		return SourceArtifact{}, [32]byte{}, fmt.Errorf("reserve source cryptographic material: %w", err)
	}
	key, err := chunkKey(fileKey, manifest.ContentSalt, commitment)
	if err != nil {
		return SourceArtifact{}, [32]byte{}, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return SourceArtifact{}, [32]byte{}, err
	}
	chunks := make([]EncryptedChunk, 0, chunkCount)
	for index := uint64(0); index < chunkCount; index++ {
		start := index * manifest.ChunkSize
		end := start + manifest.ChunkSize
		if end > manifest.PlaintextSize {
			end = manifest.PlaintextSize
		}
		nonce := chunkNonce(manifest.TransferID, commitment, index)
		aad, err := chunkAAD(manifest, commitment, index, end-start)
		if err != nil {
			return SourceArtifact{}, [32]byte{}, err
		}
		ciphertext := aead.Seal(nil, nonce[:], plaintext[start:end], aad) // #nosec G407 -- the unique reserved tuple deterministically derives this nonce.
		chunks = append(chunks, EncryptedChunk{Index: index, Ciphertext: ciphertext, CiphertextCommitment: ciphertextCommitment(ciphertext)})
	}
	return SourceArtifact{Manifest: manifest, ManifestCommitment: commitment, Chunks: chunks}, fileKey, nil
}

// OpenSourceArtifact decrypts and verifies an exact immutable chunk sequence.
// Callers receiving an artifact must verify its manifest against a fresh
// directory before calling this cryptographic helper.
func OpenSourceArtifact(manifest Manifest, commitment [32]byte, chunks []EncryptedChunk, fileKey [32]byte) ([]byte, error) {
	if validateManifest(manifest) != nil || isZero32(commitment) || uint64(len(chunks)) != manifest.ChunkCount {
		return nil, errors.New("invalid source artifact")
	}
	actualCommitment, err := manifestCommitment(manifest)
	if err != nil || actualCommitment != commitment {
		return nil, errors.New("invalid source artifact commitment")
	}
	key, err := chunkKey(fileKey, manifest.ContentSalt, commitment)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 0, manifest.PlaintextSize)
	for index := uint64(0); index < manifest.ChunkCount; index++ {
		chunk := chunks[index]
		if chunk.Index != index || ciphertextCommitment(chunk.Ciphertext) != chunk.CiphertextCommitment {
			return nil, errors.New("invalid source artifact chunk")
		}
		plainLength := manifest.ChunkSize
		if index == manifest.ChunkCount-1 {
			plainLength = manifest.PlaintextSize - manifest.ChunkSize*(manifest.ChunkCount-1)
		}
		nonce := chunkNonce(manifest.TransferID, commitment, index)
		aad, err := chunkAAD(manifest, commitment, index, plainLength)
		if err != nil {
			return nil, err
		}
		part, err := aead.Open(nil, nonce[:], chunk.Ciphertext, aad)
		if err != nil || uint64(len(part)) != plainLength {
			return nil, errors.New("invalid source artifact ciphertext")
		}
		plaintext = append(plaintext, part...)
	}
	if uint64(len(plaintext)) != manifest.PlaintextSize || plaintextCommitment(manifest.ContentSalt, manifest.PlaintextSize, plaintext) != manifest.PlaintextCommitment {
		return nil, errors.New("invalid source artifact plaintext")
	}
	return plaintext, nil
}

func plaintextCommitment(salt [32]byte, size uint64, plaintext []byte) [32]byte {
	var encodedSize [8]byte
	binary.BigEndian.PutUint64(encodedSize[:], size)
	return blake3.Sum256(append(append(append([]byte(plaintextCommitmentDomain), salt[:]...), encodedSize[:]...), plaintext...))
}

func fileKeyCommitment(fileKey [32]byte) [32]byte {
	return blake3.Sum256(append([]byte(fileKeyCommitmentDomain), fileKey[:]...))
}

func contentSaltCommitment(contentSalt [32]byte) [32]byte {
	return blake3.Sum256(append([]byte(contentSaltCommitmentDomain), contentSalt[:]...))
}

func ciphertextCommitment(ciphertext []byte) [32]byte {
	return blake3.Sum256(append([]byte(ciphertextCommitmentDomain), ciphertext...))
}

func chunkKey(fileKey, salt, commitment [32]byte) ([32]byte, error) {
	info := append([]byte(chunkKeyDomain), commitment[:]...)
	derived, err := hkdf.Key(sha256.New, fileKey[:], salt[:], string(info), chacha20poly1305.KeySize)
	if err != nil {
		return [32]byte{}, err
	}
	var key [32]byte
	copy(key[:], derived)
	return key, nil
}

func chunkNonce(transferID [16]byte, commitment [32]byte, index uint64) [chacha20poly1305.NonceSize]byte {
	var encodedIndex [8]byte
	binary.BigEndian.PutUint64(encodedIndex[:], index)
	payload := append([]byte(chunkNonceDomain), transferID[:]...)
	payload = append(payload, commitment[:]...)
	payload = append(payload, encodedIndex[:]...)
	digest := blake3.Sum256(payload)
	var nonce [chacha20poly1305.NonceSize]byte
	copy(nonce[:], digest[:])
	return nonce
}

func chunkAAD(manifest Manifest, commitment [32]byte, index, plainLength uint64) ([]byte, error) {
	return canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: manifest.TransferID, 3: commitment, 4: index, 5: manifest.ChunkCount, 6: plainLength})
}
