package attachment

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	artifactIDSize = 16
	fileKeySize    = chacha20poly1305.KeySize
)

// Artifact contains encrypted, index-bound attachment chunks. It is suitable for
// a relay blob store because it never contains plaintext after construction.
type Artifact struct {
	TransferID [artifactIDSize]byte
	ArtifactID [artifactIDSize]byte
	FileKey    [fileKeySize]byte
	ChunkSize  int
	ChunkCount int
	Chunks     []Chunk
}

// Chunk is an immutable authenticated ciphertext frame.
type Chunk struct {
	Index      int
	Ciphertext []byte
	Hash       [hashSize]byte
}

// EncryptArtifact encrypts plaintext into fixed-size, index-bound XChaCha20
// chunks. transferID must be an opaque 128-bit transfer identifier.
func EncryptArtifact(transferID, plaintext []byte, chunkSize int) (Artifact, error) {
	if len(transferID) != artifactIDSize {
		return Artifact{}, fmt.Errorf("transfer ID must be %d bytes", artifactIDSize)
	}
	if chunkSize <= 0 || chunkSize > 255<<10 {
		return Artifact{}, fmt.Errorf("invalid chunk size %d", chunkSize)
	}
	artifact := Artifact{ChunkSize: chunkSize}
	copy(artifact.TransferID[:], transferID)
	if _, err := rand.Read(artifact.ArtifactID[:]); err != nil {
		return Artifact{}, fmt.Errorf("generate artifact ID: %w", err)
	}
	if _, err := rand.Read(artifact.FileKey[:]); err != nil {
		return Artifact{}, fmt.Errorf("generate file key: %w", err)
	}
	aead, err := chacha20poly1305.NewX(artifact.FileKey[:])
	if err != nil {
		return Artifact{}, fmt.Errorf("create chunk cipher: %w", err)
	}
	count := (len(plaintext) + chunkSize - 1) / chunkSize
	if count == 0 {
		count = 1
	}
	artifact.ChunkCount = count
	artifact.Chunks = make([]Chunk, 0, count)
	for index := 0; index < count; index++ {
		start := index * chunkSize
		end := start + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := plaintext[start:end]
		// #nosec G407 -- nonce is deterministically unique for the durable
		// (transfer, artifact, index) tuple; artifact IDs are CSPRNG-generated.
		ciphertext := aead.Seal(nil, artifact.nonce(index), chunk, artifact.aad(index, len(chunk)))
		artifact.Chunks = append(artifact.Chunks, Chunk{Index: index, Ciphertext: ciphertext, Hash: hash("punaro/attachment/ciphertext/v2\x00", ciphertext)})
	}
	return artifact, nil
}

// Decrypt validates every frame before returning the ordered plaintext.
func (a Artifact) Decrypt() ([]byte, error) {
	if a.ChunkCount < 1 || len(a.Chunks) != a.ChunkCount || a.ChunkSize <= 0 {
		return nil, fmt.Errorf("invalid artifact chunk layout")
	}
	aead, err := chacha20poly1305.NewX(a.FileKey[:])
	if err != nil {
		return nil, fmt.Errorf("create chunk cipher: %w", err)
	}
	plaintext := make([]byte, 0, a.ChunkCount*a.ChunkSize)
	for index, chunk := range a.Chunks {
		if chunk.Index != index {
			return nil, fmt.Errorf("unexpected chunk index %d", chunk.Index)
		}
		computedHash := hash("punaro/attachment/ciphertext/v2\x00", chunk.Ciphertext)
		if subtle.ConstantTimeCompare(computedHash[:], chunk.Hash[:]) != 1 {
			return nil, fmt.Errorf("chunk %d hash mismatch", index)
		}
		if len(chunk.Ciphertext) < aead.Overhead() {
			return nil, fmt.Errorf("chunk %d is too short", index)
		}
		plainLen := len(chunk.Ciphertext) - aead.Overhead()
		if index < a.ChunkCount-1 && plainLen != a.ChunkSize || index == a.ChunkCount-1 && plainLen > a.ChunkSize {
			return nil, fmt.Errorf("chunk %d has invalid plaintext length", index)
		}
		plain, err := aead.Open(nil, a.nonce(index), chunk.Ciphertext, a.aad(index, plainLen))
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk %d: %w", index, err)
		}
		plaintext = append(plaintext, plain...)
	}
	return plaintext, nil
}

func (a Artifact) nonce(index int) []byte {
	if index < 0 {
		panic("attachment chunk index must be non-negative")
	}
	var indexBytes [8]byte
	// #nosec G115 -- caller validates index is non-negative and bounded by chunk count.
	binary.BigEndian.PutUint64(indexBytes[:], uint64(index))
	material := hash("punaro/attachment/chunk-nonce/v2\x00", a.TransferID[:], a.ArtifactID[:], indexBytes[:])
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	copy(nonce, material[:])
	return nonce
}

func (a Artifact) aad(index, plaintextLength int) []byte {
	if index < 0 || plaintextLength < 0 {
		panic("attachment AAD values must be non-negative")
	}
	var values [16]byte
	// #nosec G115 -- checked non-negative bounds above.
	binary.BigEndian.PutUint64(values[:8], uint64(index))
	// #nosec G115 -- checked non-negative bounds above.
	binary.BigEndian.PutUint64(values[8:], uint64(plaintextLength))
	return append(append(append([]byte("punaro/attachment/chunk-aad/v2\x00"), a.TransferID[:]...), a.ArtifactID[:]...), values[:]...)
}
