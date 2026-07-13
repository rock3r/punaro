// Package attachment implements the cryptographic attachment data-plane primitives.
package attachment

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/zeebo/blake3"
)

const (
	// ContentSaltSize is the size of a per-manifest CSPRNG content salt.
	ContentSaltSize = 32
	hashSize        = 32
	contentDomain   = "punaro/attachment/content/v2\x00"
	plainDomain     = "punaro/attachment/plaintext/v2\x00"
)

// Manifest binds exactly one plaintext to a unique content salt. It contains no
// filename, MIME type, encryption key, or plaintext bytes.
type Manifest struct {
	ContentSalt       []byte
	ContentCommitment [hashSize]byte
}

// NewManifest creates a cryptographic content binding for plaintext.
func NewManifest(plaintext []byte) (Manifest, error) {
	salt := make([]byte, ContentSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return Manifest{}, fmt.Errorf("generate content salt: %w", err)
	}
	plaintextHash := hash(plainDomain, plaintext)
	return Manifest{ContentSalt: salt, ContentCommitment: hash(contentDomain, salt, plaintextHash[:])}, nil
}

// Verifies reports whether plaintext is the sole plaintext committed by m.
func (m Manifest) Verifies(plaintext []byte) bool {
	if len(m.ContentSalt) != ContentSaltSize {
		return false
	}
	plaintextHash := hash(plainDomain, plaintext)
	commitment := hash(contentDomain, m.ContentSalt, plaintextHash[:])
	return subtle.ConstantTimeCompare(commitment[:], m.ContentCommitment[:]) == 1
}

func hash(domain string, values ...[]byte) [hashSize]byte {
	hasher := blake3.New()
	_, _ = hasher.Write([]byte(domain))
	for _, value := range values {
		_, _ = hasher.Write(value)
	}
	var result [hashSize]byte
	copy(result[:], hasher.Sum(nil))
	return result
}
