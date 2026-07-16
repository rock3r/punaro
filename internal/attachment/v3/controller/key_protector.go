package controller

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const senderKeyWrapVersion byte = 1

// HostKeyProvider obtains a 32-byte key-encryption key from the local host
// credential boundary (Keychain, TPM or an equivalent OS secret service). It
// is deliberately not an environment-variable or journal reader.
type HostKeyProvider interface {
	SenderKeyEncryptionKey(context.Context) ([32]byte, error)
	SenderKeyEncryptionKeyID(context.Context) ([32]byte, error)
}

// HostAEADFileKeyProtector is the sole standard wrapping implementation. Its
// caller supplies a host credential provider; the SQLite journal receives only
// version, non-secret key ID, nonce, and AEAD ciphertext.
type HostAEADFileKeyProtector struct {
	provider HostKeyProvider
	random   io.Reader
}

func NewHostAEADFileKeyProtector(provider HostKeyProvider) (*HostAEADFileKeyProtector, error) {
	if provider == nil {
		return nil, errors.New("missing host key provider")
	}
	return &HostAEADFileKeyProtector{provider: provider, random: rand.Reader}, nil
}

func (p *HostAEADFileKeyProtector) SealSenderFileKey(ctx context.Context, fileKey [32]byte, aad []byte) ([]byte, error) {
	if p == nil || p.provider == nil || fileKey == [32]byte{} || len(aad) == 0 {
		return nil, errors.New("invalid sender key wrap")
	}
	kek, err := p.provider.SenderKeyEncryptionKey(ctx)
	if err != nil || kek == [32]byte{} {
		return nil, errors.New("host key is unavailable")
	}
	id, err := p.provider.SenderKeyEncryptionKeyID(ctx)
	if err != nil || id == [32]byte{} {
		return nil, errors.New("host key identity is unavailable")
	}
	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(p.random, nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, fileKey[:], aad)
	out := make([]byte, 1+len(id)+len(nonce)+len(sealed))
	out[0] = senderKeyWrapVersion
	copy(out[1:], id[:])
	copy(out[1+len(id):], nonce)
	copy(out[1+len(id)+len(nonce):], sealed)
	return out, nil
}

func (p *HostAEADFileKeyProtector) OpenSenderFileKey(ctx context.Context, wrapped, aad []byte) ([32]byte, error) {
	var out [32]byte
	if p == nil || p.provider == nil || len(aad) == 0 {
		return out, errors.New("invalid sender key unwrap")
	}
	kek, err := p.provider.SenderKeyEncryptionKey(ctx)
	if err != nil || kek == [32]byte{} {
		return out, errors.New("host key is unavailable")
	}
	id, err := p.provider.SenderKeyEncryptionKeyID(ctx)
	if err != nil || id == [32]byte{} {
		return out, errors.New("host key identity is unavailable")
	}
	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return out, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return out, err
	}
	minimum := 1 + len(id) + aead.NonceSize() + len(out) + aead.Overhead()
	if len(wrapped) != minimum || wrapped[0] != senderKeyWrapVersion || !equal32(wrapped[1:1+len(id)], id) {
		return out, errors.New("invalid sender key wrapper")
	}
	plain, err := aead.Open(nil, wrapped[1+len(id):1+len(id)+aead.NonceSize()], wrapped[1+len(id)+aead.NonceSize():], aad)
	if err != nil || len(plain) != len(out) {
		return out, errors.New("invalid sender key wrapper")
	}
	copy(out[:], plain)
	return out, nil
}

func equal32(raw []byte, value [32]byte) bool { return bytes.Equal(raw, value[:]) }
