package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
)

// PublicKeysFile is the committed or operator-held set of release-verifying keys.
type PublicKeysFile struct {
	Schema int64             `json:"schema"`
	Keys   []PublicKeyRecord `json:"keys"`
}

// PublicKeyRecord is one embedded Ed25519 public key.
type PublicKeyRecord struct {
	KeyID         string `json:"key_id"`
	PublicEd25519 string `json:"public_ed25519"`
}

// ParsePublicKeys strictly parses a public key set. Empty sets are rejected.
func ParsePublicKeys(body []byte) (map[string]ed25519.PublicKey, error) {
	document, err := decodeStrict[PublicKeysFile](body, MaximumEnvelopeBytes)
	if err != nil || document.Schema != releaseDocumentSchema || len(document.Keys) == 0 || len(document.Keys) > maxSignatures {
		return nil, errors.New("release public keys are invalid")
	}
	keys := make(map[string]ed25519.PublicKey, len(document.Keys))
	for _, record := range document.Keys {
		if !keyIDPattern.MatchString(record.KeyID) {
			return nil, errors.New("release public keys are invalid")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(record.PublicEd25519)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("release public keys are invalid")
		}
		if _, exists := keys[record.KeyID]; exists {
			return nil, errors.New("release public keys are invalid")
		}
		keys[record.KeyID] = ed25519.PublicKey(decoded)
	}
	return keys, nil
}

// EncodePublicKeys writes one verifying key in the public key-set format.
func EncodePublicKeys(keyID string, public ed25519.PublicKey) ([]byte, error) {
	if !keyIDPattern.MatchString(keyID) || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("release public keys are invalid")
	}
	return encodeDocument(PublicKeysFile{
		Schema: releaseDocumentSchema,
		Keys: []PublicKeyRecord{{
			KeyID:         keyID,
			PublicEd25519: base64.RawURLEncoding.EncodeToString(public),
		}},
	})
}

// EncodePrivateKey encodes one 64-byte Ed25519 private key as raw base64url.
func EncodePrivateKey(private ed25519.PrivateKey) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(private))
}

// ParsePrivateKey accepts only the exact raw-base64url private key encoding.
func ParsePrivateKey(body []byte) (ed25519.PrivateKey, error) {
	if len(body) != base64.RawURLEncoding.EncodedLen(ed25519.PrivateKeySize) {
		return nil, errors.New("release private key is invalid")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(body))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("release private key is invalid")
	}
	return ed25519.PrivateKey(decoded), nil
}

// EncodeEnvelope writes the detached signature document.
func EncodeEnvelope(envelope Envelope) ([]byte, error) {
	return encodeEnvelope(envelope)
}
