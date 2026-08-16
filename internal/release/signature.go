package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"regexp"
)

const (
	// MaximumEnvelopeBytes bounds one detached signature envelope.
	MaximumEnvelopeBytes = 8 << 10
	maxSignatures        = 4
	ed25519SignatureSize = ed25519.SignatureSize
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Envelope is the detached Ed25519 signature document for a catalog or manifest.
type Envelope struct {
	Schema     int64               `json:"schema"`
	Signatures []EnvelopeSignature `json:"signatures"`
}

// EnvelopeSignature binds one key ID to a 64-byte Ed25519 signature.
type EnvelopeSignature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// ParseEnvelope strictly parses one detached signature envelope.
func ParseEnvelope(body []byte) (Envelope, error) {
	envelope, err := decodeStrict[Envelope](body, MaximumEnvelopeBytes)
	if err != nil || envelope.validate() != nil {
		return Envelope{}, errors.New("release signature is invalid")
	}
	return envelope, nil
}

func (envelope Envelope) validate() error {
	if envelope.Schema != releaseDocumentSchema || len(envelope.Signatures) == 0 || len(envelope.Signatures) > maxSignatures {
		return errors.New("invalid signature envelope")
	}
	seen := map[string]struct{}{}
	for _, signature := range envelope.Signatures {
		if !keyIDPattern.MatchString(signature.KeyID) {
			return errors.New("invalid signature envelope")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(signature.Signature)
		if err != nil || len(decoded) != ed25519SignatureSize {
			return errors.New("invalid signature envelope")
		}
		if _, exists := seen[signature.KeyID]; exists {
			return errors.New("invalid signature envelope")
		}
		seen[signature.KeyID] = struct{}{}
	}
	return nil
}

// Sign returns a one-signature envelope over the exact document bytes.
func Sign(document []byte, keyID string, private ed25519.PrivateKey) (Envelope, error) {
	if len(document) == 0 || !keyIDPattern.MatchString(keyID) || len(private) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("release signature is invalid")
	}
	return Envelope{
		Schema: releaseDocumentSchema,
		Signatures: []EnvelopeSignature{{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, document)),
		}},
	}, nil
}

// AppendSignature adds one more unique key's signature to an existing envelope.
func AppendSignature(envelope Envelope, document []byte, keyID string, private ed25519.PrivateKey) (Envelope, error) {
	if envelope.validate() != nil || len(document) == 0 || !keyIDPattern.MatchString(keyID) || len(private) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("release signature is invalid")
	}
	for _, signature := range envelope.Signatures {
		if signature.KeyID == keyID {
			return Envelope{}, errors.New("release signature is invalid")
		}
	}
	if len(envelope.Signatures) >= maxSignatures {
		return Envelope{}, errors.New("release signature is invalid")
	}
	envelope.Signatures = append(append([]EnvelopeSignature{}, envelope.Signatures...), EnvelopeSignature{
		KeyID:     keyID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, document)),
	})
	return envelope, nil
}

// Verify accepts a document when at least one envelope signature matches a
// trusted embedded public key. It does not parse the document.
func Verify(document []byte, envelope Envelope, keys map[string]ed25519.PublicKey) error {
	if len(document) == 0 || envelope.validate() != nil || len(keys) == 0 {
		return errors.New("release signature is invalid")
	}
	for _, signature := range envelope.Signatures {
		public, ok := keys[signature.KeyID]
		if !ok || len(public) != ed25519.PublicKeySize {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(signature.Signature)
		if err != nil {
			return errors.New("release signature is invalid")
		}
		if ed25519.Verify(public, document, decoded) {
			return nil
		}
	}
	return errors.New("release signature is invalid")
}

func encodeEnvelope(envelope Envelope) ([]byte, error) {
	if envelope.validate() != nil {
		return nil, errors.New("release signature is invalid")
	}
	return encodeDocument(envelope)
}
