package v3

import (
	"encoding/base64"
	"errors"
	"strings"
)

const (
	// offerNoticePrefix deliberately identifies a typed, inert relay body. It
	// is not a URL and it never grants download authority by itself.
	offerNoticePrefix = "punaro/attachment-offer/v3:"
	// The relay accepts opaque bodies up to 32 KiB. Keep this independent of
	// the relay package so the protocol record does not acquire a transport
	// dependency; EncodeOfferNotice enforces the same public boundary.
	maxOfferNoticeBodyBytes = 32 << 10
)

// OfferNotice is the exact canonical offer payload transported through the
// normal durable relay. The mailbox delivery is merely discovery: recipients
// must still fresh-verify the manifest and envelope and obtain their own
// operation permits before the attachment service accepts a request.
type OfferNotice struct {
	Raw             []byte
	Manifest        Manifest
	ManifestRaw     []byte
	Envelope        Envelope
	EnvelopeRaw     []byte
	AcceptanceNonce [32]byte
}

// EncodeOfferNotice returns the one bounded text envelope admitted into an
// existing relay conversation. It accepts only a fully canonical v3 offer;
// callers cannot wrap arbitrary mailbox content as an attachment notice.
func EncodeOfferNotice(rawOffer []byte) (string, error) {
	notice, err := decodeOfferNoticePayload(rawOffer)
	if err != nil || len(notice.Raw) == 0 {
		return "", errors.New("invalid v3 offer notice")
	}
	encoded := offerNoticePrefix + base64.RawURLEncoding.EncodeToString(notice.Raw)
	if len(encoded) > maxOfferNoticeBodyBytes {
		return "", errors.New("v3 offer notice exceeds relay body limit")
	}
	return encoded, nil
}

// DecodeOfferNotice recognizes exactly the canonical offer-notice grammar.
// Non-notice mailbox messages and invalid or padded base64 are rejected; the
// adapter must continue treating every other mailbox body as opaque text.
func DecodeOfferNotice(body string) (OfferNotice, error) {
	if !strings.HasPrefix(body, offerNoticePrefix) {
		return OfferNotice{}, errors.New("not a v3 offer notice")
	}
	encoded := strings.TrimPrefix(body, offerNoticePrefix)
	if encoded == "" || len(body) > maxOfferNoticeBodyBytes || strings.ContainsAny(encoded, "= \t\r\n") {
		return OfferNotice{}, errors.New("invalid v3 offer notice")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return OfferNotice{}, errors.New("invalid v3 offer notice")
	}
	return decodeOfferNoticePayload(raw)
}

func decodeOfferNoticePayload(raw []byte) (OfferNotice, error) {
	manifest, manifestRaw, envelope, envelopeRaw, nonce, err := decodeOfferPayloadDetailed(raw)
	if err != nil {
		return OfferNotice{}, errors.New("invalid v3 offer notice")
	}
	return OfferNotice{Raw: append([]byte(nil), raw...), Manifest: manifest, ManifestRaw: manifestRaw, Envelope: envelope, EnvelopeRaw: envelopeRaw, AcceptanceNonce: nonce}, nil
}
