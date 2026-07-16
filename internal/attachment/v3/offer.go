package v3

import (
	"bytes"
	"errors"
)

// maxOfferPayloadBytes is deliberately just below 24 KiB. Its raw-base64url
// representation plus the v3 notice marker must fit one 32 KiB durable relay
// body; accepting a larger offer that cannot be made recipient-discoverable
// would create a stranded transfer state.
const maxOfferPayloadBytes = 24555

type offerPayloadWire struct {
	Version         uint64   `cbor:"1,keyasint"`
	Manifest        []byte   `cbor:"2,keyasint"`
	Envelope        []byte   `cbor:"3,keyasint"`
	AcceptanceNonce [32]byte `cbor:"4,keyasint"`
}

// EncodeOfferPayload canonicalizes the only v3 offer body. The relay decodes
// this before redemption and later fresh-verifies the envelope signer.
func EncodeOfferPayload(manifest Manifest, envelope Envelope, acceptanceNonce [32]byte) ([]byte, error) {
	if acceptanceNonce == [32]byte{} {
		return nil, errors.New("invalid v3 offer acceptance nonce")
	}
	manifestRaw, err := EncodeManifest(manifest)
	if err != nil {
		return nil, err
	}
	envelopeRaw, err := EncodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(offerPayloadWire{Version: protocolVersion, Manifest: manifestRaw, Envelope: envelopeRaw, AcceptanceNonce: acceptanceNonce})
}

func decodeOfferPayload(raw []byte) (Manifest, []byte, Envelope, [32]byte, error) {
	manifest, manifestRaw, envelope, _, nonce, err := decodeOfferPayloadDetailed(raw)
	return manifest, manifestRaw, envelope, nonce, err
}

func decodeOfferPayloadDetailed(raw []byte) (Manifest, []byte, Envelope, []byte, [32]byte, error) {
	if len(raw) == 0 || len(raw) > maxOfferPayloadBytes {
		return Manifest{}, nil, Envelope{}, nil, [32]byte{}, errors.New("invalid v3 offer payload")
	}
	var wire offerPayloadWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil || wire.Version != protocolVersion || wire.AcceptanceNonce == [32]byte{} {
		return Manifest{}, nil, Envelope{}, nil, [32]byte{}, errors.New("invalid v3 offer payload")
	}
	canonical, err := canonicalEncoding.Marshal(wire)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Manifest{}, nil, Envelope{}, nil, [32]byte{}, errors.New("non-canonical v3 offer payload")
	}
	manifest, err := DecodeManifest(wire.Manifest)
	if err != nil {
		return Manifest{}, nil, Envelope{}, nil, [32]byte{}, errors.New("invalid v3 offer manifest")
	}
	envelope, err := DecodeEnvelope(wire.Envelope)
	if err != nil || !sameEnvelopeManifestBinding(envelope, manifest, wire.Manifest) {
		return Manifest{}, nil, Envelope{}, nil, [32]byte{}, errors.New("invalid v3 offer envelope")
	}
	return manifest, append([]byte(nil), wire.Manifest...), envelope, append([]byte(nil), wire.Envelope...), wire.AcceptanceNonce, nil
}

func validateOfferPayloadForPermit(raw []byte, permit Permit) error {
	manifest, manifestRaw, _, _, err := decodeOfferPayload(raw)
	if err != nil || !retainedManifestPermitBinding(permit, manifest, manifestRaw) {
		return errors.New("invalid v3 offer permit binding")
	}
	return nil
}
