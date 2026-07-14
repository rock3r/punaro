package v2

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"
)

const maxOfferPayloadBytes = 24 << 10

type offerPayloadWire struct {
	Version  uint64 `cbor:"1,keyasint"`
	Manifest []byte `cbor:"2,keyasint"`
	Envelope []byte `cbor:"3,keyasint"`
}

// EncodeOfferPayload canonicalizes the only offer body: a signed manifest and
// its recipient-bound envelope, each in their own canonical wire encoding.
func EncodeOfferPayload(manifest Manifest, envelope Envelope) ([]byte, error) {
	manifestRaw, err := EncodeManifest(manifest)
	if err != nil {
		return nil, err
	}
	envelopeRaw, err := EncodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	return canonicalEncoding.Marshal(offerPayloadWire{Version: protocolVersion, Manifest: manifestRaw, Envelope: envelopeRaw})
}

func decodeOfferPayload(raw []byte) (Manifest, Envelope, error) {
	if len(raw) == 0 || len(raw) > maxOfferPayloadBytes {
		return Manifest{}, Envelope{}, errors.New("invalid offer payload")
	}
	var wire offerPayloadWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil || wire.Version != protocolVersion {
		return Manifest{}, Envelope{}, errors.New("invalid offer payload")
	}
	canonical, err := canonicalEncoding.Marshal(wire)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Manifest{}, Envelope{}, errors.New("non-canonical offer payload")
	}
	manifest, err := DecodeManifest(wire.Manifest)
	if err != nil {
		return Manifest{}, Envelope{}, errors.New("invalid offer manifest")
	}
	envelope, err := DecodeEnvelope(wire.Envelope)
	if err != nil {
		return Manifest{}, Envelope{}, errors.New("invalid offer envelope")
	}
	return manifest, envelope, nil
}

// Offer verifies a fresh signed manifest and recipient envelope, then creates
// and offers the transfer in the same transaction as signed permit redemption.
func (s *SQLiteTransferStore) Offer(ctx context.Context, permit Permit, operation OperationRecord, request OperationRequest, route AttachmentRoute, payload []byte, issuers PermitAuthorityResolver, holders OperationHolderResolver, directory DirectoryKeyResolver, now time.Time) (TransferRecord, bool, error) {
	if s == nil || s.ledger == nil || route.Action != TransferActionOffer || route.Operation != PermitOperationOffer || route.TransferID != permit.TransferID || permit.Operation != PermitOperationOffer || permit.HolderRole != PermitHolderSender || !bytes.Equal(payload, request.body) {
		return TransferRecord{}, false, errors.New("invalid attachment offer")
	}
	manifest, envelope, err := decodeOfferPayload(payload)
	if err != nil {
		return TransferRecord{}, false, err
	}
	verified, err := verifyManifestFromDirectoryAt(manifest, directory, now)
	if err != nil || !verifyEnvelope(envelope, verified) || !offerPermitBinding(permit, manifest) {
		return TransferRecord{}, false, errors.New("invalid attachment offer authority")
	}
	raw, replayed, err := s.ledger.Redeem(ctx, permit, operation, request, issuers, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		if _, found, err := loadTransferTx(ctx, tx, permit.TransferID); err != nil || found {
			if err != nil {
				return nil, err
			}
			return nil, errors.New("transfer already exists")
		}
		sourceReady := NewTransferRecord(manifest.TransferID, verified.commitment, manifest.ExpiresAt)
		var err error
		sourceReady, err = sourceReady.Transition(TransferActionSourceReady, now)
		if err != nil {
			return nil, err
		}
		if err := insertTransferTx(ctx, tx, sourceReady); err != nil {
			return nil, err
		}
		offered, err := sourceReady.Transition(TransferActionOffer, now)
		if err != nil {
			return nil, err
		}
		if err := updateTransferTx(ctx, tx, sourceReady, offered); err != nil {
			return nil, err
		}
		return encodeTransferResult(offered)
	})
	if err != nil {
		return TransferRecord{}, false, err
	}
	record, err := decodeTransferResult(raw)
	if err != nil {
		return TransferRecord{}, false, err
	}
	return record, replayed, nil
}

func offerPermitBinding(permit Permit, manifest Manifest) bool {
	return permit.Audience == manifest.Audience && permit.TransferID == manifest.TransferID && permit.ConversationID == manifest.ConversationID && permit.SenderDeviceID == manifest.SenderDeviceID && permit.SenderGeneration == manifest.SenderGeneration && permit.RecipientDeviceID == manifest.RecipientDeviceID && permit.RecipientGeneration == manifest.RecipientGeneration && permit.DirectoryHead == manifest.DirectoryHead && permit.MembershipCommitment == manifest.MembershipCommitment && permit.RevocationEpoch == manifest.RevocationEpoch && permit.HolderDeviceID == manifest.SenderDeviceID && permit.HolderGeneration == manifest.SenderGeneration && permit.ExpiresAt <= manifest.ExpiresAt
}
