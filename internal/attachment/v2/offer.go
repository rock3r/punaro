package v2

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"time"
)

const maxOfferPayloadBytes = 24 << 10

type offerPayloadWire struct {
	Version         uint64   `cbor:"1,keyasint"`
	Manifest        []byte   `cbor:"2,keyasint"`
	Envelope        []byte   `cbor:"3,keyasint"`
	AcceptanceNonce [32]byte `cbor:"4,keyasint"`
}

// EncodeOfferPayload canonicalizes the only offer body: a signed manifest and
// its recipient-bound envelope, each in their own canonical wire encoding.
func EncodeOfferPayload(manifest Manifest, envelope Envelope, acceptanceNonce [32]byte) ([]byte, error) {
	if isZero32(acceptanceNonce) {
		return nil, errors.New("invalid offer acceptance nonce")
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

// NewOfferPayload creates the canonical offer body and a one-time recipient
// acceptance nonce. The caller sends the opaque body only to the recipient.
func NewOfferPayload(manifest Manifest, envelope Envelope) ([]byte, [32]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, [32]byte{}, err
	}
	payload, err := EncodeOfferPayload(manifest, envelope, nonce)
	return payload, nonce, err
}

func decodeOfferPayload(raw []byte) (Manifest, Envelope, [32]byte, error) {
	if len(raw) == 0 || len(raw) > maxOfferPayloadBytes {
		return Manifest{}, Envelope{}, [32]byte{}, errors.New("invalid offer payload")
	}
	var wire offerPayloadWire
	if err := strictDecoding.Unmarshal(raw, &wire); err != nil || wire.Version != protocolVersion || isZero32(wire.AcceptanceNonce) {
		return Manifest{}, Envelope{}, [32]byte{}, errors.New("invalid offer payload")
	}
	canonical, err := canonicalEncoding.Marshal(wire)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Manifest{}, Envelope{}, [32]byte{}, errors.New("non-canonical offer payload")
	}
	manifest, err := DecodeManifest(wire.Manifest)
	if err != nil {
		return Manifest{}, Envelope{}, [32]byte{}, errors.New("invalid offer manifest")
	}
	envelope, err := DecodeEnvelope(wire.Envelope)
	if err != nil {
		return Manifest{}, Envelope{}, [32]byte{}, errors.New("invalid offer envelope")
	}
	return manifest, envelope, wire.AcceptanceNonce, nil
}

// Offer verifies a fresh signed manifest and recipient envelope, then creates
// and offers the transfer in the same transaction as signed permit redemption.
func (s *SQLiteTransferStore) Offer(ctx context.Context, permit Permit, operation OperationRecord, request OperationRequest, route AttachmentRoute, payload []byte, issuers PermitAuthorityResolver, holders OperationHolderResolver, directory DirectoryKeyResolver, now time.Time) (TransferRecord, bool, error) {
	if s == nil || s.ledger == nil || route.Action != TransferActionOffer || route.Operation != PermitOperationOffer || route.TransferID != permit.TransferID || permit.Operation != PermitOperationOffer || permit.HolderRole != PermitHolderSender || !bytes.Equal(payload, request.body) {
		return TransferRecord{}, false, errors.New("invalid attachment offer")
	}
	manifest, envelope, acceptanceNonce, err := decodeOfferPayload(payload)
	if err != nil {
		return TransferRecord{}, false, err
	}
	verified, err := verifyManifestFromDirectoryAt(manifest, directory, now)
	if err != nil || !verifyEnvelope(envelope, verified) || !offerPermitBinding(permit, manifest) {
		return TransferRecord{}, false, errors.New("invalid attachment offer authority")
	}
	manifestRaw, err := EncodeManifest(manifest)
	if err != nil {
		return TransferRecord{}, false, err
	}
	envelopeRaw, err := EncodeEnvelope(envelope)
	if err != nil {
		return TransferRecord{}, false, err
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
		if _, err := tx.ExecContext(ctx, "INSERT INTO attachment_offers(transfer_id, manifest, envelope, acceptance_nonce, acceptance_consumed) VALUES (?, ?, ?, ?, ?)", manifest.TransferID[:], manifestRaw, envelopeRaw, acceptanceNonce[:], uint64Bytes(0)); err != nil {
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
	return manifestPermitBinding(permit, manifest) && permit.HolderDeviceID == manifest.SenderDeviceID && permit.HolderGeneration == manifest.SenderGeneration
}

func manifestPermitBinding(permit Permit, manifest Manifest) bool {
	return permit.Audience == manifest.Audience && permit.TransferID == manifest.TransferID && permit.ConversationID == manifest.ConversationID && permit.SenderDeviceID == manifest.SenderDeviceID && permit.SenderGeneration == manifest.SenderGeneration && permit.RecipientDeviceID == manifest.RecipientDeviceID && permit.RecipientGeneration == manifest.RecipientGeneration && permit.DirectoryHead == manifest.DirectoryHead && permit.MembershipCommitment == manifest.MembershipCommitment && permit.RevocationEpoch == manifest.RevocationEpoch && permit.ExpiresAt <= manifest.ExpiresAt
}

// Accept consumes the recipient's one-time offer nonce and records the
// accepted state atomically with its exact signed permit redemption.
func (s *SQLiteTransferStore) Accept(ctx context.Context, permit Permit, operation OperationRecord, request OperationRequest, route AttachmentRoute, issuers PermitAuthorityResolver, holders OperationHolderResolver, directory DirectoryKeyResolver, now time.Time) (TransferRecord, bool, error) {
	if s == nil || s.ledger == nil || route.Action != TransferActionAccept || route.Operation != PermitOperationAccept || route.TransferID != permit.TransferID || permit.Operation != PermitOperationAccept || permit.HolderRole != PermitHolderRecipient || len(request.body) != 32 {
		return TransferRecord{}, false, errors.New("invalid attachment acceptance")
	}
	manifest, _, found, err := s.LoadOffer(permit.TransferID)
	if err != nil || !found || permit.HolderDeviceID != manifest.RecipientDeviceID || permit.HolderGeneration != manifest.RecipientGeneration {
		return TransferRecord{}, false, errors.New("invalid attachment acceptance")
	}
	if _, err := verifyManifestFromDirectoryAt(manifest, directory, now); err != nil || !manifestPermitBinding(permit, manifest) {
		return TransferRecord{}, false, errors.New("invalid attachment acceptance authority")
	}
	raw, replayed, err := s.ledger.Redeem(ctx, permit, operation, request, issuers, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		record, found, err := loadTransferTx(ctx, tx, permit.TransferID)
		if err != nil || !found || record.Status != TransferOffered {
			return nil, errors.New("transfer does not accept recipient acceptance")
		}
		var nonce, consumed []byte
		if err := tx.QueryRowContext(ctx, "SELECT acceptance_nonce, acceptance_consumed FROM attachment_offers WHERE transfer_id = ?", permit.TransferID[:]).Scan(&nonce, &consumed); err != nil || len(nonce) != 32 || len(consumed) != 8 || uint64FromBytes(consumed) != 0 || !bytes.Equal(nonce, request.body) {
			return nil, errors.New("invalid or consumed acceptance nonce")
		}
		result, err := tx.ExecContext(ctx, "UPDATE attachment_offers SET acceptance_consumed = ? WHERE transfer_id = ? AND acceptance_consumed = ?", uint64Bytes(1), permit.TransferID[:], uint64Bytes(0))
		if err != nil {
			return nil, err
		}
		updated, err := result.RowsAffected()
		if err != nil || updated != 1 {
			return nil, errors.New("acceptance nonce fencing failed")
		}
		accepted, err := record.Transition(TransferActionAccept, now)
		if err != nil {
			return nil, err
		}
		if err := updateTransferTx(ctx, tx, record, accepted); err != nil {
			return nil, err
		}
		return encodeTransferResult(accepted)
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
