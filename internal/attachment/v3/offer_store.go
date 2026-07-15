package v3

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"
)

// redeemOffer fresh-verifies the embedded source and envelope, then makes the
// offer visible in the same permit/replay transaction as its lifecycle CAS.
func (s *sourceStore) redeemOffer(ctx context.Context, permit Permit, operation OperationRecord, route AttachmentRoute, request OperationRequest, authorities PermitAuthorityResolver, holders OperationHolderResolver, directory DirectoryKeyResolver, now time.Time) ([]byte, bool, error) {
	manifest, manifestRaw, envelope, nonce, err := decodeOfferPayload(request.body)
	if err != nil {
		return nil, false, err
	}
	source, err := DecodeAndVerifySourceInit(manifestRaw, directory, now)
	if err != nil || source.ManifestCommitment() != permit.StagedManifestCommitment || !sourceInitPermitBinding(permit, manifest, manifestRaw) {
		return nil, false, errors.New("invalid fresh v3 offer source")
	}
	signer, err := directory.ValidateManifestAuthority(manifest, now)
	if err != nil || !verifyEnvelope(envelope, manifest, manifestRaw, signer) {
		return nil, false, errors.New("invalid fresh v3 offer envelope")
	}
	envelopeRaw, err := EncodeEnvelope(envelope)
	if err != nil {
		return nil, false, err
	}
	return s.redeemPermitOperation(ctx, permit, operation, route, request, authorities, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		spec, found, err := loadSpecTx(ctx, tx, permit.TransferID)
		if err != nil || !found || spec.ManifestCommitment != permit.StagedManifestCommitment || !bytes.Equal(spec.Manifest, manifestRaw) {
			return nil, errors.New("staged v3 manifest mismatch")
		}
		var status transferStatus
		var attempt uint64
		var expires int64
		if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation, expires_at FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt, &expires); err != nil || status != transferSourceReady || attempt != 0 {
			return nil, errors.New("v3 transfer cannot be offered")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_offers(transfer_id, manifest, envelope, acceptance_nonce, acceptance_consumed) VALUES (?, ?, ?, ?, 0)`, permit.TransferID[:], manifestRaw, envelopeRaw, nonce[:]); err != nil {
			return nil, err
		}
		res, err := tx.ExecContext(ctx, `UPDATE v3_transfers SET status = ? WHERE transfer_id = ? AND manifest_commitment = ? AND status = ? AND attempt_generation = 0 AND expires_at = ?`, transferOffered, permit.TransferID[:], permit.StagedManifestCommitment[:], transferSourceReady, expires)
		if err != nil {
			return nil, err
		}
		if changed, err := res.RowsAffected(); err != nil || changed != 1 {
			return nil, errors.New("v3 offer lifecycle fence failed")
		}
		return encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, transferOffered, 0, expires)
	})
}

// redeemAccept atomically consumes the one-time nonce and advances offered to
// accepted after fresh directory validation of the original staged Manifest.
func (s *sourceStore) redeemAccept(ctx context.Context, permit Permit, operation OperationRecord, route AttachmentRoute, request OperationRequest, authorities PermitAuthorityResolver, holders OperationHolderResolver, directory DirectoryKeyResolver, now time.Time) ([]byte, bool, error) {
	if len(request.body) != 32 {
		return nil, false, errors.New("invalid v3 acceptance nonce")
	}
	return s.redeemPermitOperation(ctx, permit, operation, route, request, authorities, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		var raw, envelopeRaw, nonce []byte
		var consumed int
		if err := tx.QueryRowContext(ctx, `SELECT manifest, envelope, acceptance_nonce, acceptance_consumed FROM v3_offers WHERE transfer_id = ?`, permit.TransferID[:]).Scan(&raw, &envelopeRaw, &nonce, &consumed); err != nil || consumed != 0 || len(nonce) != 32 || !bytes.Equal(nonce, request.body) {
			return nil, errors.New("invalid or consumed v3 acceptance")
		}
		source, err := DecodeAndVerifySourceInit(raw, directory, now)
		if err != nil || source.ManifestCommitment() != permit.StagedManifestCommitment {
			return nil, errors.New("invalid fresh v3 acceptance source")
		}
		envelope, err := DecodeEnvelope(envelopeRaw)
		if err != nil {
			return nil, errors.New("invalid stored v3 envelope")
		}
		signer, err := directory.ValidateManifestAuthority(source.manifest, now)
		if err != nil || !verifyEnvelope(envelope, source.manifest, raw, signer) {
			return nil, errors.New("invalid fresh stored v3 envelope")
		}
		var status transferStatus
		var attempt uint64
		var expires int64
		if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation, expires_at FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt, &expires); err != nil || status != transferOffered || attempt != 0 {
			return nil, errors.New("v3 transfer cannot be accepted")
		}
		res, err := tx.ExecContext(ctx, `UPDATE v3_offers SET acceptance_consumed = 1 WHERE transfer_id = ? AND acceptance_consumed = 0`, permit.TransferID[:])
		if err != nil {
			return nil, err
		}
		if changed, err := res.RowsAffected(); err != nil || changed != 1 {
			return nil, errors.New("v3 acceptance fence failed")
		}
		res, err = tx.ExecContext(ctx, `UPDATE v3_transfers SET status = ? WHERE transfer_id = ? AND manifest_commitment = ? AND status = ? AND attempt_generation = 0 AND expires_at = ?`, transferAccepted, permit.TransferID[:], permit.StagedManifestCommitment[:], transferOffered, expires)
		if err != nil {
			return nil, err
		}
		if changed, err := res.RowsAffected(); err != nil || changed != 1 {
			return nil, errors.New("v3 acceptance lifecycle fence failed")
		}
		return encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, transferAccepted, 0, expires)
	})
}
