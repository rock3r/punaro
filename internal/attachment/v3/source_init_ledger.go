package v3

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"
)

// redeemSourceInit atomically fresh-verifies the exact submitted body, stages
// records its signed source-init permit and its operation result. This is the
// only bootstrap path: it avoids a source-init permit/source existence cycle.
func (s *sourceStore) redeemSourceInit(ctx context.Context, directory DirectoryKeyResolver, permit Permit, operation OperationRecord, route AttachmentRoute, request OperationRequest, authority PermitAuthorityResolver, holders OperationHolderResolver, now time.Time) ([]byte, bool, error) {
	if s == nil || s.db == nil || directory == nil || permit.Operation != permitOperationSourceInit {
		return nil, false, errors.New("invalid v3 source-init redemption")
	}
	source, err := DecodeAndVerifySourceInit(request.body, directory, now)
	if err != nil {
		return nil, false, err
	}
	if err := VerifyPermit(permit, authority, now); err != nil {
		return nil, false, err
	}
	if _, _, err := VerifyAttachmentOperationRequest(operation, permit, holders, route, request, now); err != nil {
		return nil, false, err
	}
	if source.TransferID() != permit.TransferID || source.ManifestCommitment() != permit.StagedManifestCommitment {
		return nil, false, errors.New("source-init verified source does not match permit")
	}
	rawPermit, err := EncodePermit(permit)
	if err != nil {
		return nil, false, err
	}
	permitExpiry, err := unixSeconds(permit.ExpiresAt)
	if err != nil {
		return nil, false, err
	}
	sourceExpiry, err := unixSeconds(source.manifest.ExpiresAt)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	// Source-init is the one operation whose source does not exist when the
	// permit is issued. Require the issuance journal before creating it: an
	// otherwise-valid issuer signature is not a bootstrap admission token.
	var journalPermit []byte
	if err := tx.QueryRowContext(ctx, `SELECT permit FROM v3_permit_requests WHERE permit_serial = ?`, permit.Serial[:]).Scan(&journalPermit); err != nil || !bytes.Equal(journalPermit, rawPermit) {
		return nil, false, errors.New("unknown or mismatched v3 source-init permit issuance")
	}
	var stored []byte
	err = tx.QueryRowContext(ctx, `SELECT permit FROM v3_issued_permits WHERE serial = ?`, permit.Serial[:]).Scan(&stored)
	if err == nil {
		if !bytes.Equal(stored, rawPermit) {
			return nil, false, errors.New("changed v3 source-init permit serial")
		}
		return sourceInitReplayTx(ctx, tx, permit, operation)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	created, err := s.initializeTx(ctx, tx, source, now)
	if err != nil || !created {
		if err == nil {
			err = errors.New("v3 source-init already exists")
		}
		return nil, false, err
	}
	spec, err := source.sourceSpec()
	if err != nil {
		return nil, false, err
	}
	if err := s.admitLedgerOperationTx(ctx, tx, spec, uint64(maxOperationResultBytes), now); err != nil {
		return nil, false, err
	}
	retainUntil := now.UTC().Add(s.limits.TombstoneRetention).Unix()
	if retainUntil < permitExpiry {
		retainUntil = permitExpiry
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_issued_permits(serial, permit, transfer_id, manifest_commitment, expires_at, retain_until) VALUES (?, ?, ?, ?, ?, ?)`, permit.Serial[:], rawPermit, permit.TransferID[:], permit.StagedManifestCommitment[:], permit.ExpiresAt, retainUntil); err != nil {
		return nil, false, err
	}
	result, err := encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, transferSourceUploading, 0, sourceExpiry)
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_redeemed_operations(permit_serial, operation_id, operation, method, path_commitment, target_commitment, body_commitment, idempotency_key, ciphertext_bytes, ciphertext_chunks, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)`, permit.Serial[:], operation.OperationID[:], operation.Operation, operation.Method, operation.PathCommitment[:], operation.TargetCommitment[:], operation.BodyCommitment[:], operation.IdempotencyKey[:], result); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return result, false, nil
}

func sourceInitReplayTx(ctx context.Context, tx *sql.Tx, permit Permit, operation OperationRecord) ([]byte, bool, error) {
	var storedOperation uint64
	var method uint64
	var path, target, body, idempotency, result []byte
	err := tx.QueryRowContext(ctx, `SELECT operation, method, path_commitment, target_commitment, body_commitment, idempotency_key, result FROM v3_redeemed_operations WHERE permit_serial = ? AND operation_id = ?`, permit.Serial[:], operation.OperationID[:]).Scan(&storedOperation, &method, &path, &target, &body, &idempotency, &result)
	if err != nil {
		return nil, false, errors.New("unknown v3 source-init operation")
	}
	if storedOperation != operation.Operation || method != operation.Method || !bytes.Equal(path, operation.PathCommitment[:]) || !bytes.Equal(target, operation.TargetCommitment[:]) || !bytes.Equal(body, operation.BodyCommitment[:]) || !bytes.Equal(idempotency, operation.IdempotencyKey[:]) {
		return nil, false, errors.New("changed v3 source-init replay")
	}
	return append([]byte(nil), result...), true, nil
}

func encodeTransferResult(transferID [16]byte, commitment [32]byte, status transferStatus, attempt uint64, expiresAt int64) ([]byte, error) {
	return canonicalEncoding.Marshal(map[uint64]any{1: uint64(protocolVersion), 2: transferID, 3: commitment, 4: uint64(status), 5: attempt, 6: expiresAt})
}
