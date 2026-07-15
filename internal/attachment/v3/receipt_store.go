package v3

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

func (s *sourceStore) redeemBegin(ctx context.Context, permit Permit, operation OperationRecord, route AttachmentRoute, request OperationRequest, authorities PermitAuthorityResolver, holders OperationHolderResolver, now time.Time) ([]byte, bool, error) {
	return s.redeemPermitOperation(ctx, permit, operation, route, request, authorities, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		var status transferStatus
		var attempt uint64
		var expires int64
		if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation, expires_at FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt, &expires); err != nil || status != transferAccepted || attempt != 0 {
			return nil, errors.New("v3 transfer cannot begin")
		}
		res, err := tx.ExecContext(ctx, `UPDATE v3_transfers SET status = ?, attempt_generation = 1 WHERE transfer_id = ? AND manifest_commitment = ? AND status = ? AND attempt_generation = 0 AND expires_at = ?`, transferTransferring, permit.TransferID[:], permit.StagedManifestCommitment[:], transferAccepted, expires)
		if err != nil {
			return nil, err
		}
		if changed, err := res.RowsAffected(); err != nil || changed != 1 {
			return nil, errors.New("v3 begin lifecycle fence failed")
		}
		return encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, transferTransferring, 1, expires)
	})
}

// redeemDownload first authenticates the fixed signed GET request without a
// storage lookup. It then selects the immutable ciphertext inside the same
// transaction which admits the receipt. The returned ciphertext is therefore
// never caller-supplied and an exact replay must select the same stored bytes.
func (s *sourceStore) redeemDownload(ctx context.Context, permit Permit, operation OperationRecord, route AttachmentRoute, request OperationRequest, authorities PermitAuthorityResolver, holders OperationHolderResolver, now time.Time) ([]byte, []byte, bool, error) {
	if s == nil || s.db == nil {
		return nil, nil, false, errors.New("invalid v3 download redemption")
	}
	if err := VerifyPermit(permit, authorities, now); err != nil {
		return nil, nil, false, err
	}
	if err := VerifyAttachmentOperationAdmission(operation, permit, holders, route, request, now); err != nil {
		return nil, nil, false, err
	}
	rawPermit, err := EncodePermit(permit)
	if err != nil {
		return nil, nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var stored, transferID, manifestCommitment []byte
	if err := tx.QueryRowContext(ctx, `SELECT permit, transfer_id, manifest_commitment FROM v3_issued_permits WHERE serial = ?`, permit.Serial[:]).Scan(&stored, &transferID, &manifestCommitment); err != nil || !bytes.Equal(stored, rawPermit) || !bytes.Equal(transferID, permit.TransferID[:]) || !bytes.Equal(manifestCommitment, permit.StagedManifestCommitment[:]) {
		return nil, nil, false, errors.New("unknown or mismatched v3 issued permit")
	}
	var existingOperation uint64
	var method uint64
	var path, target, body, idempotency, result []byte
	err = tx.QueryRowContext(ctx, `SELECT operation, method, path_commitment, target_commitment, body_commitment, idempotency_key, result FROM v3_redeemed_operations WHERE permit_serial = ? AND operation_id = ?`, permit.Serial[:], operation.OperationID[:]).Scan(&existingOperation, &method, &path, &target, &body, &idempotency, &result)
	if err == nil {
		if existingOperation != operation.Operation || method != operation.Method || !bytes.Equal(path, operation.PathCommitment[:]) || !bytes.Equal(target, operation.TargetCommitment[:]) || !bytes.Equal(body, operation.BodyCommitment[:]) || !bytes.Equal(idempotency, operation.IdempotencyKey[:]) {
			return nil, nil, false, errors.New("changed v3 operation replay")
		}
		ciphertext, _, err := loadDownloadCiphertextTx(ctx, tx, permit.TransferID, route.ChunkIndex)
		if err != nil {
			return nil, nil, false, err
		}
		if err := tx.Commit(); err != nil {
			return nil, nil, false, err
		}
		return ciphertext, append([]byte(nil), result...), true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, err
	}
	var status transferStatus
	var attempt uint64
	var expires int64
	if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation, expires_at FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt, &expires); err != nil || status != transferTransferring || attempt != 1 {
		return nil, nil, false, errors.New("v3 transfer cannot download")
	}
	spec, found, err := loadSpecTx(ctx, tx, permit.TransferID)
	if err != nil || !found || spec.ManifestCommitment != permit.StagedManifestCommitment {
		return nil, nil, false, errors.New("unknown v3 source ledger admission")
	}
	ciphertext, commitment, err := loadDownloadCiphertextTx(ctx, tx, permit.TransferID, route.ChunkIndex)
	if err != nil {
		return nil, nil, false, err
	}
	if err := s.admitLedgerOperationTx(ctx, tx, spec, uint64(maxOperationResultBytes), now); err != nil {
		return nil, nil, false, err
	}
	var other [16]byte
	if err := tx.QueryRowContext(ctx, `SELECT operation_id FROM v3_redeemed_operations WHERE permit_serial = ? AND idempotency_key = ?`, permit.Serial[:], operation.IdempotencyKey[:]).Scan(&other); err == nil {
		return nil, nil, false, errors.New("reused v3 idempotency key")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, err
	}
	used := uint64(len(ciphertext))
	var usedOps, usedBytes, usedChunks uint64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(ciphertext_bytes), 0), COALESCE(SUM(ciphertext_chunks), 0) FROM v3_redeemed_operations WHERE permit_serial = ?`, permit.Serial[:]).Scan(&usedOps, &usedBytes, &usedChunks); err != nil || usedOps >= permit.MaxOperations || used > permit.MaxBytes || usedBytes > permit.MaxBytes-used || usedChunks >= permit.MaxChunks {
		return nil, nil, false, errors.New("v3 permit operation quota exhausted")
	}
	var existing []byte
	err = tx.QueryRowContext(ctx, `SELECT ciphertext_commitment FROM v3_receipt_chunks WHERE transfer_id = ? AND attempt_generation = 1 AND chunk_index = ?`, permit.TransferID[:], route.ChunkIndex).Scan(&existing)
	if err == nil {
		if !bytes.Equal(existing, commitment[:]) {
			return nil, nil, false, errors.New("v3 receipt commitment replacement")
		}
		return nil, nil, false, errors.New("v3 chunk was already received")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_receipt_chunks(transfer_id, attempt_generation, chunk_index, ciphertext_commitment) VALUES (?, 1, ?, ?)`, permit.TransferID[:], route.ChunkIndex, commitment[:]); err != nil {
		return nil, nil, false, err
	}
	result, err = encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, transferTransferring, 1, expires)
	if err != nil || len(result) > maxOperationResultBytes {
		return nil, nil, false, errors.New("invalid v3 download result")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_redeemed_operations(permit_serial, operation_id, operation, method, path_commitment, target_commitment, body_commitment, idempotency_key, ciphertext_bytes, ciphertext_chunks, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`, permit.Serial[:], operation.OperationID[:], operation.Operation, operation.Method, operation.PathCommitment[:], operation.TargetCommitment[:], operation.BodyCommitment[:], operation.IdempotencyKey[:], used, result); err != nil {
		return nil, nil, false, fmt.Errorf("record v3 download operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, false, err
	}
	return ciphertext, append([]byte(nil), result...), false, nil
}

func loadDownloadCiphertextTx(ctx context.Context, tx *sql.Tx, transferID [16]byte, index uint64) ([]byte, [32]byte, error) {
	spec, found, err := loadSpecTx(ctx, tx, transferID)
	if err != nil || !found || index >= spec.ChunkCount {
		return nil, [32]byte{}, errors.New("invalid v3 stored ciphertext response")
	}
	var ciphertext, rawCommitment []byte
	if err := tx.QueryRowContext(ctx, `SELECT ciphertext, ciphertext_commitment FROM v3_source_chunks WHERE transfer_id = ? AND chunk_index = ?`, transferID[:], index).Scan(&ciphertext, &rawCommitment); err != nil || uint64(len(ciphertext)) != expectedCiphertextLength(spec, index) || len(rawCommitment) != 32 {
		return nil, [32]byte{}, errors.New("invalid v3 stored ciphertext response")
	}
	commitment := ciphertextCommitment(ciphertext)
	if !bytes.Equal(rawCommitment, commitment[:]) {
		return nil, [32]byte{}, errors.New("invalid v3 stored ciphertext response")
	}
	return append([]byte(nil), ciphertext...), commitment, nil
}

func (s *sourceStore) redeemComplete(ctx context.Context, permit Permit, operation OperationRecord, route AttachmentRoute, request OperationRequest, authorities PermitAuthorityResolver, holders OperationHolderResolver, now time.Time) ([]byte, bool, error) {
	return s.redeemPermitOperation(ctx, permit, operation, route, request, authorities, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		var status transferStatus
		var attempt uint64
		var expires int64
		if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation, expires_at FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt, &expires); err != nil || status != transferTransferring || attempt != 1 {
			return nil, errors.New("v3 transfer cannot complete")
		}
		spec, found, err := loadSpecTx(ctx, tx, permit.TransferID)
		if err != nil || !found || spec.ManifestCommitment != permit.StagedManifestCommitment {
			return nil, errors.New("missing v3 completion source")
		}
		var received uint64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v3_receipt_chunks WHERE transfer_id = ? AND attempt_generation = 1`, permit.TransferID[:]).Scan(&received); err != nil || received != spec.ChunkCount {
			return nil, errors.New("incomplete v3 receipt")
		}
		var mismatch int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM v3_source_chunks s LEFT JOIN v3_receipt_chunks r ON r.transfer_id = s.transfer_id AND r.attempt_generation = 1 AND r.chunk_index = s.chunk_index WHERE s.transfer_id = ? AND (r.chunk_index IS NULL OR r.ciphertext_commitment != s.ciphertext_commitment) LIMIT 1`, permit.TransferID[:]).Scan(&mismatch); err == nil {
			return nil, errors.New("invalid v3 receipt commitment")
		} else if err != sql.ErrNoRows {
			return nil, err
		}
		res, err := tx.ExecContext(ctx, `UPDATE v3_transfers SET status = ? WHERE transfer_id = ? AND manifest_commitment = ? AND status = ? AND attempt_generation = 1 AND expires_at = ?`, transferCompleted, permit.TransferID[:], permit.StagedManifestCommitment[:], transferTransferring, expires)
		if err != nil {
			return nil, err
		}
		if changed, err := res.RowsAffected(); err != nil || changed != 1 {
			return nil, errors.New("v3 completion lifecycle fence failed")
		}
		// Keep the immutable source rows quota-accounted until their short
		// manifest/permit expiry. A download replay needs the same ciphertext;
		// deleting it here would either violate exact retry semantics or create
		// an unbounded, unaccounted post-completion cache. reapExpired preserves
		// transferCompleted while releasing these rows at expiry.
		return encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, transferCompleted, 1, expires)
	})
}
