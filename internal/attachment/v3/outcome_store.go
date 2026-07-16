package v3

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"
)

// redeemOutcome is a permit-bound, replay-fenced state query. It never reads
// source chunks, offers, envelopes, filenames, or plaintext.
func (s *sourceStore) redeemOutcome(ctx context.Context, permit Permit, operation OperationRecord, route AttachmentRoute, request OperationRequest, authority PermitAuthorityResolver, holders OperationHolderResolver, now time.Time) ([]byte, bool, error) {
	if permit.Operation != permitOperationOutcome || route.Operation != permitOperationOutcome {
		return nil, false, errors.New("invalid v3 outcome redemption")
	}
	if err := VerifyPermit(permit, authority, now); err != nil {
		return nil, false, err
	}
	if _, _, err := VerifyAttachmentOperationRequest(operation, permit, holders, route, request, now); err != nil {
		return nil, false, err
	}
	rawPermit, err := EncodePermit(permit)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var stored []byte
	if err := tx.QueryRowContext(ctx, `SELECT permit FROM v3_issued_permits WHERE serial = ?`, permit.Serial[:]).Scan(&stored); err != nil || !bytes.Equal(stored, rawPermit) {
		return nil, false, errors.New("unknown or mismatched v3 issued outcome permit")
	}
	var existingOperation uint64
	var method uint64
	var path, target, body, idempotency, result []byte
	err = tx.QueryRowContext(ctx, `SELECT operation, method, path_commitment, target_commitment, body_commitment, idempotency_key, result FROM v3_redeemed_operations WHERE permit_serial = ? AND operation_id = ?`, permit.Serial[:], operation.OperationID[:]).Scan(&existingOperation, &method, &path, &target, &body, &idempotency, &result)
	if err == nil {
		if existingOperation != operation.Operation || method != operation.Method || !bytes.Equal(path, operation.PathCommitment[:]) || !bytes.Equal(target, operation.TargetCommitment[:]) || !bytes.Equal(body, operation.BodyCommitment[:]) || !bytes.Equal(idempotency, operation.IdempotencyKey[:]) {
			return nil, false, errors.New("changed v3 outcome replay")
		}
		return append([]byte(nil), result...), true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	original, originErr := outcomeOriginPermitTx(ctx, tx, permit, now)
	if originErr != nil {
		return nil, false, originErr
	}
	sourceExists, admitted := false, false
	var originalResult []byte
	err = tx.QueryRowContext(ctx, `SELECT result FROM v3_redeemed_operations WHERE permit_serial = ?`, original.Serial[:]).Scan(&originalResult)
	if err == nil {
		var present uint64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&present); err != nil {
			return nil, false, err
		}
		sourceExists = present == 1
		known, decodeErr := DecodeTransferResult(originalResult)
		if decodeErr != nil || known.TransferID != permit.TransferID || known.ManifestCommitment != permit.StagedManifestCommitment {
			return nil, false, errors.New("invalid v3 outcome origin result")
		}
		result = originalResult
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	} else {
		var status transferStatus
		var attempt uint64
		var expires int64
		err = tx.QueryRowContext(ctx, `SELECT status, attempt_generation, expires_at FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt, &expires)
		if err == nil {
			sourceExists = true
			if status.terminal() {
				result, err = encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, status, attempt, expires)
				if err != nil {
					return nil, false, err
				}
			} else {
				spec, found, specErr := loadSpecTx(ctx, tx, permit.TransferID)
				if specErr != nil || !found || spec.ManifestCommitment != permit.StagedManifestCommitment || s.admitLedgerOperationTx(ctx, tx, spec, uint64(maxOperationResultBytes), now) != nil || s.terminalizeSourceTx(ctx, tx, spec, now) != nil {
					return nil, false, errors.New("cannot terminalize unknown v3 outcome")
				}
				admitted = true
				result, err = encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, transferCancelled, attempt, spec.ExpiresAt)
				if err != nil {
					return nil, false, err
				}
			}
		} else if errors.Is(err, sql.ErrNoRows) {
			if original.Operation != permitOperationSourceInit {
				return nil, false, errors.New("unknown v3 transfer outcome")
			}
			// If source-init committed first it is visible above. Otherwise this
			// inserts the terminal fence in the same write transaction; a delayed
			// source-init cannot later create the transfer with this permit.
			if _, err := tx.ExecContext(ctx, `INSERT INTO v3_source_init_fences(permit_serial,transfer_id,manifest_commitment,state) VALUES(?,?,?,'terminal') ON CONFLICT(permit_serial) DO NOTHING`, original.Serial[:], permit.TransferID[:], permit.StagedManifestCommitment[:]); err != nil {
				return nil, false, err
			}
			var fenceTransfer, fenceCommitment []byte
			var state string
			if err := tx.QueryRowContext(ctx, `SELECT transfer_id, manifest_commitment, state FROM v3_source_init_fences WHERE permit_serial = ?`, original.Serial[:]).Scan(&fenceTransfer, &fenceCommitment, &state); err != nil || !bytes.Equal(fenceTransfer, permit.TransferID[:]) || !bytes.Equal(fenceCommitment, permit.StagedManifestCommitment[:]) || state != "terminal" {
				return nil, false, errors.New("inconsistent v3 source-init fence")
			}
			expires, err = unixSeconds(original.ExpiresAt)
			if err != nil {
				return nil, false, err
			}
			result, err = encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, transferCancelled, 0, expires)
			if err != nil {
				return nil, false, err
			}
		} else {
			return nil, false, err
		}
	}
	if sourceExists && !admitted {
		spec, found, err := loadSpecTx(ctx, tx, permit.TransferID)
		if err != nil || !found || spec.ManifestCommitment != permit.StagedManifestCommitment || s.admitLedgerOperationTx(ctx, tx, spec, uint64(maxOperationResultBytes), now) != nil {
			return nil, false, errors.New("cannot admit v3 outcome operation")
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_redeemed_operations(permit_serial, operation_id, operation, method, path_commitment, target_commitment, body_commitment, idempotency_key, ciphertext_bytes, ciphertext_chunks, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)`, permit.Serial[:], operation.OperationID[:], operation.Operation, operation.Method, operation.PathCommitment[:], operation.TargetCommitment[:], operation.BodyCommitment[:], operation.IdempotencyKey[:], result); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return result, false, nil
}
