package v3

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	maxOperationResultBytes = 256
	// One max-geometry transfer can legitimately use an exact sender permit
	// per upload and an exact recipient permit per download, plus lifecycle
	// and bounded reconciliation permits. This is a per-source storage bound,
	// not a per-permit operation quota.
	maxActivePermitsPerSource = 3 * 4096
)

type permitMutation func(context.Context, *sql.Tx) ([]byte, error)

// issuePermit records only a fresh, signed permit bound to an already staged
// canonical source. The source-init handler is separate because it creates
// that source atomically after fresh directory verification.
func (s *sourceStore) issuePermit(ctx context.Context, permit Permit, authority PermitAuthorityResolver, now time.Time) error {
	if s == nil || s.db == nil || permit.Operation == permitOperationSourceInit {
		return errors.New("invalid v3 permit issuance")
	}
	if err := VerifyPermit(permit, authority, now); err != nil {
		return err
	}
	raw, err := EncodePermit(permit)
	if err != nil {
		return err
	}
	permitExpiry, err := unixSeconds(permit.ExpiresAt)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// An exact issuance retry must remain retrievable after the permit has
	// advanced the lifecycle or terminal cleanup released its source. It still
	// passed fresh issuer/revocation validation above; only a *new* serial needs
	// current source admission below.
	var existing []byte
	err = tx.QueryRowContext(ctx, `SELECT permit FROM v3_issued_permits WHERE serial = ?`, permit.Serial[:]).Scan(&existing)
	if err == nil {
		if !bytes.Equal(existing, raw) {
			return errors.New("changed v3 permit serial")
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var outcomeOrigin Permit
	if permit.Operation == permitOperationOutcome {
		outcomeOrigin, err = outcomeOriginPermitTx(ctx, tx, permit, now)
		if err != nil {
			return err
		}
	}
	spec, found, err := loadSpecTx(ctx, tx, permit.TransferID)
	if err != nil || (!found && permit.Operation != permitOperationOutcome) || (found && spec.ManifestCommitment != permit.StagedManifestCommitment) {
		return errors.New("unknown v3 staged source")
	}
	// An expired source-init is the only valid outcome whose source may still
	// be absent. Its exact issuance-row correlation is checked above; the
	// outcome handler will atomically either observe the source or terminalize
	// the bootstrap fence before it can be resurrected.
	if !found {
		if outcomeOrigin.Operation != permitOperationSourceInit {
			return errors.New("missing v3 outcome source")
		}
		if err := insertIssuedPermitTx(ctx, tx, s, permit, raw, permitExpiry, now); err != nil {
			return err
		}
		return tx.Commit()
	}
	manifest, err := DecodeManifest(spec.Manifest)
	if err != nil || !sourceInitPermitBinding(permit, manifest, spec.Manifest) {
		return errors.New("invalid v3 staged permit binding")
	}
	var status transferStatus
	var attempt uint64
	if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt); err != nil || !permitCompatibleSourceStatus(permit, status, attempt) {
		return errors.New("v3 permit is not admitted by source lifecycle")
	}
	var active uint64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v3_issued_permits WHERE transfer_id = ? AND retain_until > ?`, permit.TransferID[:], now.UTC().Unix()).Scan(&active); err != nil || active >= maxActivePermitsPerSource {
		return errors.New("v3 permit admission exhausted")
	}
	if err := insertIssuedPermitTx(ctx, tx, s, permit, raw, permitExpiry, now); err != nil {
		return err
	}
	return tx.Commit()
}

func insertIssuedPermitTx(ctx context.Context, tx *sql.Tx, s *sourceStore, permit Permit, raw []byte, permitExpiry int64, now time.Time) error {
	retainUntil := now.UTC().Add(s.limits.TombstoneRetention).Unix()
	if retainUntil < permitExpiry {
		retainUntil = permitExpiry
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_issued_permits(serial, permit, transfer_id, manifest_commitment, expires_at, retain_until) VALUES (?, ?, ?, ?, ?, ?)`, permit.Serial[:], raw, permit.TransferID[:], permit.StagedManifestCommitment[:], permit.ExpiresAt, retainUntil); err != nil {
		return errors.New("v3 permit serial collision")
	}
	return nil
}

// outcomeOriginPermitTx recovers the exact short-lived capability being
// reconciled. A transfer ID alone is insufficient: it would let a holder use
// a valid outcome permit to probe or terminalize a different ambiguous phase.
func outcomeOriginPermitTx(ctx context.Context, tx *sql.Tx, outcome Permit, now time.Time) (Permit, error) {
	if outcome.Operation != permitOperationOutcome || outcome.OutcomeOfSerial == [16]byte{} || now.Unix() < 0 {
		return Permit{}, errors.New("invalid v3 outcome origin")
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT permit FROM v3_permit_requests WHERE permit_serial = ?`, outcome.OutcomeOfSerial[:]).Scan(&raw); err != nil {
		return Permit{}, errors.New("unknown v3 outcome origin")
	}
	original, err := DecodePermit(raw)
	if err != nil || original.Serial != outcome.OutcomeOfSerial || original.Operation == permitOperationOutcome || original.ExpiresAt > uint64(now.Unix()) || original.TransferID != outcome.TransferID || original.ConversationID != outcome.ConversationID || original.SenderDeviceID != outcome.SenderDeviceID || original.SenderGeneration != outcome.SenderGeneration || original.RecipientDeviceID != outcome.RecipientDeviceID || original.RecipientGeneration != outcome.RecipientGeneration || original.MembershipCommitment != outcome.MembershipCommitment || original.StagedManifestCommitment != outcome.StagedManifestCommitment || original.HolderDeviceID != outcome.HolderDeviceID || original.HolderGeneration != outcome.HolderGeneration || original.HolderRole != outcome.HolderRole {
		return Permit{}, errors.New("mismatched v3 outcome origin")
	}
	return original, nil
}

// permitCompatibleSourceStatus keeps unsupported future endpoint permits
// fail-closed. Recipient permits are issued only once their offer/receipt
// stores exist and perform their own same-transaction lifecycle admission.
func permitCompatibleSourceStatus(permit Permit, status transferStatus, attempt uint64) bool {
	switch permit.Operation {
	case permitOperationSourceUpload:
		return status == transferSourceUploading && attempt == 0 && permit.AttemptGeneration == 0
	case permitOperationOffer:
		return status == transferSourceReady && attempt == 0 && permit.AttemptGeneration == 0
	case permitOperationCancel:
		return (status == transferSourceUploading || status == transferSourceReady) && attempt == 0 && permit.AttemptGeneration == 0
	case permitOperationAccept:
		return status == transferOffered && attempt == 0 && permit.AttemptGeneration == 0
	case permitOperationBegin:
		return status == transferAccepted && attempt == 0 && permit.AttemptGeneration == 1
	case permitOperationDownload, permitOperationComplete:
		return status == transferTransferring && attempt == 1 && permit.AttemptGeneration == 1
	case permitOperationOutcome:
		return permit.AttemptGeneration == 0
	default:
		return false
	}
}

// redeemPermitOperation verifies a route-bound operation, performs a caller
// state mutation within the same transaction, and returns the original durable
// result for an exact retry. A revoked/expired permit is revalidated even on a
// replay, so cached success cannot bypass current authority.
func (s *sourceStore) redeemPermitOperation(ctx context.Context, permit Permit, operation OperationRecord, route AttachmentRoute, request OperationRequest, authority PermitAuthorityResolver, holders OperationHolderResolver, now time.Time, mutation permitMutation) ([]byte, bool, error) {
	if s == nil || s.db == nil || mutation == nil {
		return nil, false, errors.New("invalid v3 permit redemption")
	}
	if err := VerifyPermit(permit, authority, now); err != nil {
		return nil, false, err
	}
	bytesUsed, chunksUsed, err := VerifyAttachmentOperationRequest(operation, permit, holders, route, request, now)
	if err != nil {
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
	var transferID, commitment []byte
	if err := tx.QueryRowContext(ctx, `SELECT permit, transfer_id, manifest_commitment FROM v3_issued_permits WHERE serial = ?`, permit.Serial[:]).Scan(&stored, &transferID, &commitment); err != nil || !bytes.Equal(stored, rawPermit) || !bytes.Equal(transferID, permit.TransferID[:]) || !bytes.Equal(commitment, permit.StagedManifestCommitment[:]) {
		return nil, false, errors.New("unknown or mismatched v3 issued permit")
	}
	var existingOperation uint64
	var method uint64
	var path, target, body, idempotency, result []byte
	err = tx.QueryRowContext(ctx, `SELECT operation, method, path_commitment, target_commitment, body_commitment, idempotency_key, result FROM v3_redeemed_operations WHERE permit_serial = ? AND operation_id = ?`, permit.Serial[:], operation.OperationID[:]).Scan(&existingOperation, &method, &path, &target, &body, &idempotency, &result)
	if err == nil {
		if existingOperation != operation.Operation || method != operation.Method || !bytes.Equal(path, operation.PathCommitment[:]) || !bytes.Equal(target, operation.TargetCommitment[:]) || !bytes.Equal(body, operation.BodyCommitment[:]) || !bytes.Equal(idempotency, operation.IdempotencyKey[:]) {
			return nil, false, errors.New("changed v3 operation replay")
		}
		return append([]byte(nil), result...), true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	var status transferStatus
	var attempt uint64
	if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt); err != nil || !permitCompatibleSourceStatus(permit, status, attempt) {
		return nil, false, errors.New("v3 permit is no longer admitted by source lifecycle")
	}
	spec, found, err := loadSpecTx(ctx, tx, permit.TransferID)
	if err != nil || !found || spec.ManifestCommitment != permit.StagedManifestCommitment {
		return nil, false, errors.New("unknown v3 source ledger admission")
	}
	if err := s.admitLedgerOperationTx(ctx, tx, spec, uint64(maxOperationResultBytes), now); err != nil {
		return nil, false, err
	}
	var other [16]byte
	if err := tx.QueryRowContext(ctx, `SELECT operation_id FROM v3_redeemed_operations WHERE permit_serial = ? AND idempotency_key = ?`, permit.Serial[:], operation.IdempotencyKey[:]).Scan(&other); err == nil {
		return nil, false, errors.New("reused v3 idempotency key")
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	var usedOps, usedBytes, usedChunks uint64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(ciphertext_bytes), 0), COALESCE(SUM(ciphertext_chunks), 0) FROM v3_redeemed_operations WHERE permit_serial = ?`, permit.Serial[:]).Scan(&usedOps, &usedBytes, &usedChunks); err != nil || usedOps >= permit.MaxOperations || bytesUsed > permit.MaxBytes || usedBytes > permit.MaxBytes-bytesUsed || chunksUsed > permit.MaxChunks || usedChunks > permit.MaxChunks-chunksUsed {
		return nil, false, errors.New("v3 permit operation quota exhausted")
	}
	result, err = mutation(ctx, tx)
	if err != nil || len(result) > maxOperationResultBytes {
		if err != nil {
			return nil, false, err
		}
		return nil, false, errors.New("v3 operation result exceeds bound")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_redeemed_operations(permit_serial, operation_id, operation, method, path_commitment, target_commitment, body_commitment, idempotency_key, ciphertext_bytes, ciphertext_chunks, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, permit.Serial[:], operation.OperationID[:], operation.Operation, operation.Method, operation.PathCommitment[:], operation.TargetCommitment[:], operation.BodyCommitment[:], operation.IdempotencyKey[:], bytesUsed, chunksUsed, result); err != nil {
		return nil, false, fmt.Errorf("record v3 operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return append([]byte(nil), result...), false, nil
}

func (s *sourceStore) admitLedgerOperationTx(ctx context.Context, tx *sql.Tx, spec sourceSpec, resultBytes uint64, now time.Time) error {
	maxOperations := spec.ChunkCount + 16
	if maxOperations < spec.ChunkCount || resultBytes > maxOperationResultBytes || maxOperations > 4112 {
		return errors.New("invalid v3 ledger admission")
	}
	var commitmentRaw []byte
	var operations, storedBytes uint64
	err := tx.QueryRowContext(ctx, `SELECT manifest_commitment, operations, result_bytes FROM v3_ledger_admission WHERE transfer_id = ?`, spec.TransferID[:]).Scan(&commitmentRaw, &operations, &storedBytes)
	if errors.Is(err, sql.ErrNoRows) {
		commitmentRaw, operations, storedBytes = spec.ManifestCommitment[:], 0, 0
	} else if err != nil || !bytes.Equal(commitmentRaw, spec.ManifestCommitment[:]) {
		return errors.New("invalid v3 ledger admission state")
	}
	maxBytes := maxOperations * uint64(maxOperationResultBytes)
	if operations >= maxOperations || storedBytes > maxBytes-resultBytes {
		return errors.New("v3 ledger admission exhausted")
	}
	retainUntil := now.UTC().Add(s.limits.TombstoneRetention).Unix()
	if retainUntil < spec.ExpiresAt {
		retainUntil = spec.ExpiresAt
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_ledger_admission(transfer_id, manifest_commitment, operations, result_bytes, retain_until) VALUES (?, ?, 1, ?, ?) ON CONFLICT(transfer_id) DO UPDATE SET operations = v3_ledger_admission.operations + 1, result_bytes = v3_ledger_admission.result_bytes + excluded.result_bytes, retain_until = MAX(v3_ledger_admission.retain_until, excluded.retain_until)`, spec.TransferID[:], spec.ManifestCommitment[:], resultBytes, retainUntil)
	return err
}
