package v3

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// redeemUpload atomically binds a sender's exact ciphertext frame to its
// permit/operation result and advances source-ready only after every immutable
// staged chunk exists.
func (s *sourceStore) redeemUpload(ctx context.Context, permit Permit, operation OperationRecord, route AttachmentRoute, request OperationRequest, authority PermitAuthorityResolver, holders OperationHolderResolver, now time.Time) ([]byte, bool, error) {
	if permit.Operation != permitOperationSourceUpload || route.Operation != permitOperationSourceUpload {
		return nil, false, errors.New("invalid v3 source-upload redemption")
	}
	return s.redeemPermitOperation(ctx, permit, operation, route, request, authority, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		// Generic permit replay has already returned exact operation retries.
		// A distinct operation must never become a second retry identity for an
		// immutable chunk, even when it submits byte-identical ciphertext.
		var prior int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM v3_source_chunks WHERE transfer_id = ? AND chunk_index = ?`, permit.TransferID[:], route.ChunkIndex).Scan(&prior)
		if err == nil {
			return nil, errors.New("v3 source chunk already has a retry identity")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if err := s.uploadTx(ctx, tx, permit.TransferID, route.ChunkIndex, request.body, now); err != nil {
			return nil, err
		}
		var status transferStatus
		var attempt uint64
		var expires int64
		if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation, expires_at FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt, &expires); err != nil || (status != transferSourceUploading && status != transferSourceReady) || attempt != 0 {
			return nil, errors.New("invalid v3 source-upload lifecycle")
		}
		return encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, status, attempt, expires)
	})
}
