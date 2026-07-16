package v3

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// redeemCancel is sender-only by Permit validation and is admitted only while
// the source remains private. It terminalizes the source and records the
// result in the same transaction as the signed operation.
func (s *sourceStore) redeemCancel(ctx context.Context, permit Permit, operation OperationRecord, route AttachmentRoute, request OperationRequest, authority PermitAuthorityResolver, holders OperationHolderResolver, now time.Time) ([]byte, bool, error) {
	if permit.Operation != permitOperationCancel || route.Operation != permitOperationCancel {
		return nil, false, errors.New("invalid v3 cancellation redemption")
	}
	return s.redeemPermitOperation(ctx, permit, operation, route, request, authority, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		spec, found, err := loadSpecTx(ctx, tx, permit.TransferID)
		if err != nil || !found || spec.ManifestCommitment != permit.StagedManifestCommitment {
			return nil, errors.New("unknown v3 cancellation source")
		}
		var status transferStatus
		var attempt uint64
		if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt); err != nil || (status != transferSourceUploading && status != transferSourceReady) || attempt != 0 {
			return nil, errors.New("v3 source is no longer cancellable")
		}
		if err := s.terminalizeSourceTx(ctx, tx, spec, now); err != nil {
			return nil, err
		}
		return encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, transferCancelled, 0, spec.ExpiresAt)
	})
}
