package v3

import (
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
	return s.redeemPermitOperation(ctx, permit, operation, route, request, authority, holders, now, func(ctx context.Context, tx *sql.Tx) ([]byte, error) {
		var status transferStatus
		var attempt uint64
		var expires int64
		if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation, expires_at FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ?`, permit.TransferID[:], permit.StagedManifestCommitment[:]).Scan(&status, &attempt, &expires); err != nil {
			return nil, errors.New("unknown v3 transfer outcome")
		}
		return encodeTransferResult(permit.TransferID, permit.StagedManifestCommitment, status, attempt, expires)
	})
}
