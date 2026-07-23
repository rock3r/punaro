package postgres

import (
	"context"
	"database/sql"
	"errors"
)

const maxMemoryReconcileBatch = 64

// MemoryReconcileRequest identifies one direct canonical project maintenance batch.
type MemoryReconcileRequest struct {
	PrincipalID string
	ProjectID   string
	Limit       int
}

// MemoryReconcileResult is a content-free, bounded reconciliation summary.
type MemoryReconcileResult struct {
	AliasRepairs       int   `json:"alias_repairs"`
	OrphanEdgesRemoved int   `json:"orphan_edges_removed"`
	More               bool  `json:"more"`
	ChangeSequence     int64 `json:"change_sequence"`
}

func (request MemoryReconcileRequest) normalized() (MemoryReconcileRequest, error) {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.ProjectID) ||
		request.Limit < 1 || request.Limit > maxMemoryReconcileBatch {
		return MemoryReconcileRequest{}, errors.New("invalid memory reconciliation request")
	}
	return request, nil
}

// ReconcileMemoryReferences repairs authoritative permanent aliases and
// removes only soft edges whose exact target revision no longer exists.
func (d *Database) ReconcileMemoryReferences(ctx context.Context, raw MemoryReconcileRequest) (MemoryReconcileResult, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryReconcileResult{}, err
	}
	var result MemoryReconcileResult
	err = d.brainPool().QueryRowContext(ctx, `SELECT alias_repairs,orphan_edges_removed,more,change_sequence
FROM brain.reconcile_memory_references($1,$2,$3)`,
		request.PrincipalID, request.ProjectID, request.Limit).
		Scan(&result.AliasRepairs, &result.OrphanEdgesRemoved, &result.More, &result.ChangeSequence)
	if errors.Is(err, sql.ErrNoRows) {
		return MemoryReconcileResult{}, ErrNotFound
	}
	if err != nil {
		if isMaintenanceError(err) {
			return MemoryReconcileResult{}, ErrMaintenance
		}
		return MemoryReconcileResult{}, errors.New("memory reference reconciliation is unavailable")
	}
	if result.AliasRepairs < 0 || result.OrphanEdgesRemoved < 0 ||
		result.AliasRepairs+result.OrphanEdgesRemoved > request.Limit || result.ChangeSequence < 0 {
		return MemoryReconcileResult{}, errors.New("memory reference reconciliation returned an invalid result")
	}
	return result, nil
}
