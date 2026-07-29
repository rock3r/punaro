package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
)

// LoadMemoryConsolidationPass returns the immutable plan reserved for this
// exact source page. A retry must load this before consulting a planner.
func (d *Database) LoadMemoryConsolidationPass(ctx context.Context, input MemoryConsolidationInput, request MemoryConsolidationExecutionRequest) ([]MemoryConsolidationProposal, bool, error) {
	if err := d.validateMemoryConsolidationProposalScope(ctx, request.PrincipalID, request.ProjectID, input.Lease.ScopeID); err != nil {
		return nil, false, err
	}
	return d.readMemoryConsolidationPass(ctx, d.db, input, request)
}

// ReserveMemoryConsolidationPass atomically records a fully validated plan.
// Concurrent workers resolve to the first plan rather than replacing it.
func (d *Database) ReserveMemoryConsolidationPass(ctx context.Context, input MemoryConsolidationInput, request MemoryConsolidationExecutionRequest, proposals []MemoryConsolidationProposal) ([]MemoryConsolidationProposal, error) {
	if err := d.validateMemoryConsolidationProposalScope(ctx, request.PrincipalID, request.ProjectID, input.Lease.ScopeID); err != nil {
		return nil, err
	}
	body, err := json.Marshal(proposals)
	if err != nil {
		return nil, errors.New("consolidation pass cannot be encoded")
	}
	sourceSHA, err := memoryConsolidationPassSourceSHA(input)
	if err != nil {
		return nil, err
	}
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return nil, mutationStartError(err, "consolidation pass transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_consolidation_passes
(scope_id,timeline_id,start_sequence,next_sequence,principal_id,project_id,lease_token,lease_generation,source_sha256,proposals)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (scope_id,timeline_id,start_sequence,next_sequence,principal_id,project_id) DO NOTHING`,
		input.Lease.ScopeID, input.TimelineID, input.Lease.Sequence, input.NextSequence, request.PrincipalID, request.ProjectID,
		input.Lease.Token, input.Lease.Generation, sourceSHA, body); err != nil {
		return nil, errors.New("consolidation pass cannot be reserved")
	}
	resolved, found, err := d.readMemoryConsolidationPass(ctx, tx, input, request)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("consolidation pass was not reserved")
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.New("consolidation pass transaction cannot commit")
	}
	return resolved, nil
}

// CompleteMemoryConsolidationPass atomically advances the fenced checkpoint
// and removes the plan that made all staging retries deterministic.
func (d *Database) CompleteMemoryConsolidationPass(ctx context.Context, input MemoryConsolidationInput, request MemoryConsolidationExecutionRequest) error {
	var completed bool
	err := d.db.QueryRowContext(ctx, `SELECT brain.complete_memory_consolidation_pass($1,$2,$3,$4,$5,$6,$7,$8)`,
		input.Lease.ScopeID, input.Lease.Token, input.Lease.Generation, input.TimelineID, input.Lease.Sequence, input.NextSequence, request.PrincipalID, request.ProjectID).Scan(&completed)
	if err != nil {
		return errors.New("consolidation pass cannot be completed")
	}
	if !completed {
		return ErrStaleMemoryConsolidationLease
	}
	return nil
}

func (d *Database) readMemoryConsolidationPass(ctx context.Context, q queryer, input MemoryConsolidationInput, request MemoryConsolidationExecutionRequest) ([]MemoryConsolidationProposal, bool, error) {
	sourceSHA, err := memoryConsolidationPassSourceSHA(input)
	if err != nil {
		return nil, false, err
	}
	var storedSHA []byte
	var body string
	err = q.QueryRowContext(ctx, `SELECT source_sha256,proposals::text FROM brain.memory_consolidation_passes
WHERE scope_id=$1 AND timeline_id=$2 AND start_sequence=$3 AND next_sequence=$4 AND principal_id=$5 AND project_id=$6`,
		input.Lease.ScopeID, input.TimelineID, input.Lease.Sequence, input.NextSequence, request.PrincipalID, request.ProjectID).Scan(&storedSHA, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.New("consolidation pass is unavailable")
	}
	if len(storedSHA) != sha256.Size || string(storedSHA) != string(sourceSHA) {
		return nil, false, ErrStaleMemoryConsolidationLease
	}
	var proposals []MemoryConsolidationProposal
	if err := json.Unmarshal([]byte(body), &proposals); err != nil {
		return nil, false, errors.New("consolidation pass is malformed")
	}
	return proposals, true, nil
}

func memoryConsolidationPassSourceSHA(input MemoryConsolidationInput) ([]byte, error) {
	body, err := json.Marshal(struct {
		TimelineID    string                      `json:"timeline_id"`
		StartSequence int64                       `json:"start_sequence"`
		NextSequence  int64                       `json:"next_sequence"`
		Sources       []MemoryConsolidationSource `json:"sources"`
	}{input.TimelineID, input.Lease.Sequence, input.NextSequence, input.Sources})
	if err != nil {
		return nil, errors.New("consolidation source page cannot be encoded")
	}
	digest := sha256.Sum256(body)
	return digest[:], nil
}
