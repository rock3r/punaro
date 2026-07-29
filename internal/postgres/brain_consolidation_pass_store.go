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
func (d *Database) LoadMemoryConsolidationPass(ctx context.Context, lease MemoryConsolidationLease, request MemoryConsolidationExecutionRequest) (MemoryConsolidationInput, MemoryConsolidationExecutionRequest, []MemoryConsolidationProposal, bool, error) {
	if err := d.validateMemoryConsolidationProposalScope(ctx, request.PrincipalID, request.ProjectID, lease.ScopeID); err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, false, err
	}
	return d.readMemoryConsolidationPass(ctx, d.db, lease, request)
}

// ReserveMemoryConsolidationPass atomically records a fully validated plan.
// Concurrent workers resolve to the first plan rather than replacing it.
func (d *Database) ReserveMemoryConsolidationPass(ctx context.Context, input MemoryConsolidationInput, request MemoryConsolidationExecutionRequest, proposals []MemoryConsolidationProposal) (MemoryConsolidationInput, MemoryConsolidationExecutionRequest, []MemoryConsolidationProposal, error) {
	if err := d.validateMemoryConsolidationProposalScope(ctx, request.PrincipalID, request.ProjectID, input.Lease.ScopeID); err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, err
	}
	body, err := json.Marshal(proposals)
	if err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, errors.New("consolidation pass cannot be encoded")
	}
	sourceSHA, err := memoryConsolidationPassSourceSHA(input)
	if err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, err
	}
	sourcesBody, err := json.Marshal(input.Sources)
	if err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, errors.New("consolidation pass sources cannot be encoded")
	}
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, mutationStartError(err, "consolidation pass transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_consolidation_passes
(scope_id,timeline_id,start_sequence,next_sequence,principal_id,project_id,lease_token,lease_generation,source_sha256,sources,proposals)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (scope_id,timeline_id,start_sequence) DO NOTHING`,
		input.Lease.ScopeID, input.TimelineID, input.Lease.Sequence, input.NextSequence, request.PrincipalID, request.ProjectID,
		input.Lease.Token, input.Lease.Generation, sourceSHA, sourcesBody, body); err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, errors.New("consolidation pass cannot be reserved")
	}
	resolvedInput, resolvedRequest, resolved, found, err := d.readMemoryConsolidationPass(ctx, tx, input.Lease, request)
	if err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, err
	}
	if !found {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, errors.New("consolidation pass was not reserved")
	}
	if err := tx.Commit(); err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, errors.New("consolidation pass transaction cannot commit")
	}
	return resolvedInput, resolvedRequest, resolved, nil
}

// CheckMemoryConsolidationPassCapacity verifies that every not-yet-staged
// ordinal of a durable pass fits the live quota and that completed ordinals
// still reference actionable proposals.
func (d *Database) CheckMemoryConsolidationPassCapacity(ctx context.Context, input MemoryConsolidationInput, request MemoryConsolidationExecutionRequest, proposals int) error {
	if proposals < 0 || !request.valid() {
		return errors.New("consolidation pass capacity is invalid")
	}
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return mutationStartError(err, "consolidation pass capacity cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	remaining, err := unstagedMemoryConsolidationProposalCount(ctx, tx, input, request, proposals)
	if err != nil {
		return err
	}
	if err := checkMemoryProposalCapacityForCount(ctx, tx, input.Lease.ScopeID, request.PrincipalID, remaining); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("consolidation pass capacity cannot commit")
	}
	return nil
}

func unstagedMemoryConsolidationProposalCount(ctx context.Context, tx *sql.Tx, input MemoryConsolidationInput, request MemoryConsolidationExecutionRequest, proposals int) (int, error) {
	remaining := 0
	for ordinal := range proposals {
		var status sql.NullString
		var state sql.NullString
		var actionable sql.NullBool
		err := tx.QueryRowContext(ctx, `SELECT record.status,proposal.state,proposal.expires_at > statement_timestamp()
FROM relay.idempotency_records AS record
LEFT JOIN brain.memory_proposals AS proposal ON proposal.id=record.resource_id
WHERE record.key=$1`, memoryConsolidationProposalIdempotencyKey(input, request.PrincipalID, request.ProjectID, ordinal)).Scan(&status, &state, &actionable)
		if errors.Is(err, sql.ErrNoRows) {
			remaining++
			continue
		}
		if err != nil {
			return 0, errors.New("consolidation pass idempotency is unavailable")
		}
		if status.String != string(OutcomeSucceeded) || state.String == "" || state.String == "expired" ||
			(state.String == string(MemoryProposalPending) && !actionable.Bool) {
			return 0, errMemoryConsolidationProposalRejected
		}
	}
	return remaining, nil
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

// AbandonMemoryConsolidationPass releases an immutable pass whose source page
// can no longer be staged. It advances through the already-reserved page so a
// later lease starts at the newer source revision with distinct proposal
// idempotency coordinates.
func (d *Database) AbandonMemoryConsolidationPass(ctx context.Context, input MemoryConsolidationInput, request MemoryConsolidationExecutionRequest) error {
	var abandoned bool
	err := d.db.QueryRowContext(ctx, `SELECT brain.abandon_memory_consolidation_pass($1,$2,$3,$4,$5,$6,$7,$8)`,
		input.Lease.ScopeID, input.Lease.Token, input.Lease.Generation, input.TimelineID, input.Lease.Sequence, input.NextSequence, request.PrincipalID, request.ProjectID).Scan(&abandoned)
	if err != nil {
		return errors.New("consolidation pass cannot be abandoned")
	}
	if !abandoned {
		return ErrStaleMemoryConsolidationLease
	}
	return nil
}

func (d *Database) readMemoryConsolidationPass(ctx context.Context, q queryer, lease MemoryConsolidationLease, _ MemoryConsolidationExecutionRequest) (MemoryConsolidationInput, MemoryConsolidationExecutionRequest, []MemoryConsolidationProposal, bool, error) {
	var storedSHA []byte
	var timelineID, body, sourcesBody, principalID, projectID string
	var nextSequence int64
	err := q.QueryRowContext(ctx, `SELECT timeline_id::text,next_sequence,principal_id::text,project_id::text,source_sha256,proposals::text,sources::text FROM brain.memory_consolidation_passes
WHERE scope_id=$1 AND timeline_id=$2 AND start_sequence=$3`,
		lease.ScopeID, lease.TimelineID, lease.Sequence).Scan(&timelineID, &nextSequence, &principalID, &projectID, &storedSHA, &body, &sourcesBody)
	if errors.Is(err, sql.ErrNoRows) {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, false, nil
	}
	if err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, false, errors.New("consolidation pass is unavailable")
	}
	input := MemoryConsolidationInput{Lease: lease, TimelineID: timelineID, NextSequence: nextSequence}
	if err := json.Unmarshal([]byte(sourcesBody), &input.Sources); err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, false, errors.New("consolidation pass is malformed")
	}
	sourceSHA, err := memoryConsolidationPassSourceSHA(input)
	if err != nil || len(storedSHA) != sha256.Size || string(storedSHA) != string(sourceSHA) {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, false, ErrStaleMemoryConsolidationLease
	}
	var proposals []MemoryConsolidationProposal
	if err := json.Unmarshal([]byte(body), &proposals); err != nil {
		return MemoryConsolidationInput{}, MemoryConsolidationExecutionRequest{}, nil, false, errors.New("consolidation pass is malformed")
	}
	return input, MemoryConsolidationExecutionRequest{Lease: lease, PrincipalID: principalID, ProjectID: projectID}, proposals, true, nil
}

func memoryConsolidationPassSourceSHA(input MemoryConsolidationInput) ([]byte, error) {
	canonicalSources := make([]MemoryConsolidationSource, len(input.Sources))
	for index, source := range input.Sources {
		var document any
		if err := json.Unmarshal(source.Document, &document); err != nil {
			return nil, errors.New("consolidation source page cannot be encoded")
		}
		canonicalDocument, err := json.Marshal(document)
		if err != nil {
			return nil, errors.New("consolidation source page cannot be encoded")
		}
		source.Document = canonicalDocument
		canonicalSources[index] = source
	}
	body, err := json.Marshal(struct {
		TimelineID    string                      `json:"timeline_id"`
		StartSequence int64                       `json:"start_sequence"`
		NextSequence  int64                       `json:"next_sequence"`
		Sources       []MemoryConsolidationSource `json:"sources"`
	}{input.TimelineID, input.Lease.Sequence, input.NextSequence, canonicalSources})
	if err != nil {
		return nil, errors.New("consolidation source page cannot be encoded")
	}
	digest := sha256.Sum256(body)
	return digest[:], nil
}
