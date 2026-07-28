package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// StageMemoryConsolidationProposal stages a proposal and its exact source page
// only while the supplied consolidation lease remains live. It deliberately
// does not advance the checkpoint: a later bounded runner decides when the
// complete page has been handled.
func (d *Database) StageMemoryConsolidationProposal(ctx context.Context, raw MemoryConsolidationProposalRequest) (MemoryProposalResult, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryProposalResult{}, err
	}
	proposal := request.Proposal
	body, payloadSHA := memoryProposalPayloadSHA(proposal.ProjectID, proposal.Action, proposal.Steps, proposal.Evidence)
	inputBody, err := json.Marshal(struct {
		Proposal json.RawMessage             `json:"proposal"`
		Timeline string                      `json:"timeline"`
		Sequence int64                       `json:"sequence"`
		Sources  []MemoryConsolidationSource `json:"sources"`
	}{Proposal: body, Timeline: request.Input.TimelineID, Sequence: request.Input.NextSequence, Sources: request.Input.Sources})
	if err != nil {
		return MemoryProposalResult{}, errors.New("consolidation proposal cannot be encoded")
	}
	idempotency := IdempotencyRequest{PrincipalID: proposal.PrincipalID, Operation: "memory.consolidation.proposal.create", Key: proposal.IdempotencyKey, Body: inputBody}
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return MemoryProposalResult{}, mutationStartError(err, "consolidation proposal transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, idempotency, func(control *ControlTx) (IdempotencyOutcome, error) {
		var timelineID string
		var sequence int64
		err := tx.QueryRowContext(ctx, `SELECT timeline_id::text,change_sequence FROM brain.memory_consolidation_checkpoints
WHERE scope_id=$1 AND lease_token=$2 AND lease_generation=$3 AND lease_until>statement_timestamp() FOR UPDATE`, request.Input.Lease.ScopeID, request.Input.Lease.Token, request.Input.Lease.Generation).Scan(&timelineID, &sequence)
		if errors.Is(err, sql.ErrNoRows) {
			return IdempotencyOutcome{}, ErrStaleMemoryConsolidationLease
		}
		if err != nil || timelineID != request.Input.TimelineID || sequence != request.Input.Lease.Sequence {
			return IdempotencyOutcome{}, ErrStaleMemoryConsolidationLease
		}
		project, err := lockDirectActiveProject(ctx, tx, proposal.ProjectID)
		if err != nil {
			return IdempotencyOutcome{}, ErrNotFound
		}
		var scopeProjectID string
		if err := tx.QueryRowContext(ctx, `SELECT project_id::text FROM brain.scopes WHERE id=$1 FOR SHARE`, request.Input.Lease.ScopeID).Scan(&scopeProjectID); err != nil || scopeProjectID != project.ID {
			return IdempotencyOutcome{}, ErrNotFound
		}
		allowed, err := lockCapability(ctx, tx, proposal.PrincipalID, project.ID, CapabilityMemoryPropose)
		if err != nil || !allowed {
			return IdempotencyOutcome{}, ErrNotFound
		}
		if err := lockAndValidateConsolidationInputSources(ctx, tx, project.ID, request.Input); err != nil {
			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrStaleMemoryETag) {
				return IdempotencyOutcome{}, ErrStaleMemoryConsolidationLease
			}
			return IdempotencyOutcome{}, err
		}
		items, err := lockAndValidateProposalItems(ctx, tx, project.ID, proposal.Steps, proposal.Evidence)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		for _, step := range proposal.Steps {
			if step.Operation == MemoryProposalStepCreate || step.Operation == MemoryProposalStepUpdate {
				if err := guardMemoryDocument(ctx, tx, project.ID, step.Document); err != nil {
					return IdempotencyOutcome{}, err
				}
			}
			if step.Operation == MemoryProposalStepArchive && (items[step.ItemID].State == MemoryArchived) == step.Archived {
				return IdempotencyOutcome{}, ErrMemoryProposalAlreadySatisfied
			}
		}
		if err := checkMemoryProposalCapacity(ctx, tx, request.Input.Lease.ScopeID, proposal.PrincipalID); err != nil {
			return IdempotencyOutcome{}, err
		}
		var proposalID string
		if err := tx.QueryRowContext(ctx, `INSERT INTO brain.memory_proposals(scope_id,action,proposed_by,payload_sha256,payload) VALUES ($1,$2,$3,$4,$5) RETURNING id::text`, request.Input.Lease.ScopeID, proposal.Action, proposal.PrincipalID, payloadSHA, body).Scan(&proposalID); err != nil {
			return IdempotencyOutcome{}, errors.New("consolidation proposal could not be created")
		}
		for ordinal, step := range proposal.Steps {
			var targetRevision any
			if step.ItemID != "" {
				targetRevision = items[step.ItemID].Revision
			}
			var archived any
			if step.Operation == MemoryProposalStepArchive {
				archived = step.Archived
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_proposal_steps
(proposal_id,ordinal,operation,item_id,target_revision,logical_key,kind,trust,document,archived)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, proposalID, ordinal, step.Operation, nullableString(step.ItemID), targetRevision, nullableMemoryKey(step.LogicalKey), nullableString(step.Kind), nullableString(step.Trust), nullableJSON(step.Document), archived); err != nil {
				return IdempotencyOutcome{}, errors.New("consolidation proposal step could not be created")
			}
		}
		for ordinal, evidence := range proposal.Evidence {
			if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_proposal_evidence(proposal_id,ordinal,item_id,revision) VALUES ($1,$2,$3,$4)`, proposalID, ordinal, evidence.ItemID, evidence.Revision); err != nil {
				return IdempotencyOutcome{}, errors.New("consolidation proposal evidence could not be created")
			}
		}
		for ordinal, source := range request.Input.Sources {
			if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_consolidation_proposal_sources(proposal_id,ordinal,timeline_id,item_id,revision,change_sequence) VALUES ($1,$2,$3,$4,$5,$6)`, proposalID, ordinal, request.Input.TimelineID, source.ItemID, source.Revision, source.ChangeSequence); err != nil {
				return IdempotencyOutcome{}, errors.New("consolidation proposal source could not be recorded")
			}
		}
		if err := advanceProposalGeneration(ctx, tx, project.ID); err != nil {
			return IdempotencyOutcome{}, err
		}
		if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: proposal.PrincipalID, ProjectID: project.ID, Action: AuditMemoryProposalCreate, Outcome: AuditSucceeded, TargetKind: AuditTargetMemoryProposal, TargetID: proposalID}); err != nil {
			return IdempotencyOutcome{}, err
		}
		return memoryProposalOutcome(MemoryProposalResult{ProposalID: proposalID, State: MemoryProposalPending, ETag: memoryProposalETag(proposalID, MemoryProposalPending, payloadSHA)})
	})
	if err != nil {
		return MemoryProposalResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryProposalResult{}, errors.New("consolidation proposal transaction could not commit")
	}
	return decodeMemoryProposalOutcome(outcome)
}

// lockAndValidateConsolidationInputSources rejects forged or superseded source
// coordinates before they can become durable proposal provenance.
func lockAndValidateConsolidationInputSources(ctx context.Context, tx *sql.Tx, projectID string, input MemoryConsolidationInput) error {
	for _, source := range input.Sources {
		var itemID string
		err := tx.QueryRowContext(ctx, `SELECT item.id::text
FROM brain.memory_changes AS change
JOIN brain.memory_items AS item ON item.id=change.item_id
JOIN brain.scopes AS scope ON scope.id=item.scope_id
WHERE change.timeline_id=$1 AND change.change_sequence=$2 AND change.scope_id=$3
  AND change.item_id=$4 AND change.revision=$5 AND scope.project_id=$6
  AND item.current_revision=$5 AND item.state='active' AND item.layer='curated'
FOR SHARE OF item`, input.TimelineID, source.ChangeSequence, input.Lease.ScopeID, source.ItemID, source.Revision, projectID).Scan(&itemID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrStaleMemoryETag
		}
		if err != nil || itemID != source.ItemID {
			return errors.New("consolidation source cannot be validated")
		}
	}
	return nil
}
