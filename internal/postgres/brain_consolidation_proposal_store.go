package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	// The request body fences idempotency before the lease transaction. The
	// stored proposal payload is derived later from the scope's physical project
	// ID so it remains reproducible after that project becomes an alias.
	idempotencyPayload, _ := memoryProposalPayloadSHA(proposal.ProjectID, proposal.Action, proposal.Steps, proposal.Evidence)
	type sourceDigest struct {
		ItemID         string            `json:"item_id"`
		Revision       int64             `json:"revision"`
		ChangeSequence int64             `json:"change_sequence"`
		ContentSHA256  [sha256.Size]byte `json:"content_sha256"`
	}
	sources := make([]sourceDigest, len(request.Input.Sources))
	for index, source := range request.Input.Sources {
		sources[index] = sourceDigest{ItemID: source.ItemID, Revision: source.Revision, ChangeSequence: source.ChangeSequence, ContentSHA256: sha256.Sum256(source.Document)}
	}
	inputBody, err := json.Marshal(struct {
		Proposal json.RawMessage `json:"proposal"`
		Timeline string          `json:"timeline"`
		Sequence int64           `json:"sequence"`
		Sources  []sourceDigest  `json:"sources"`
	}{Proposal: idempotencyPayload, Timeline: request.Input.TimelineID, Sequence: request.Input.NextSequence, Sources: sources})
	if err != nil {
		return MemoryProposalResult{}, errors.New("consolidation proposal cannot be encoded")
	}
	idempotency := IdempotencyRequest{PrincipalID: proposal.PrincipalID, Operation: "memory.consolidation.proposal.create", Key: proposal.IdempotencyKey, Body: inputBody}
	if outcome, completed, err := completedIdempotencyOutcome(ctx, d.db, idempotency); err != nil {
		return MemoryProposalResult{}, err
	} else if completed {
		return decodeMemoryProposalOutcome(outcome)
	}
	if err := d.maintainMemoryProposals(ctx, proposal.PrincipalID, proposal.ProjectID); err != nil {
		return MemoryProposalResult{}, err
	}
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
		var scopeProjectID, canonicalScopeProjectID string
		if err := tx.QueryRowContext(ctx, `SELECT scope.project_id::text,COALESCE(alias.canonical_project_id,scope.project_id)::text
FROM brain.scopes AS scope
LEFT JOIN relay.project_lookup_aliases AS alias ON alias.alias_project_id=scope.project_id
WHERE scope.id=$1 FOR SHARE OF scope`, request.Input.Lease.ScopeID).Scan(&scopeProjectID, &canonicalScopeProjectID); err != nil || canonicalScopeProjectID != project.ID {
			return IdempotencyOutcome{}, ErrNotFound
		}
		body, payloadSHA := memoryProposalPayloadSHA(scopeProjectID, proposal.Action, proposal.Steps, proposal.Evidence)
		allowed, err := lockCapability(ctx, tx, proposal.PrincipalID, project.ID, CapabilityMemoryPropose)
		if err != nil || !allowed {
			return IdempotencyOutcome{}, ErrNotFound
		}
		if err := validateConsolidationInputSources(ctx, tx, request.Input); err != nil {
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

// validateConsolidationInputSources re-reads the complete security-definer
// page under the live lease. This preserves the exact source page and applies
// the retrieval path's quarantine and scan-coverage fences at staging time.
func validateConsolidationInputSources(ctx context.Context, tx *sql.Tx, input MemoryConsolidationInput) error {
	rows, err := tx.QueryContext(ctx, `SELECT timeline_id::text,item_id::text,revision,change_sequence,document::text,content_sha256,is_fence
FROM brain.read_memory_consolidation_documents($1,$2,$3)`, input.Lease.ScopeID, input.Lease.Token, input.Lease.Generation)
	if err != nil {
		return ErrStaleMemoryConsolidationLease
	}
	defer func() { _ = rows.Close() }()
	index, next := 0, input.Lease.Sequence
	for rows.Next() {
		var timelineID string
		var itemID, document sql.NullString
		var revision, sequence sql.NullInt64
		var contentHash []byte
		var fence bool
		if err := rows.Scan(&timelineID, &itemID, &revision, &sequence, &document, &contentHash, &fence); err != nil || timelineID != input.TimelineID || !sequence.Valid {
			return ErrStaleMemoryConsolidationLease
		}
		if fence {
			if sequence.Int64 != input.Lease.Sequence {
				return ErrStaleMemoryConsolidationLease
			}
			continue
		}
		next = sequence.Int64
		if !itemID.Valid {
			continue
		}
		if index >= len(input.Sources) || !revision.Valid || !document.Valid {
			return ErrStaleMemoryConsolidationLease
		}
		source := input.Sources[index]
		canonical, err := canonicalMemoryDocument(json.RawMessage(document.String))
		digest := sha256.Sum256([]byte(document.String))
		if err != nil || len(contentHash) != sha256.Size || !bytes.Equal(digest[:], contentHash) || source.ItemID != itemID.String || source.Revision != revision.Int64 || source.ChangeSequence != sequence.Int64 || !bytes.Equal(source.Document, canonical) {
			return ErrStaleMemoryConsolidationLease
		}
		index++
	}
	if rows.Err() != nil || index != len(input.Sources) || next != input.NextSequence {
		return ErrStaleMemoryConsolidationLease
	}
	return nil
}
