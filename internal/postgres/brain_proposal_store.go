package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
)

type lockedProposalItem struct {
	lockedMemory
	Quarantined bool
}

// ProposeMemory stages one bounded immutable action without changing canonical memory.
func (d *Database) ProposeMemory(ctx context.Context, raw MemoryProposalCreateRequest) (MemoryProposalResult, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryProposalResult{}, err
	}
	body, payloadSHA := memoryProposalPayloadSHA(request.ProjectID, request.Action, request.Steps, request.Evidence)
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return MemoryProposalResult{}, mutationStartError(err, "memory proposal transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: request.PrincipalID, Operation: "memory.proposal.create", Key: request.IdempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
		project, err := lockDirectActiveProject(ctx, tx, request.ProjectID)
		if err != nil {
			return IdempotencyOutcome{}, ErrNotFound
		}
		allowed, err := lockCapability(ctx, tx, request.PrincipalID, project.ID, CapabilityMemoryPropose)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		if !allowed {
			return IdempotencyOutcome{}, ErrNotFound
		}
		items, err := lockAndValidateProposalItems(ctx, tx, project.ID, request.Steps, request.Evidence)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		for _, step := range request.Steps {
			if step.Operation == MemoryProposalStepCreate || step.Operation == MemoryProposalStepUpdate {
				if err := guardMemoryDocument(ctx, tx, project.ID, step.Document); err != nil {
					return IdempotencyOutcome{}, err
				}
			}
			if step.Operation == MemoryProposalStepArchive {
				locked := items[step.ItemID]
				if (locked.State == MemoryArchived) == step.Archived {
					return IdempotencyOutcome{}, errors.New("memory proposal archive is already satisfied")
				}
			}
		}
		scopeID, err := ensureMemoryScope(ctx, tx, project.ID, request.PrincipalID)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		var proposalID string
		if err := tx.QueryRowContext(ctx, `INSERT INTO brain.memory_proposals(scope_id,action,proposed_by,payload_sha256,payload) VALUES ($1,$2,$3,$4,$5) RETURNING id::text`, scopeID, request.Action, request.PrincipalID, payloadSHA, body).Scan(&proposalID); err != nil {
			return IdempotencyOutcome{}, errors.New("memory proposal could not be created")
		}
		for ordinal, step := range request.Steps {
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
				return IdempotencyOutcome{}, errors.New("memory proposal step could not be created")
			}
		}
		for ordinal, evidence := range request.Evidence {
			if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_proposal_evidence(proposal_id,ordinal,item_id,revision) VALUES ($1,$2,$3,$4)`, proposalID, ordinal, evidence.ItemID, evidence.Revision); err != nil {
				return IdempotencyOutcome{}, errors.New("memory proposal evidence could not be created")
			}
		}
		if err := advanceProposalGeneration(ctx, tx, project.ID); err != nil {
			return IdempotencyOutcome{}, err
		}
		if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: request.PrincipalID, ProjectID: project.ID, Action: AuditMemoryProposalCreate, Outcome: AuditSucceeded, TargetKind: AuditTargetMemoryProposal, TargetID: proposalID}); err != nil {
			return IdempotencyOutcome{}, err
		}
		return memoryProposalOutcome(MemoryProposalResult{ProposalID: proposalID, State: MemoryProposalPending, ETag: memoryProposalETag(proposalID, MemoryProposalPending, payloadSHA)})
	})
	if err != nil {
		return MemoryProposalResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryProposalResult{}, errors.New("memory proposal transaction could not commit")
	}
	return decodeMemoryProposalOutcome(outcome)
}

// GetMemoryProposal returns one authorized immutable proposal payload.
func (d *Database) GetMemoryProposal(ctx context.Context, principalID, projectID, proposalID string) (MemoryProposal, error) {
	if !validOpaqueID(principalID) || !validOpaqueID(projectID) || !validOpaqueID(proposalID) {
		return MemoryProposal{}, errors.New("invalid memory proposal lookup")
	}
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryProposal{}, errors.New("memory proposal snapshot cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	canonicalProjectID, err := resolveCanonicalActiveProject(ctx, tx, projectID)
	if err != nil {
		return MemoryProposal{}, ErrNotFound
	}
	allowed, err := hasCapability(ctx, tx, principalID, canonicalProjectID, CapabilityMemoryRead)
	if err != nil {
		return MemoryProposal{}, err
	}
	if !allowed {
		return MemoryProposal{}, ErrNotFound
	}
	proposal, err := readMemoryProposal(ctx, tx, canonicalProjectID, proposalID, false)
	if err != nil {
		return MemoryProposal{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryProposal{}, errors.New("memory proposal snapshot cannot commit")
	}
	return proposal, nil
}

// ApproveMemoryProposal applies every step atomically after exact CAS revalidation.
func (d *Database) ApproveMemoryProposal(ctx context.Context, request MemoryProposalDecisionRequest) (MemoryProposalResult, error) {
	return d.decideMemoryProposal(ctx, request, true)
}

// RejectMemoryProposal closes a pending proposal without changing canonical memory.
func (d *Database) RejectMemoryProposal(ctx context.Context, request MemoryProposalDecisionRequest) (MemoryProposalResult, error) {
	return d.decideMemoryProposal(ctx, request, false)
}

func (d *Database) decideMemoryProposal(ctx context.Context, request MemoryProposalDecisionRequest, approve bool) (MemoryProposalResult, error) {
	if err := request.validate(); err != nil {
		return MemoryProposalResult{}, err
	}
	operation := "memory.proposal.reject"
	decision := MemoryProposalRejected
	action := AuditMemoryProposalReject
	if approve {
		operation = "memory.proposal.approve"
		decision = MemoryProposalApproved
		action = AuditMemoryProposalApprove
	}
	body, _ := json.Marshal(struct {
		ProjectID    string `json:"project_id"`
		ProposalID   string `json:"proposal_id"`
		ExpectedETag string `json:"expected_etag"`
	}{request.ProjectID, request.ProposalID, request.ExpectedETag})
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return MemoryProposalResult{}, mutationStartError(err, "memory proposal decision cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: request.PrincipalID, Operation: operation, Key: request.IdempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
		project, err := lockDirectActiveProject(ctx, tx, request.ProjectID)
		if err != nil {
			return IdempotencyOutcome{}, ErrNotFound
		}
		allowed, err := lockCapability(ctx, tx, request.PrincipalID, project.ID, CapabilityMemoryAdminister)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		if !allowed {
			return IdempotencyOutcome{}, ErrNotFound
		}
		proposal, err := readMemoryProposal(ctx, tx, project.ID, request.ProposalID, true)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		if proposal.State != MemoryProposalPending || !memoryProposalETagMatches(request.ExpectedETag, proposal.ProposalID, proposal.State, proposal.payloadSHA) {
			return IdempotencyOutcome{}, ErrStaleMemoryProposal
		}
		updated, err := tx.ExecContext(ctx, `UPDATE brain.memory_proposals SET state=$2,decided_by=$3,decided_at=transaction_timestamp(),decided_xid=pg_current_xact_id() WHERE id=$1 AND state='pending'`, request.ProposalID, decision, request.PrincipalID)
		if err != nil {
			return IdempotencyOutcome{}, errors.New("memory proposal could not be decided")
		}
		if count, err := updated.RowsAffected(); err != nil || count != 1 {
			return IdempotencyOutcome{}, ErrStaleMemoryProposal
		}
		mutations := []MemoryMutationResult(nil)
		if approve {
			steps := proposalStepInputs(proposal.Steps)
			evidence := proposalEvidenceInputs(proposal.Evidence)
			items, err := lockAndValidateProposalItems(ctx, tx, project.ID, steps, evidence)
			if err != nil {
				if errors.Is(err, ErrNotFound) || errors.Is(err, ErrStaleMemoryETag) {
					return IdempotencyOutcome{}, ErrStaleMemoryProposal
				}
				return IdempotencyOutcome{}, err
			}
			for ordinal, step := range steps {
				if step.Operation == MemoryProposalStepCreate || step.Operation == MemoryProposalStepUpdate {
					if err := guardMemoryDocument(ctx, tx, project.ID, step.Document); err != nil {
						return IdempotencyOutcome{}, err
					}
				}
				mutation, err := applyMemoryProposalStep(ctx, tx, control, request.PrincipalID, project.ID, proposal.ScopeID, step, items)
				if err != nil {
					return IdempotencyOutcome{}, err
				}
				mutations = append(mutations, mutation)
				if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_proposal_results(proposal_id,ordinal,item_id,revision) VALUES ($1,$2,$3,$4)`, proposal.ProposalID, ordinal, mutation.ItemID, mutation.Revision); err != nil {
					return IdempotencyOutcome{}, errors.New("memory proposal result could not be recorded")
				}
			}
		}
		if err := advanceProposalGeneration(ctx, tx, project.ID); err != nil {
			return IdempotencyOutcome{}, err
		}
		if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: request.PrincipalID, ProjectID: project.ID, Action: action, Outcome: AuditSucceeded, TargetKind: AuditTargetMemoryProposal, TargetID: request.ProposalID}); err != nil {
			return IdempotencyOutcome{}, err
		}
		return memoryProposalOutcome(MemoryProposalResult{ProposalID: request.ProposalID, State: decision, ETag: memoryProposalETag(request.ProposalID, decision, proposal.payloadSHA), Mutations: mutations})
	})
	if err != nil {
		return MemoryProposalResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryProposalResult{}, errors.New("memory proposal decision cannot commit")
	}
	return decodeMemoryProposalOutcome(outcome)
}

func lockAndValidateProposalItems(ctx context.Context, tx *sql.Tx, projectID string, steps []MemoryProposalStepInput, evidence []MemoryProposalEvidenceInput) (map[string]lockedProposalItem, error) {
	items := make(map[string]lockedProposalItem, len(steps)+len(evidence))
	for _, itemID := range sortedMemoryProposalItemIDs(steps, evidence) {
		var item lockedProposalItem
		item.ProjectID = projectID
		err := tx.QueryRowContext(ctx, `SELECT scope.id::text,item.current_revision,item.state,item.layer,revision.document::text,revision.content_sha256,
EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)
FROM brain.memory_items AS item
JOIN brain.scopes AS scope ON scope.id=item.scope_id
JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
WHERE item.id=$1 AND scope.project_id=$2
FOR SHARE OF item`, itemID, projectID).Scan(&item.ScopeID, &item.Revision, &item.State, &item.Layer, &item.Document, &item.ContentHash, &item.Quarantined)
		if errors.Is(err, sql.ErrNoRows) || item.Quarantined {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, errors.New("memory proposal item could not be locked")
		}
		if len(item.ContentHash) != 32 {
			return nil, errors.New("memory proposal item is malformed")
		}
		items[itemID] = item
	}
	for _, step := range steps {
		if step.ItemID == "" {
			continue
		}
		item := items[step.ItemID]
		if item.Layer != MemoryLayerCurated || !memoryETagMatches(step.ExpectedETag, step.ItemID, item.Revision) {
			return nil, ErrStaleMemoryETag
		}
	}
	for _, source := range evidence {
		item := items[source.ItemID]
		if item.Layer != MemoryLayerEvidence || item.State != MemoryActive {
			return nil, ErrNotFound
		}
		if item.Revision != source.Revision {
			return nil, ErrNotFound
		}
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM brain.memory_revisions WHERE item_id=$1 AND revision=$2)`, source.ItemID, source.Revision).Scan(&exists); err != nil || !exists {
			return nil, ErrNotFound
		}
	}
	return items, nil
}

func applyMemoryProposalStep(ctx context.Context, tx *sql.Tx, control *ControlTx, principalID, projectID, scopeID string, step MemoryProposalStepInput, items map[string]lockedProposalItem) (MemoryMutationResult, error) {
	switch step.Operation {
	case MemoryProposalStepCreate:
		var itemID string
		err := tx.QueryRowContext(ctx, `INSERT INTO brain.memory_items(scope_id,kind,state,trust,logical_key,current_revision,created_by) VALUES ($1,$2,'active',$3,$4,1,$5) RETURNING id::text`, scopeID, step.Kind, step.Trust, nullableMemoryKey(step.LogicalKey), principalID).Scan(&itemID)
		if isSQLState(err, "23505") {
			return MemoryMutationResult{}, ErrMemoryLogicalKeyConflict
		}
		if err != nil {
			return MemoryMutationResult{}, errors.New("proposed memory could not be created")
		}
		if err := insertMemoryRevision(ctx, tx, itemID, 1, step.Document, principalID, MemoryChangeCreate); err != nil {
			return MemoryMutationResult{}, err
		}
		if err := recordMemorySecretScan(ctx, tx, projectID, itemID, 1, principalID, "clear"); err != nil {
			return MemoryMutationResult{}, err
		}
		state, err := commitMemoryChange(ctx, tx, control, principalID, projectID, scopeID, itemID, 1, MemoryChangeCreate, AuditMemoryCreate)
		if err != nil {
			return MemoryMutationResult{}, err
		}
		return MemoryMutationResult{ItemID: itemID, Revision: 1, ETag: memoryETag(itemID, 1), State: MemoryActive, ChangeSequence: state.ChangeSequence}, nil
	case MemoryProposalStepUpdate:
		locked := items[step.ItemID]
		next := locked.Revision + 1
		if err := insertMemoryRevision(ctx, tx, step.ItemID, next, step.Document, principalID, MemoryChangeUpdate); err != nil {
			return MemoryMutationResult{}, err
		}
		_, err := tx.ExecContext(ctx, `UPDATE brain.memory_items SET logical_key=$2,kind=$3,trust=$4,current_revision=$5,updated_at=statement_timestamp() WHERE id=$1`, step.ItemID, nullableMemoryKey(step.LogicalKey), step.Kind, step.Trust, next)
		if isSQLState(err, "23505") {
			return MemoryMutationResult{}, ErrMemoryLogicalKeyConflict
		}
		if err != nil {
			return MemoryMutationResult{}, errors.New("proposed memory could not be updated")
		}
		if err := recordMemorySecretScan(ctx, tx, projectID, step.ItemID, next, principalID, "clear"); err != nil {
			return MemoryMutationResult{}, err
		}
		state, err := commitMemoryChange(ctx, tx, control, principalID, projectID, locked.ScopeID, step.ItemID, next, MemoryChangeUpdate, AuditMemoryUpdate)
		if err != nil {
			return MemoryMutationResult{}, err
		}
		return MemoryMutationResult{ItemID: step.ItemID, Revision: next, ETag: memoryETag(step.ItemID, next), State: locked.State, ChangeSequence: state.ChangeSequence}, nil
	case MemoryProposalStepArchive:
		locked := items[step.ItemID]
		target := MemoryActive
		change := MemoryChangeRestore
		action := AuditMemoryRestore
		if step.Archived {
			target = MemoryArchived
			change = MemoryChangeArchive
			action = AuditMemoryArchive
		}
		if locked.State == target {
			return MemoryMutationResult{}, ErrStaleMemoryProposal
		}
		next := locked.Revision + 1
		if err := insertMemoryRevision(ctx, tx, step.ItemID, next, locked.Document, principalID, change); err != nil {
			return MemoryMutationResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE brain.memory_items SET state=$2,current_revision=$3,updated_at=statement_timestamp() WHERE id=$1`, step.ItemID, target, next); err != nil {
			return MemoryMutationResult{}, errors.New("proposed memory state could not be updated")
		}
		state, err := commitMemoryChange(ctx, tx, control, principalID, projectID, locked.ScopeID, step.ItemID, next, change, action)
		if err != nil {
			return MemoryMutationResult{}, err
		}
		return MemoryMutationResult{ItemID: step.ItemID, Revision: next, ETag: memoryETag(step.ItemID, next), State: target, ChangeSequence: state.ChangeSequence}, nil
	default:
		return MemoryMutationResult{}, errors.New("memory proposal step is unavailable")
	}
}

func readMemoryProposal(ctx context.Context, tx *sql.Tx, projectID, proposalID string, lock bool) (MemoryProposal, error) {
	var proposal MemoryProposal
	var decidedBy sql.NullString
	var decidedAt sql.NullTime
	query := `SELECT proposal.id::text,proposal.scope_id::text,scope.project_id::text,proposal.action,proposal.state,proposal.proposed_by::text,proposal.decided_by::text,proposal.created_at,proposal.decided_at,proposal.payload_sha256,proposal.payload
FROM brain.memory_proposals AS proposal
JOIN brain.scopes AS scope ON scope.id=proposal.scope_id
LEFT JOIN relay.project_lookup_aliases AS alias ON alias.alias_project_id=scope.project_id
WHERE proposal.id=$1 AND COALESCE(alias.canonical_project_id,scope.project_id)=$2`
	if lock {
		query += ` FOR UPDATE OF proposal`
	}
	if err := tx.QueryRowContext(ctx, query, proposalID, projectID).Scan(&proposal.ProposalID, &proposal.ScopeID, &proposal.ProjectID, &proposal.Action, &proposal.State, &proposal.ProposedBy, &decidedBy, &proposal.CreatedAt, &decidedAt, &proposal.payloadSHA, &proposal.payload); errors.Is(err, sql.ErrNoRows) {
		return MemoryProposal{}, ErrNotFound
	} else if err != nil {
		return MemoryProposal{}, errors.New("memory proposal is unavailable")
	}
	proposal.DecidedBy = decidedBy.String
	if decidedAt.Valid {
		value := decidedAt.Time
		proposal.DecidedAt = &value
	}
	rows, err := tx.QueryContext(ctx, `SELECT ordinal,operation,item_id::text,target_revision,logical_key,kind,trust,document,archived FROM brain.memory_proposal_steps WHERE proposal_id=$1 ORDER BY ordinal`, proposalID)
	if err != nil {
		return MemoryProposal{}, errors.New("memory proposal steps are unavailable")
	}
	for rows.Next() {
		var step MemoryProposalStep
		var itemID, logicalKey, kind, trust sql.NullString
		var document []byte
		var revision sql.NullInt64
		var archived sql.NullBool
		if err := rows.Scan(&step.Ordinal, &step.Operation, &itemID, &revision, &logicalKey, &kind, &trust, &document, &archived); err != nil {
			_ = rows.Close()
			return MemoryProposal{}, errors.New("memory proposal step is malformed")
		}
		step.ItemID, step.LogicalKey, step.Kind, step.Trust = itemID.String, logicalKey.String, kind.String, trust.String
		if revision.Valid {
			step.ExpectedETag = memoryETag(step.ItemID, revision.Int64)
			step.targetRevision = revision.Int64
		}
		if len(document) > 0 {
			step.Document = json.RawMessage(document)
		}
		step.Archived = archived.Bool
		proposal.Steps = append(proposal.Steps, step)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return MemoryProposal{}, errors.New("memory proposal steps are unavailable")
	}
	if err := rows.Close(); err != nil {
		return MemoryProposal{}, errors.New("memory proposal steps cannot close")
	}
	evidenceRows, err := tx.QueryContext(ctx, `SELECT ordinal,item_id::text,revision FROM brain.memory_proposal_evidence WHERE proposal_id=$1 ORDER BY ordinal`, proposalID)
	if err != nil {
		return MemoryProposal{}, errors.New("memory proposal evidence is unavailable")
	}
	for evidenceRows.Next() {
		var evidence MemoryProposalEvidence
		if err := evidenceRows.Scan(&evidence.Ordinal, &evidence.ItemID, &evidence.Revision); err != nil {
			_ = evidenceRows.Close()
			return MemoryProposal{}, errors.New("memory proposal evidence is malformed")
		}
		proposal.Evidence = append(proposal.Evidence, evidence)
	}
	if err := evidenceRows.Err(); err != nil {
		_ = evidenceRows.Close()
		return MemoryProposal{}, errors.New("memory proposal evidence is unavailable")
	}
	if err := evidenceRows.Close(); err != nil {
		return MemoryProposal{}, errors.New("memory proposal evidence cannot close")
	}
	resultRows, err := tx.QueryContext(ctx, `SELECT ordinal,item_id::text,revision FROM brain.memory_proposal_results WHERE proposal_id=$1 ORDER BY ordinal`, proposalID)
	if err != nil {
		return MemoryProposal{}, errors.New("memory proposal results are unavailable")
	}
	for resultRows.Next() {
		var result MemoryProposalAppliedStep
		if err := resultRows.Scan(&result.Ordinal, &result.ItemID, &result.Revision); err != nil {
			_ = resultRows.Close()
			return MemoryProposal{}, errors.New("memory proposal result is malformed")
		}
		proposal.Results = append(proposal.Results, result)
	}
	if err := resultRows.Err(); err != nil {
		_ = resultRows.Close()
		return MemoryProposal{}, errors.New("memory proposal results are unavailable")
	}
	if err := resultRows.Close(); err != nil {
		return MemoryProposal{}, errors.New("memory proposal results cannot close")
	}
	if len(proposal.Steps) < 1 || len(proposal.Steps) > maxMemoryProposalSteps || len(proposal.Evidence) > maxMemoryProposalEvidence || !validMemoryProposalShape(proposal.Action, proposalStepInputs(proposal.Steps)) {
		return MemoryProposal{}, errors.New("memory proposal is malformed")
	}
	if (proposal.State == MemoryProposalApproved && len(proposal.Results) != len(proposal.Steps)) || (proposal.State != MemoryProposalApproved && len(proposal.Results) != 0) {
		return MemoryProposal{}, errors.New("memory proposal results are malformed")
	}
	for ordinal, result := range proposal.Results {
		if result.Ordinal != ordinal || !validOpaqueID(result.ItemID) || result.Revision < 1 {
			return MemoryProposal{}, errors.New("memory proposal results are malformed")
		}
		step := proposal.Steps[ordinal]
		if (step.Operation == MemoryProposalStepCreate && result.Revision != 1) ||
			(step.Operation != MemoryProposalStepCreate && (result.ItemID != step.ItemID || result.Revision != step.targetRevision+1)) {
			return MemoryProposal{}, errors.New("memory proposal results are malformed")
		}
	}
	expectedPayload, expectedPayloadSHA := memoryProposalPayloadSHA(proposal.ProjectID, proposal.Action, proposalStepInputs(proposal.Steps), proposalEvidenceInputs(proposal.Evidence))
	storedPayloadSHA := sha256.Sum256(proposal.payload)
	if len(proposal.payloadSHA) != sha256.Size || subtle.ConstantTimeCompare(proposal.payloadSHA, expectedPayloadSHA) != 1 || subtle.ConstantTimeCompare(proposal.payloadSHA, storedPayloadSHA[:]) != 1 || !bytes.Equal(proposal.payload, expectedPayload) {
		return MemoryProposal{}, errors.New("memory proposal payload is malformed")
	}
	proposal.ETag = memoryProposalETag(proposal.ProposalID, proposal.State, proposal.payloadSHA)
	return proposal, nil
}

func proposalStepInputs(steps []MemoryProposalStep) []MemoryProposalStepInput {
	result := make([]MemoryProposalStepInput, len(steps))
	for index := range steps {
		result[index] = steps[index].MemoryProposalStepInput
	}
	return result
}

func proposalEvidenceInputs(evidence []MemoryProposalEvidence) []MemoryProposalEvidenceInput {
	result := make([]MemoryProposalEvidenceInput, len(evidence))
	for index := range evidence {
		result[index] = evidence[index].MemoryProposalEvidenceInput
	}
	return result
}

func memoryProposalOutcome(result MemoryProposalResult) (IdempotencyOutcome, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return IdempotencyOutcome{}, errors.New("memory proposal result cannot be encoded")
	}
	return IdempotencyOutcome{Status: OutcomeSucceeded, ResourceID: result.ProposalID, Result: encoded}, nil
}

func decodeMemoryProposalOutcome(outcome IdempotencyOutcome) (MemoryProposalResult, error) {
	var result MemoryProposalResult
	if outcome.Status != OutcomeSucceeded || json.Unmarshal(outcome.Result, &result) != nil || !validOpaqueID(result.ProposalID) ||
		(result.State != MemoryProposalPending && result.State != MemoryProposalApproved && result.State != MemoryProposalRejected) ||
		!validMemoryProposalETagShape(result.ETag) {
		return MemoryProposalResult{}, errors.New("memory proposal result is unavailable")
	}
	for _, mutation := range result.Mutations {
		if !validOpaqueID(mutation.ItemID) || mutation.Revision < 1 || !validMemoryETagShape(mutation.ETag) {
			return MemoryProposalResult{}, errors.New("memory proposal result is unavailable")
		}
	}
	return result, nil
}

func advanceProposalGeneration(ctx context.Context, tx *sql.Tx, projectID string) error {
	updated, err := tx.ExecContext(ctx, `UPDATE relay.projects SET content_generation=content_generation+1 WHERE id=$1 AND merged_into IS NULL`, projectID)
	if err != nil {
		return errors.New("memory proposal generation could not advance")
	}
	if count, err := updated.RowsAffected(); err != nil || count != 1 {
		return ErrNotFound
	}
	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableJSON(value json.RawMessage) any {
	if len(value) == 0 {
		return nil
	}
	return []byte(value)
}
