package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

func (r MemoryUpdateRequest) normalized() (MemoryUpdateRequest, error) {
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || !validOpaqueID(r.ItemID) || !validOpaqueID(r.IdempotencyKey) ||
		!validMemoryETagShape(r.ExpectedETag) || !validMemoryLogicalKey(r.LogicalKey) || !validMemoryToken(r.Kind) || !validMemoryToken(r.Trust) {
		return MemoryUpdateRequest{}, errors.New("invalid memory update request")
	}
	document, err := canonicalMemoryDocument(r.Document)
	if err != nil {
		return MemoryUpdateRequest{}, err
	}
	r.Document = document
	return r, nil
}

func (r MemoryArchiveRequest) validate() error {
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || !validOpaqueID(r.ItemID) || !validOpaqueID(r.IdempotencyKey) || !validMemoryETagShape(r.ExpectedETag) {
		return errors.New("invalid memory archive request")
	}
	return nil
}

func (r MemoryDeleteRequest) validate() error {
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || !validOpaqueID(r.ItemID) || !validOpaqueID(r.IdempotencyKey) || !validMemoryETagShape(r.ExpectedETag) {
		return errors.New("invalid memory delete request")
	}
	return nil
}

func validMemoryETagShape(value string) bool {
	if len(value) != len(`"m1-`)+sha256.Size*2+1 || !strings.HasPrefix(value, `"m1-`) || !strings.HasSuffix(value, `"`) {
		return false
	}
	decoded, err := hex.DecodeString(value[len(`"m1-`) : len(value)-1])
	return err == nil && len(decoded) == sha256.Size
}

// CreateMemory creates the canonical scope lazily and commits revision one.
func (d *Database) CreateMemory(ctx context.Context, raw MemoryCreateRequest) (MemoryMutationResult, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryMutationResult{}, err
	}
	body, _ := json.Marshal(struct {
		ProjectID  string          `json:"project_id"`
		LogicalKey string          `json:"logical_key,omitempty"`
		Kind       string          `json:"kind"`
		Trust      string          `json:"trust"`
		Document   json.RawMessage `json:"document"`
	}{request.ProjectID, request.LogicalKey, request.Kind, request.Trust, request.Document})
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return MemoryMutationResult{}, mutationStartError(err, "memory create transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: request.PrincipalID, Operation: "memory.create", Key: request.IdempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
		project, err := lockDirectActiveProject(ctx, tx, request.ProjectID)
		if err != nil {
			return IdempotencyOutcome{}, ErrNotFound
		}
		allowed, err := lockCapability(ctx, tx, request.PrincipalID, project.ID, CapabilityMemoryWrite)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		if !allowed {
			return IdempotencyOutcome{}, ErrNotFound
		}
		if err := guardMemoryDocument(ctx, tx, project.ID, request.Document); err != nil {
			return IdempotencyOutcome{}, err
		}
		scopeID, err := ensureMemoryScope(ctx, tx, project.ID, request.PrincipalID)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		var itemID string
		err = tx.QueryRowContext(ctx, `INSERT INTO brain.memory_items (scope_id,kind,state,trust,logical_key,current_revision,created_by)
VALUES ($1,$2,'active',$3,$4,1,$5) RETURNING id::text`, scopeID, request.Kind, request.Trust, nullableMemoryKey(request.LogicalKey), request.PrincipalID).Scan(&itemID)
		if isSQLState(err, "23505") {
			return IdempotencyOutcome{}, ErrMemoryLogicalKeyConflict
		}
		if err != nil {
			return IdempotencyOutcome{}, errors.New("memory item could not be created")
		}
		if err := insertMemoryRevision(ctx, tx, itemID, 1, request.Document, request.PrincipalID, MemoryChangeCreate); err != nil {
			return IdempotencyOutcome{}, err
		}
		if err := recordMemorySecretScan(ctx, tx, project.ID, itemID, 1, request.PrincipalID, "clear"); err != nil {
			return IdempotencyOutcome{}, err
		}
		state, err := commitMemoryChange(ctx, tx, control, request.PrincipalID, project.ID, scopeID, itemID, 1, MemoryChangeCreate, AuditMemoryCreate)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		result := MemoryMutationResult{ItemID: itemID, Revision: 1, ETag: memoryETag(itemID, 1), State: MemoryActive, ChangeSequence: state.ChangeSequence}
		return memoryOutcome(result)
	})
	if err != nil {
		return MemoryMutationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryMutationResult{}, errors.New("memory create transaction could not commit")
	}
	return decodeMemoryOutcome(outcome)
}

// GetMemory returns only an authorized current revision. Missing and denied are indistinguishable.
func (d *Database) GetMemory(ctx context.Context, principalID, projectID, itemID string) (MemoryItem, error) {
	if !validOpaqueID(principalID) || !validOpaqueID(projectID) || !validOpaqueID(itemID) {
		return MemoryItem{}, errors.New("invalid memory lookup")
	}
	canonicalProjectID, err := resolveCanonicalActiveProject(ctx, d.db, projectID)
	if err != nil {
		return MemoryItem{}, ErrNotFound
	}
	allowed, err := hasCapability(ctx, d.db, principalID, canonicalProjectID, CapabilityMemoryRead)
	if err != nil {
		return MemoryItem{}, err
	}
	if !allowed {
		return MemoryItem{}, ErrNotFound
	}
	var item MemoryItem
	var logicalKey sql.NullString
	var document, contentHash []byte
	err = d.db.QueryRowContext(ctx, `SELECT item.id::text,scope.id::text,scope.project_id::text,item.logical_key,item.kind,item.state,item.trust,item.layer,
	       item.current_revision,revision.document::text,revision.content_sha256,revision.author_principal_id::text,
       item.created_at,revision.created_at,
       COALESCE((SELECT max(change.change_sequence) FROM brain.memory_changes AS change
                 WHERE change.scope_id=scope.id AND change.item_id=item.id AND change.revision=item.current_revision
                   AND change.timeline_id=(SELECT timeline_id FROM jobs.server_state WHERE singleton)),0)
FROM brain.memory_items AS item
JOIN brain.scopes AS scope ON scope.id=item.scope_id
JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
WHERE item.id=$1 AND scope.project_id=$2
  AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)`, itemID, canonicalProjectID).Scan(
		&item.ItemID, &item.ScopeID, &item.ProjectID, &logicalKey, &item.Kind, &item.State, &item.Trust, &item.Layer,
		&item.Revision, &document, &contentHash, &item.AuthorID, &item.CreatedAt, &item.RevisionAt, &item.ChangeSequence)
	if errors.Is(err, sql.ErrNoRows) {
		return MemoryItem{}, ErrNotFound
	}
	documentDigest := sha256.Sum256(document)
	if err != nil || len(contentHash) != sha256.Size || !bytes.Equal(documentDigest[:], contentHash) {
		return MemoryItem{}, errors.New("memory item is unavailable")
	}
	item.LogicalKey = logicalKey.String
	item.Document = append(json.RawMessage(nil), document...)
	item.ContentSHA256 = hex.EncodeToString(contentHash)
	item.ETag = memoryETag(item.ItemID, item.Revision)
	return item, nil
}

// UpdateMemory appends one immutable canonical revision through exact CAS.
func (d *Database) UpdateMemory(ctx context.Context, raw MemoryUpdateRequest) (MemoryMutationResult, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryMutationResult{}, err
	}
	body, _ := json.Marshal(struct {
		ProjectID    string          `json:"project_id"`
		ItemID       string          `json:"item_id"`
		ExpectedETag string          `json:"expected_etag"`
		LogicalKey   string          `json:"logical_key,omitempty"`
		Kind         string          `json:"kind"`
		Trust        string          `json:"trust"`
		Document     json.RawMessage `json:"document"`
	}{request.ProjectID, request.ItemID, request.ExpectedETag, request.LogicalKey, request.Kind, request.Trust, request.Document})
	return d.mutateMemory(ctx, request.PrincipalID, request.IdempotencyKey, "memory.update", body, request.ProjectID, request.ItemID, CapabilityMemoryWrite, func(tx *sql.Tx, control *ControlTx, locked lockedMemory) (MemoryMutationResult, error) {
		if locked.Layer == MemoryLayerEvidence {
			return MemoryMutationResult{}, ErrImmutableMemoryEvidence
		}
		if !memoryETagMatches(request.ExpectedETag, request.ItemID, locked.Revision) {
			return MemoryMutationResult{}, ErrStaleMemoryETag
		}
		if err := guardMemoryDocument(ctx, tx, locked.ProjectID, request.Document); err != nil {
			return MemoryMutationResult{}, err
		}
		next := locked.Revision + 1
		if err := insertMemoryRevision(ctx, tx, request.ItemID, next, request.Document, request.PrincipalID, MemoryChangeUpdate); err != nil {
			return MemoryMutationResult{}, err
		}
		_, err := tx.ExecContext(ctx, `UPDATE brain.memory_items SET logical_key=$2,kind=$3,trust=$4,current_revision=$5,updated_at=statement_timestamp() WHERE id=$1`, request.ItemID, nullableMemoryKey(request.LogicalKey), request.Kind, request.Trust, next)
		if isSQLState(err, "23505") {
			return MemoryMutationResult{}, ErrMemoryLogicalKeyConflict
		}
		if err != nil {
			return MemoryMutationResult{}, errors.New("memory item could not be updated")
		}
		released, err := releaseActiveMemoryQuarantine(ctx, tx, request.PrincipalID, request.ItemID)
		if err != nil {
			return MemoryMutationResult{}, err
		}
		if released {
			if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: request.PrincipalID, ProjectID: locked.ProjectID, Action: AuditMemoryQuarantineRelease, Outcome: AuditSucceeded, TargetKind: AuditTargetMemoryItem, TargetID: request.ItemID}); err != nil {
				return MemoryMutationResult{}, err
			}
		}
		if err := recordMemorySecretScan(ctx, tx, locked.ProjectID, request.ItemID, next, request.PrincipalID, "clear"); err != nil {
			return MemoryMutationResult{}, err
		}
		state, err := commitMemoryChange(ctx, tx, control, request.PrincipalID, locked.ProjectID, locked.ScopeID, request.ItemID, next, MemoryChangeUpdate, AuditMemoryUpdate)
		if err != nil {
			return MemoryMutationResult{}, err
		}
		return MemoryMutationResult{ItemID: request.ItemID, Revision: next, ETag: memoryETag(request.ItemID, next), State: locked.State, ChangeSequence: state.ChangeSequence}, nil
	})
}

// ArchiveMemory reversibly archives or restores one memory and advances its ETag.
func (d *Database) ArchiveMemory(ctx context.Context, request MemoryArchiveRequest) (MemoryMutationResult, error) {
	if err := request.validate(); err != nil {
		return MemoryMutationResult{}, err
	}
	body, _ := json.Marshal(struct {
		ProjectID    string `json:"project_id"`
		ItemID       string `json:"item_id"`
		ExpectedETag string `json:"expected_etag"`
		Archived     bool   `json:"archived"`
	}{request.ProjectID, request.ItemID, request.ExpectedETag, request.Archived})
	return d.mutateMemory(ctx, request.PrincipalID, request.IdempotencyKey, "memory.archive", body, request.ProjectID, request.ItemID, CapabilityMemoryWrite, func(tx *sql.Tx, control *ControlTx, locked lockedMemory) (MemoryMutationResult, error) {
		if !memoryETagMatches(request.ExpectedETag, request.ItemID, locked.Revision) {
			return MemoryMutationResult{}, ErrStaleMemoryETag
		}
		target := MemoryActive
		change := MemoryChangeRestore
		action := AuditMemoryRestore
		if request.Archived {
			target = MemoryArchived
			change = MemoryChangeArchive
			action = AuditMemoryArchive
		}
		if locked.State == target {
			var changeSequence int64
			if err := tx.QueryRowContext(ctx, `SELECT COALESCE((
    SELECT max(change.change_sequence) FROM brain.memory_changes AS change
    WHERE change.timeline_id=state.timeline_id AND change.scope_id=$1 AND change.item_id=$2 AND change.revision=$3
),0)
FROM jobs.server_state AS state WHERE state.singleton`, locked.ScopeID, request.ItemID, locked.Revision).Scan(&changeSequence); err != nil {
				return MemoryMutationResult{}, errors.New("memory state is unavailable")
			}
			return MemoryMutationResult{ItemID: request.ItemID, Revision: locked.Revision, ETag: memoryETag(request.ItemID, locked.Revision), State: target, ChangeSequence: changeSequence}, nil
		}
		next := locked.Revision + 1
		if err := insertMemoryRevision(ctx, tx, request.ItemID, next, locked.Document, request.PrincipalID, change); err != nil {
			return MemoryMutationResult{}, err
		}
		if locked.Layer == MemoryLayerEvidence {
			if err := copyMemoryEvidenceProvenance(ctx, tx, request.ItemID, locked.Revision, next, request.PrincipalID); err != nil {
				return MemoryMutationResult{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE brain.memory_items SET state=$2,current_revision=$3,updated_at=statement_timestamp() WHERE id=$1`, request.ItemID, target, next); err != nil {
			return MemoryMutationResult{}, errors.New("memory archive state could not be updated")
		}
		state, err := commitMemoryChange(ctx, tx, control, request.PrincipalID, locked.ProjectID, locked.ScopeID, request.ItemID, next, change, action)
		if err != nil {
			return MemoryMutationResult{}, err
		}
		return MemoryMutationResult{ItemID: request.ItemID, Revision: next, ETag: memoryETag(request.ItemID, next), State: target, ChangeSequence: state.ChangeSequence}, nil
	})
}

// DeleteMemory irreversibly removes the item and every canonical revision.
func (d *Database) DeleteMemory(ctx context.Context, request MemoryDeleteRequest) (MemoryMutationResult, error) {
	if err := request.validate(); err != nil {
		return MemoryMutationResult{}, err
	}
	body, _ := json.Marshal(struct {
		ProjectID    string `json:"project_id"`
		ItemID       string `json:"item_id"`
		ExpectedETag string `json:"expected_etag"`
	}{request.ProjectID, request.ItemID, request.ExpectedETag})
	return d.mutateMemory(ctx, request.PrincipalID, request.IdempotencyKey, "memory.delete", body, request.ProjectID, request.ItemID, CapabilityMemoryPurge, func(tx *sql.Tx, _ *ControlTx, locked lockedMemory) (MemoryMutationResult, error) {
		if !memoryETagMatches(request.ExpectedETag, request.ItemID, locked.Revision) {
			return MemoryMutationResult{}, ErrStaleMemoryETag
		}
		var scopeID, timelineID string
		var revision, changeSequence int64
		if err := tx.QueryRowContext(ctx, `SELECT scope_id::text,revision,timeline_id::text,change_sequence
FROM brain.purge_memory($1::uuid,$2::uuid,$3::uuid,$4)`, request.PrincipalID, locked.ProjectID, request.ItemID, locked.Revision).Scan(&scopeID, &revision, &timelineID, &changeSequence); err != nil {
			return MemoryMutationResult{}, errors.New("memory item could not be purged")
		}
		if scopeID != locked.ScopeID || revision != locked.Revision || !validOpaqueID(timelineID) || changeSequence < 1 {
			return MemoryMutationResult{}, errors.New("memory purge result is unavailable")
		}
		return MemoryMutationResult{ItemID: request.ItemID, Revision: revision, ChangeSequence: changeSequence}, nil
	})
}

type lockedMemory struct {
	ScopeID     string
	ProjectID   string
	Revision    int64
	State       MemoryState
	Layer       MemoryLayer
	Document    []byte
	ContentHash []byte
}

func (d *Database) mutateMemory(ctx context.Context, principalID, idempotencyKey, operation string, body []byte, projectID, itemID string, capability Capability, mutation func(*sql.Tx, *ControlTx, lockedMemory) (MemoryMutationResult, error)) (MemoryMutationResult, error) {
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return MemoryMutationResult{}, mutationStartError(err, "memory transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: principalID, Operation: operation, Key: idempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
		project, err := lockDirectActiveProject(ctx, tx, projectID)
		if err != nil {
			return IdempotencyOutcome{}, ErrNotFound
		}
		allowed, err := lockCapability(ctx, tx, principalID, project.ID, capability)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		if !allowed {
			return IdempotencyOutcome{}, ErrNotFound
		}
		locked, err := lockMemory(ctx, tx, project.ID, itemID)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		result, err := mutation(tx, control, locked)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		return memoryOutcome(result)
	})
	if err != nil {
		return MemoryMutationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryMutationResult{}, errors.New("memory transaction could not commit")
	}
	return decodeMemoryOutcome(outcome)
}

func lockMemory(ctx context.Context, tx *sql.Tx, projectID, itemID string) (lockedMemory, error) {
	var locked lockedMemory
	locked.ProjectID = projectID
	err := tx.QueryRowContext(ctx, `SELECT scope.id::text,item.current_revision,item.state,item.layer,revision.document::text,revision.content_sha256
FROM brain.memory_items AS item
JOIN brain.scopes AS scope ON scope.id=item.scope_id
JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
WHERE item.id=$1 AND scope.project_id=$2
FOR UPDATE OF item`, itemID, projectID).Scan(&locked.ScopeID, &locked.Revision, &locked.State, &locked.Layer, &locked.Document, &locked.ContentHash)
	if errors.Is(err, sql.ErrNoRows) {
		return lockedMemory{}, ErrNotFound
	}
	if err != nil || len(locked.ContentHash) != sha256.Size {
		return lockedMemory{}, errors.New("memory item could not be locked")
	}
	return locked, nil
}

func ensureMemoryScope(ctx context.Context, tx *sql.Tx, projectID, principalID string) (string, error) {
	var scopeID string
	err := tx.QueryRowContext(ctx, `INSERT INTO brain.scopes (project_id,created_by) VALUES ($1,$2)
ON CONFLICT (project_id) DO NOTHING RETURNING id::text`, projectID, principalID).Scan(&scopeID)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `SELECT id::text FROM brain.scopes WHERE project_id=$1`, projectID).Scan(&scopeID)
	}
	if err != nil {
		return "", errors.New("memory scope is unavailable")
	}
	return scopeID, nil
}

func insertMemoryRevision(ctx context.Context, tx *sql.Tx, itemID string, revision int64, document []byte, principalID string, operation MemoryChangeType) error {
	var storedDocument string
	if err := tx.QueryRowContext(ctx, `SELECT $1::jsonb::text`, string(document)).Scan(&storedDocument); err != nil || len(storedDocument) > maxMemoryDocumentBytes {
		return errors.New("memory document could not be normalized")
	}
	contentHash := sha256.Sum256([]byte(storedDocument))
	_, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_revisions (item_id,revision,document,content_sha256,author_principal_id,operation)
	VALUES ($1,$2,$3,$4,$5,$6)`, itemID, revision, storedDocument, contentHash[:], principalID, operation)
	if err != nil {
		return errors.New("memory revision could not be appended")
	}
	return nil
}

func commitMemoryChange(ctx context.Context, tx *sql.Tx, control *ControlTx, principalID, projectID, scopeID, itemID string, revision int64, change MemoryChangeType, action AuditAction) (InstallationState, error) {
	advanced, err := tx.ExecContext(ctx, `UPDATE relay.projects SET content_generation=content_generation+1 WHERE id=$1 AND merged_into IS NULL`, projectID)
	if err != nil {
		return InstallationState{}, errors.New("project content generation could not advance")
	}
	if count, err := advanced.RowsAffected(); err != nil || count != 1 {
		return InstallationState{}, ErrNotFound
	}
	state, err := control.AdvanceChange(ctx)
	if err != nil {
		return InstallationState{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_changes (timeline_id,change_sequence,scope_id,item_id,operation,revision)
VALUES ($1,$2,$3,$4,$5,$6)`, state.TimelineID, state.ChangeSequence, scopeID, itemID, change, revision); err != nil {
		return InstallationState{}, errors.New("memory change could not be recorded")
	}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: principalID, ProjectID: projectID, Action: action, Outcome: AuditSucceeded, TargetKind: AuditTargetMemoryItem, TargetID: itemID}); err != nil {
		return InstallationState{}, err
	}
	return state, nil
}

func memoryOutcome(result MemoryMutationResult) (IdempotencyOutcome, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return IdempotencyOutcome{}, errors.New("memory result cannot be encoded")
	}
	return IdempotencyOutcome{Status: OutcomeSucceeded, ResourceID: result.ItemID, Result: encoded}, nil
}

func decodeMemoryOutcome(outcome IdempotencyOutcome) (MemoryMutationResult, error) {
	var result MemoryMutationResult
	if outcome.Status != OutcomeSucceeded || json.Unmarshal(outcome.Result, &result) != nil || !validOpaqueID(result.ItemID) || result.Revision < 1 || result.ChangeSequence < 0 || (result.ETag != "" && !validMemoryETagShape(result.ETag)) {
		return MemoryMutationResult{}, errors.New("memory result is unavailable")
	}
	return result, nil
}

func nullableMemoryKey(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// FetchMemoryChanges returns a bounded timeline-aware feed for one authorized project.
func (d *Database) FetchMemoryChanges(ctx context.Context, request MemoryChangeRequest) (MemoryChangePage, error) {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.ProjectID) || request.Limit < 1 || request.Limit > maxMemoryChangePage {
		return MemoryChangePage{}, errors.New("invalid memory change request")
	}
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryChangePage{}, errors.New("memory change snapshot cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(ctx, tx, request.ProjectID)
	if err != nil {
		return MemoryChangePage{}, ErrNotFound
	}
	allowed, err := hasCapability(ctx, tx, request.PrincipalID, projectID, CapabilityMemoryRead)
	if err != nil {
		return MemoryChangePage{}, err
	}
	if !allowed {
		return MemoryChangePage{}, ErrNotFound
	}
	var current InstallationState
	if err := tx.QueryRowContext(ctx, `SELECT installation_id::text,timeline_id::text,change_sequence FROM jobs.server_state WHERE singleton`).Scan(&current.InstallationID, &current.TimelineID, &current.ChangeSequence); err != nil {
		return MemoryChangePage{}, errors.New("memory change cursor is unavailable")
	}
	if err := ValidateCursor(current, request.Cursor); err != nil {
		return MemoryChangePage{}, err
	}
	var scopeID string
	err = tx.QueryRowContext(ctx, `SELECT id::text FROM brain.scopes WHERE project_id=$1`, projectID).Scan(&scopeID)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return MemoryChangePage{}, errors.New("memory change snapshot cannot commit")
		}
		return MemoryChangePage{Changes: []MemoryChange{}, Cursor: current}, nil
	}
	if err != nil {
		return MemoryChangePage{}, errors.New("memory scope is unavailable")
	}
	rows, err := tx.QueryContext(ctx, `SELECT timeline_id::text,change_sequence,scope_id::text,item_id::text,operation,revision,occurred_at
FROM brain.memory_changes
WHERE scope_id=$1 AND timeline_id=$2 AND change_sequence>$3
ORDER BY change_sequence,item_id LIMIT $4`, scopeID, current.TimelineID, request.Cursor.ChangeSequence, request.Limit+1)
	if err != nil {
		return MemoryChangePage{}, errors.New("memory changes are unavailable")
	}
	defer func() { _ = rows.Close() }()
	changes := make([]MemoryChange, 0, request.Limit+1)
	for rows.Next() {
		var change MemoryChange
		if err := rows.Scan(&change.TimelineID, &change.ChangeSequence, &change.ScopeID, &change.ItemID, &change.Type, &change.Revision, &change.OccurredAt); err != nil {
			return MemoryChangePage{}, errors.New("memory change is malformed")
		}
		changes = append(changes, change)
	}
	if err := rows.Err(); err != nil {
		return MemoryChangePage{}, errors.New("memory changes are unavailable")
	}
	more := len(changes) > request.Limit
	if more {
		changes = changes[:request.Limit]
	}
	cursor := current
	if more && len(changes) > 0 {
		cursor.ChangeSequence = changes[len(changes)-1].ChangeSequence
	}
	if err := tx.Commit(); err != nil {
		return MemoryChangePage{}, errors.New("memory change snapshot cannot commit")
	}
	return MemoryChangePage{Changes: changes, Cursor: cursor, More: more}, nil
}
