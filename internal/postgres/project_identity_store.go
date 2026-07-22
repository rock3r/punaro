package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

var (
	// ErrProjectIdentityClaimed reports that a normalized locator belongs to another project.
	ErrProjectIdentityClaimed = errors.New("project identity is already claimed")
	// ErrMergedProject reports an attempted mutation through a retired project ID.
	ErrMergedProject = errors.New("project is a permanent lookup alias")
	// ErrStaleProjectMerge reports an expired or generation-mismatched preview.
	ErrStaleProjectMerge = errors.New("project merge preview is stale")
	// ErrProjectMergeTooLarge reports a merge outside a hard transaction bound.
	ErrProjectMergeTooLarge = errors.New("project merge exceeds a safe bound")
	// ErrProjectPreviewCapacity reports that a bounded live-preview quota is full.
	ErrProjectPreviewCapacity = errors.New("project merge preview capacity is full")
	// ErrProjectMergeAttachmentState fences project identities until the later
	// attachment lifecycle defines an explicit, transactional merge behavior.
	ErrProjectMergeAttachmentState = errors.New("project attachment state blocks merge")
	// ErrProjectMergeBrainState prevents retiring a project while canonical
	// memory would remain bound to its now-inaccessible scope.
	ErrProjectMergeBrainState = errors.New("project memory state blocks merge")
)

const (
	maxProjectIdentities          = 100
	maxProjectMergeGrants         = 1000
	maxProjectMergeAliases        = 1000
	maxProjectMergePrivateRecords = 1000
	maxNewlyAuthorizedPrincipals  = 256
	maxLiveProjectPreviewsActor   = 16
	maxLiveProjectPreviews        = 1024
	projectPreviewPruneBatch      = 100
	projectPreviewTTL             = 10 * time.Minute
	projectPreviewRetention       = 24 * time.Hour
	projectMergePreviewLockKey    = int64(0x50756e61726f4d50) // "PunaroMP"
)

// ProjectIdentityAttachRequest names one unique identity claim.
type ProjectIdentityAttachRequest struct {
	ActorPrincipalID string
	ProjectID        string
	IdempotencyKey   string
	Kind             ProjectIdentityKind
	Locator          string
}

// ProjectIdentityAttachment is the stable result of an identity claim.
type ProjectIdentityAttachment struct {
	IdentityID        string              `json:"identity_id"`
	ProjectID         string              `json:"project_id"`
	Kind              ProjectIdentityKind `json:"kind"`
	NormalizedLocator string              `json:"normalized_locator"`
	ChangeSequence    int64               `json:"change_sequence"`
}

// ProjectIdentityResolution returns only an identity visible to the caller.
type ProjectIdentityResolution struct {
	IdentityID string
	ProjectID  string
	Kind       ProjectIdentityKind
}

// ProjectMergePreviewRequest identifies the local project and claimed locator.
type ProjectMergePreviewRequest struct {
	ActorPrincipalID string
	SourceProjectID  string
	IdempotencyKey   string
	Kind             ProjectIdentityKind
	Locator          string
}

// ProjectMergePreview is a bounded, generation-fenced operator decision.
type ProjectMergePreview struct {
	PreviewID                   string    `json:"preview_id"`
	SourceProjectID             string    `json:"source_project_id"`
	CanonicalProjectID          string    `json:"canonical_project_id"`
	IdentityCount               int       `json:"identity_count"`
	GrantCount                  int       `json:"grant_count"`
	AliasCount                  int       `json:"alias_count"`
	PendingEnrollmentCount      int       `json:"pending_enrollment_count"`
	NewlyAuthorizedPrincipalIDs []string  `json:"newly_authorized_principal_ids"`
	PrivateRecordCount          int       `json:"private_record_count"`
	ConflictCount               int       `json:"conflict_count"`
	ExpiresAt                   time.Time `json:"expires_at"`
}

// ProjectMergeApproval consumes one stored preview. M-4 has no logical-key
// conflicts yet, so any non-empty conflict resolution is rejected by shape.
type ProjectMergeApproval struct {
	ActorPrincipalID string
	PreviewID        string
}

// ProjectMergeResult is the exact durable merge response returned on retries.
type ProjectMergeResult struct {
	AliasProjectID     string `json:"alias_project_id"`
	CanonicalProjectID string `json:"canonical_project_id"`
	ChangeSequence     int64  `json:"change_sequence"`
}

type projectFence struct {
	ID                 string
	IdentityGeneration int64
	ACLGeneration      int64
	ContentGeneration  int64
	MergedInto         sql.NullString
}

// AttachProjectIdentity attaches an unclaimed normalized locator without
// changing any authorization grant.
func (d *Database) AttachProjectIdentity(ctx context.Context, request ProjectIdentityAttachRequest) (ProjectIdentityAttachment, error) {
	locator, err := NormalizeProjectIdentityLocator(request.Kind, request.Locator)
	if err != nil || !validOpaqueID(request.ActorPrincipalID) || !validOpaqueID(request.ProjectID) || !validOpaqueID(request.IdempotencyKey) {
		return ProjectIdentityAttachment{}, errors.New("invalid project identity attachment")
	}
	body, _ := json.Marshal(struct {
		ProjectID string              `json:"project_id"`
		Kind      ProjectIdentityKind `json:"kind"`
		Locator   string              `json:"locator"`
	}{request.ProjectID, request.Kind, locator})
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return ProjectIdentityAttachment{}, mutationStartError(err, "project identity transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: request.ActorPrincipalID, Operation: "project.identity.attach", Key: request.IdempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
		project, err := lockDirectActiveProject(ctx, tx, request.ProjectID)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		writeAllowed, err := lockCapability(ctx, tx, request.ActorPrincipalID, project.ID, CapabilityProjectWrite)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		attachAllowed, err := lockCapability(ctx, tx, request.ActorPrincipalID, project.ID, CapabilityProjectAttachUnclaimed)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		if !writeAllowed || !attachAllowed {
			return IdempotencyOutcome{}, ErrForbidden
		}
		var identityID, claimedProject string
		err = tx.QueryRowContext(ctx, `SELECT id::text, project_id::text FROM relay.project_identities WHERE kind = $1 AND normalized_locator = $2`, request.Kind, locator).Scan(&identityID, &claimedProject)
		if err == nil {
			if claimedProject != project.ID {
				return IdempotencyOutcome{}, ErrProjectIdentityClaimed
			}
			state, err := currentInstallationState(ctx, tx)
			if err != nil {
				return IdempotencyOutcome{}, err
			}
			result := ProjectIdentityAttachment{IdentityID: identityID, ProjectID: project.ID, Kind: request.Kind, NormalizedLocator: locator, ChangeSequence: state.ChangeSequence}
			encoded, _ := json.Marshal(result)
			return IdempotencyOutcome{Status: OutcomeSucceeded, ResourceID: identityID, Result: encoded}, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return IdempotencyOutcome{}, errors.New("project identity claim cannot be inspected")
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM relay.project_identities WHERE project_id = $1`, project.ID).Scan(&count); err != nil {
			return IdempotencyOutcome{}, errors.New("project identity capacity cannot be checked")
		}
		if count >= maxProjectIdentities {
			return IdempotencyOutcome{}, ErrProjectMergeTooLarge
		}
		err = tx.QueryRowContext(ctx, `INSERT INTO relay.project_identities (project_id, kind, normalized_locator, created_by)
VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING id::text`, project.ID, request.Kind, locator, request.ActorPrincipalID).Scan(&identityID)
		inserted := true
		if errors.Is(err, sql.ErrNoRows) {
			inserted = false
			var claimedProject string
			err = tx.QueryRowContext(ctx, `SELECT id::text, project_id::text FROM relay.project_identities WHERE kind = $1 AND normalized_locator = $2`, request.Kind, locator).Scan(&identityID, &claimedProject)
			if err == nil && claimedProject != project.ID {
				return IdempotencyOutcome{}, ErrProjectIdentityClaimed
			}
		}
		if err != nil {
			return IdempotencyOutcome{}, errors.New("project identity could not be claimed")
		}
		var changeSequence int64
		if inserted {
			if _, err := tx.ExecContext(ctx, `UPDATE relay.projects SET identity_generation = identity_generation + 1, content_generation = content_generation + 1 WHERE id = $1`, project.ID); err != nil {
				return IdempotencyOutcome{}, errors.New("project identity generation could not advance")
			}
			if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: request.ActorPrincipalID, ProjectID: project.ID, Action: AuditProjectIdentityAttach, Outcome: AuditSucceeded, TargetKind: AuditTargetProjectIdentity, TargetID: identityID}); err != nil {
				return IdempotencyOutcome{}, err
			}
			state, err := control.AdvanceChange(ctx)
			if err != nil {
				return IdempotencyOutcome{}, err
			}
			changeSequence = state.ChangeSequence
		} else {
			state, err := currentInstallationState(ctx, tx)
			if err != nil {
				return IdempotencyOutcome{}, err
			}
			changeSequence = state.ChangeSequence
		}
		result := ProjectIdentityAttachment{IdentityID: identityID, ProjectID: project.ID, Kind: request.Kind, NormalizedLocator: locator, ChangeSequence: changeSequence}
		encoded, _ := json.Marshal(result)
		return IdempotencyOutcome{Status: OutcomeSucceeded, ResourceID: identityID, Result: encoded}, nil
	})
	if err != nil {
		return ProjectIdentityAttachment{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProjectIdentityAttachment{}, errors.New("project identity transaction could not commit")
	}
	var result ProjectIdentityAttachment
	if outcome.Status != OutcomeSucceeded || json.Unmarshal(outcome.Result, &result) != nil || !validOpaqueID(result.IdentityID) || !validOpaqueID(result.ProjectID) || result.ChangeSequence < 0 {
		return ProjectIdentityAttachment{}, errors.New("project identity result is unavailable")
	}
	return result, nil
}

// ResolveProjectIdentity reveals a locator only when the caller can discover
// the active project. Authorization failures are intentionally not-found.
func (d *Database) ResolveProjectIdentity(ctx context.Context, actorPrincipalID string, kind ProjectIdentityKind, rawLocator string) (ProjectIdentityResolution, error) {
	locator, err := NormalizeProjectIdentityLocator(kind, rawLocator)
	if err != nil || !validOpaqueID(actorPrincipalID) {
		return ProjectIdentityResolution{}, errors.New("invalid project identity lookup")
	}
	var result ProjectIdentityResolution
	err = d.db.QueryRowContext(ctx, `SELECT identity.id::text, identity.project_id::text, identity.kind
FROM relay.project_identities AS identity
JOIN relay.projects AS project ON project.id = identity.project_id
WHERE identity.kind = $1 AND identity.normalized_locator = $2 AND project.merged_into IS NULL`, kind, locator).Scan(&result.IdentityID, &result.ProjectID, &result.Kind)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectIdentityResolution{}, ErrNotFound
	}
	if err != nil {
		return ProjectIdentityResolution{}, errors.New("project identity lookup failed")
	}
	allowed, err := hasCapability(ctx, d.db, actorPrincipalID, result.ProjectID, CapabilityProjectDiscover)
	if err != nil {
		return ProjectIdentityResolution{}, err
	}
	if !allowed {
		return ProjectIdentityResolution{}, ErrNotFound
	}
	return result, nil
}

// PreviewProjectIdentityMerge creates a bounded decision record for a claimed
// locator collision. It holds the same project locks used by every participant.
func (d *Database) PreviewProjectIdentityMerge(ctx context.Context, request ProjectMergePreviewRequest) (ProjectMergePreview, error) {
	locator, err := NormalizeProjectIdentityLocator(request.Kind, request.Locator)
	if err != nil || !validOpaqueID(request.ActorPrincipalID) || !validOpaqueID(request.SourceProjectID) || !validOpaqueID(request.IdempotencyKey) {
		return ProjectMergePreview{}, errors.New("invalid project merge preview")
	}
	body, _ := json.Marshal(struct {
		SourceProjectID string              `json:"source_project_id"`
		Kind            ProjectIdentityKind `json:"kind"`
		Locator         string              `json:"locator"`
	}{request.SourceProjectID, request.Kind, locator})
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return ProjectMergePreview{}, mutationStartError(err, "project merge preview transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: request.ActorPrincipalID, Operation: "project.merge.preview", Key: request.IdempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
		if err := lockProjectJobMutations(ctx, tx, true); err != nil {
			return IdempotencyOutcome{}, err
		}
		if err := lockGrantMutations(ctx, tx); err != nil {
			return IdempotencyOutcome{}, err
		}
		if err := lockProjectMergePreviews(ctx, tx); err != nil {
			return IdempotencyOutcome{}, err
		}
		var identityID, canonicalProjectID string
		if err := tx.QueryRowContext(ctx, `SELECT id::text, project_id::text FROM relay.project_identities WHERE kind = $1 AND normalized_locator = $2`, request.Kind, locator).Scan(&identityID, &canonicalProjectID); errors.Is(err, sql.ErrNoRows) {
			return IdempotencyOutcome{}, ErrNotFound
		} else if err != nil {
			return IdempotencyOutcome{}, errors.New("claimed project identity cannot be inspected")
		}
		if canonicalProjectID == request.SourceProjectID {
			return IdempotencyOutcome{}, errors.New("project identity is already attached")
		}
		projects, err := lockProjectPair(ctx, tx, request.SourceProjectID, canonicalProjectID)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		source, sourceOK := projects[request.SourceProjectID]
		canonical, canonicalOK := projects[canonicalProjectID]
		if !sourceOK || !canonicalOK || source.MergedInto.Valid || canonical.MergedInto.Valid {
			return IdempotencyOutcome{}, ErrMergedProject
		}
		var claimedProject string
		if err := tx.QueryRowContext(ctx, `SELECT project_id::text FROM relay.project_identities WHERE id = $1`, identityID).Scan(&claimedProject); err != nil || claimedProject != canonical.ID {
			return IdempotencyOutcome{}, ErrStaleProjectMerge
		}
		for _, projectID := range []string{source.ID, canonical.ID} {
			allowed, err := lockCapability(ctx, tx, request.ActorPrincipalID, projectID, CapabilityProjectAdminister)
			if err != nil {
				return IdempotencyOutcome{}, err
			}
			if !allowed {
				return IdempotencyOutcome{}, ErrForbidden
			}
		}
		if err := pruneProjectMergePreviews(ctx, tx); err != nil {
			return IdempotencyOutcome{}, err
		}
		if err := checkProjectPreviewCapacity(ctx, tx, request.ActorPrincipalID); err != nil {
			return IdempotencyOutcome{}, err
		}
		identityCount, grantCount, aliasCount, pendingEnrollmentCount, privateRecordCount, newlyAuthorized, err := projectMergeCounts(ctx, tx, request.ActorPrincipalID, source.ID, canonical.ID)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		var globalGeneration int64
		if err := tx.QueryRowContext(ctx, `SELECT global_generation FROM auth.project_acl_state WHERE singleton FOR SHARE`).Scan(&globalGeneration); err != nil {
			return IdempotencyOutcome{}, errors.New("project authorization generation cannot be read")
		}
		var previewID string
		var expiresAt time.Time
		err = tx.QueryRowContext(ctx, `INSERT INTO relay.project_merge_previews (
    actor_principal_id, source_project_id, canonical_project_id, identity_id,
    source_identity_generation, source_acl_generation, source_content_generation,
    canonical_identity_generation, canonical_acl_generation, canonical_content_generation,
    global_acl_generation, identity_count, grant_count, alias_count, newly_authorized_principal_ids,
    private_record_count, expires_at, pending_enrollment_count
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::uuid[],$16,statement_timestamp() + ($17 * interval '1 microsecond'),$18)
RETURNING id::text, expires_at`, request.ActorPrincipalID, source.ID, canonical.ID, identityID,
			source.IdentityGeneration, source.ACLGeneration, source.ContentGeneration,
			canonical.IdentityGeneration, canonical.ACLGeneration, canonical.ContentGeneration,
			globalGeneration, identityCount, grantCount, aliasCount, newlyAuthorized, privateRecordCount, projectPreviewTTL.Microseconds(), pendingEnrollmentCount).Scan(&previewID, &expiresAt)
		if err != nil {
			return IdempotencyOutcome{}, errors.New("project merge preview could not be recorded")
		}
		preview := ProjectMergePreview{PreviewID: previewID, SourceProjectID: source.ID, CanonicalProjectID: canonical.ID, IdentityCount: identityCount, GrantCount: grantCount, AliasCount: aliasCount, PendingEnrollmentCount: pendingEnrollmentCount, NewlyAuthorizedPrincipalIDs: newlyAuthorized, PrivateRecordCount: privateRecordCount, ConflictCount: 0, ExpiresAt: expiresAt}
		if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: request.ActorPrincipalID, ProjectID: canonical.ID, Action: AuditProjectMergePreview, Outcome: AuditSucceeded, TargetKind: AuditTargetProjectMerge, TargetID: previewID}); err != nil {
			return IdempotencyOutcome{}, err
		}
		if _, err := control.AdvanceChange(ctx); err != nil {
			return IdempotencyOutcome{}, err
		}
		encoded, _ := json.Marshal(preview)
		return IdempotencyOutcome{Status: OutcomeSucceeded, ResourceID: previewID, Result: encoded}, nil
	})
	if err != nil {
		return ProjectMergePreview{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProjectMergePreview{}, errors.New("project merge preview transaction could not commit")
	}
	var result ProjectMergePreview
	if outcome.Status != OutcomeSucceeded || json.Unmarshal(outcome.Result, &result) != nil || !validOpaqueID(result.PreviewID) || !validOpaqueID(result.SourceProjectID) || !validOpaqueID(result.CanonicalProjectID) {
		return ProjectMergePreview{}, errors.New("project merge preview result is unavailable")
	}
	return result, nil
}

// ApproveProjectIdentityMerge performs one bounded merge or returns the exact
// stored result to the same actor after a lost response.
func (d *Database) ApproveProjectIdentityMerge(ctx context.Context, approval ProjectMergeApproval) (ProjectMergeResult, error) {
	if !validOpaqueID(approval.ActorPrincipalID) || !validOpaqueID(approval.PreviewID) {
		return ProjectMergeResult{}, errors.New("invalid project merge approval")
	}
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return ProjectMergeResult{}, mutationStartError(err, "project merge transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockProjectJobMutations(ctx, tx, true); err != nil {
		return ProjectMergeResult{}, err
	}
	if err := lockGrantMutations(ctx, tx); err != nil {
		return ProjectMergeResult{}, err
	}
	if err := lockProjectMergePreviews(ctx, tx); err != nil {
		return ProjectMergeResult{}, err
	}
	var actorID, sourceID, canonicalID, identityID string
	var sourceIdentity, sourceACL, sourceContent, canonicalIdentity, canonicalACL, canonicalContent, globalACL int64
	var storedIdentityCount, storedGrantCount, storedAliasCount, storedPendingEnrollmentCount, storedPrivateRecordCount int
	var expiresAt time.Time
	var unexpired bool
	var consumedAt sql.NullTime
	var storedResult []byte
	err = tx.QueryRowContext(ctx, `SELECT actor_principal_id::text, source_project_id::text, canonical_project_id::text, identity_id::text,
    source_identity_generation, source_acl_generation, source_content_generation,
    canonical_identity_generation, canonical_acl_generation, canonical_content_generation,
    global_acl_generation, identity_count, grant_count, alias_count, pending_enrollment_count, private_record_count,
    expires_at, expires_at > statement_timestamp(), consumed_at, result
FROM relay.project_merge_previews WHERE id = $1 FOR UPDATE`, approval.PreviewID).Scan(
		&actorID, &sourceID, &canonicalID, &identityID,
		&sourceIdentity, &sourceACL, &sourceContent, &canonicalIdentity, &canonicalACL, &canonicalContent,
		&globalACL, &storedIdentityCount, &storedGrantCount, &storedAliasCount, &storedPendingEnrollmentCount, &storedPrivateRecordCount,
		&expiresAt, &unexpired, &consumedAt, &storedResult)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectMergeResult{}, ErrNotFound
	}
	if err != nil {
		return ProjectMergeResult{}, errors.New("project merge preview cannot be read")
	}
	if actorID != approval.ActorPrincipalID {
		return ProjectMergeResult{}, ErrForbidden
	}
	if consumedAt.Valid {
		var result ProjectMergeResult
		if json.Unmarshal(storedResult, &result) != nil {
			return ProjectMergeResult{}, errors.New("project merge result is unavailable")
		}
		return result, nil
	}
	if !unexpired {
		return ProjectMergeResult{}, ErrStaleProjectMerge
	}
	projects, err := lockProjectPair(ctx, tx, sourceID, canonicalID)
	if err != nil {
		return ProjectMergeResult{}, err
	}
	source, sourceOK := projects[sourceID]
	canonical, canonicalOK := projects[canonicalID]
	if !sourceOK || !canonicalOK || source.MergedInto.Valid || canonical.MergedInto.Valid ||
		source.IdentityGeneration != sourceIdentity || source.ACLGeneration != sourceACL || source.ContentGeneration != sourceContent ||
		canonical.IdentityGeneration != canonicalIdentity || canonical.ACLGeneration != canonicalACL || canonical.ContentGeneration != canonicalContent {
		return ProjectMergeResult{}, ErrStaleProjectMerge
	}
	var currentGlobal int64
	if err := tx.QueryRowContext(ctx, `SELECT global_generation FROM auth.project_acl_state WHERE singleton FOR SHARE`).Scan(&currentGlobal); err != nil || currentGlobal != globalACL {
		return ProjectMergeResult{}, ErrStaleProjectMerge
	}
	var claimedProject string
	if err := tx.QueryRowContext(ctx, `SELECT project_id::text FROM relay.project_identities WHERE id = $1`, identityID).Scan(&claimedProject); err != nil || claimedProject != canonicalID {
		return ProjectMergeResult{}, ErrStaleProjectMerge
	}
	for _, projectID := range []string{sourceID, canonicalID} {
		allowed, err := lockCapability(ctx, tx, approval.ActorPrincipalID, projectID, CapabilityProjectAdminister)
		if err != nil {
			return ProjectMergeResult{}, err
		}
		if !allowed {
			return ProjectMergeResult{}, ErrForbidden
		}
	}
	identityCount, grantCount, aliasCount, pendingEnrollmentCount, privateRecordCount, _, err := projectMergeCounts(ctx, tx, approval.ActorPrincipalID, sourceID, canonicalID)
	if err != nil {
		return ProjectMergeResult{}, err
	}
	if identityCount != storedIdentityCount || grantCount != storedGrantCount || aliasCount != storedAliasCount ||
		pendingEnrollmentCount != storedPendingEnrollmentCount || privateRecordCount != storedPrivateRecordCount {
		return ProjectMergeResult{}, ErrStaleProjectMerge
	}
	if _, err := tx.ExecContext(ctx, `UPDATE relay.project_identities SET project_id = $1 WHERE project_id = $2`, canonicalID, sourceID); err != nil {
		return ProjectMergeResult{}, errors.New("project identities could not be merged")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth.capability_grants SET revoked_at = statement_timestamp() WHERE project_id = $1 AND revoked_at IS NULL`, sourceID); err != nil {
		return ProjectMergeResult{}, errors.New("source project membership could not be retired")
	}
	invalidatedEnrollments, err := tx.ExecContext(ctx, `UPDATE auth.pending_enrollments AS enrollment
SET invalidated_at = statement_timestamp()
	WHERE enrollment.redeemed_at IS NULL AND enrollment.invalidated_at IS NULL AND enrollment.expires_at > statement_timestamp()
  AND EXISTS (
      SELECT 1 FROM auth.pending_enrollment_grants AS pending_grant
      WHERE pending_grant.enrollment_id = enrollment.id
        AND pending_grant.scope = 'project' AND pending_grant.project_id = $1
	  )`, sourceID)
	if err != nil {
		return ProjectMergeResult{}, errors.New("source project enrollments could not be fenced")
	}
	if count, err := invalidatedEnrollments.RowsAffected(); err != nil || count != int64(pendingEnrollmentCount) {
		return ProjectMergeResult{}, ErrStaleProjectMerge
	}
	rehomedJobs, err := tx.ExecContext(ctx, `UPDATE jobs.outbox AS job
SET project_id = $1::uuid,
    payload = CASE job.kind
		WHEN 'project.created' THEN jsonb_set(job.payload, '{project_id}', to_jsonb(($1::uuid)::text), true)
        ELSE job.payload
    END,
    state = CASE WHEN job.state = 'running' THEN 'queued' ELSE job.state END,
	attempts = job.attempts - CASE WHEN job.state = 'running' THEN 1 ELSE 0 END,
    lease_holder = NULL, lease_token = NULL, lease_until = NULL,
    lease_generation = job.lease_generation + CASE WHEN job.state = 'running' THEN 1 ELSE 0 END,
    available_at = CASE WHEN job.state = 'running' THEN statement_timestamp() ELSE job.available_at END,
    last_error_code = CASE WHEN job.state = 'running' THEN 'project_merged' ELSE job.last_error_code END,
    updated_at = statement_timestamp()
WHERE job.project_id = $2 AND job.state IN ('queued', 'running')`, canonicalID, sourceID)
	if err != nil {
		return ProjectMergeResult{}, errors.New("source project jobs could not be rehomed")
	}
	if count, err := rehomedJobs.RowsAffected(); err != nil || count != int64(privateRecordCount) {
		return ProjectMergeResult{}, ErrStaleProjectMerge
	}
	if _, err := tx.ExecContext(ctx, `WITH rewritten AS (
    UPDATE relay.project_lookup_aliases SET canonical_project_id = $1 WHERE canonical_project_id = $2
    RETURNING alias_project_id
) UPDATE relay.projects AS project SET merged_into = $1
WHERE project.id IN (SELECT alias_project_id FROM rewritten) AND project.merged_into = $2`, canonicalID, sourceID); err != nil {
		return ProjectMergeResult{}, errors.New("project lookup aliases could not be flattened")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO relay.project_lookup_aliases (alias_project_id, canonical_project_id) VALUES ($1, $2)`, sourceID, canonicalID); err != nil {
		return ProjectMergeResult{}, errors.New("project lookup alias could not be created")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE relay.projects SET merged_into = $1, merged_at = statement_timestamp(), identity_generation = identity_generation + 1, acl_generation = acl_generation + 1, content_generation = content_generation + 1 WHERE id = $2`, canonicalID, sourceID); err != nil {
		return ProjectMergeResult{}, errors.New("source project could not be retired")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE relay.projects SET identity_generation = identity_generation + 1, content_generation = content_generation + 1 WHERE id = $1`, canonicalID); err != nil {
		return ProjectMergeResult{}, errors.New("canonical project generation could not advance")
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: approval.ActorPrincipalID, ProjectID: canonicalID, Action: AuditProjectMerge, Outcome: AuditSucceeded, TargetKind: AuditTargetProjectMerge, TargetID: sourceID}); err != nil {
		return ProjectMergeResult{}, err
	}
	state, err := control.AdvanceChange(ctx)
	if err != nil {
		return ProjectMergeResult{}, err
	}
	result := ProjectMergeResult{AliasProjectID: sourceID, CanonicalProjectID: canonicalID, ChangeSequence: state.ChangeSequence}
	encoded, _ := json.Marshal(result)
	if _, err := tx.ExecContext(ctx, `UPDATE relay.project_merge_previews SET consumed_at = statement_timestamp(), result = $2 WHERE id = $1 AND consumed_at IS NULL`, approval.PreviewID, encoded); err != nil {
		return ProjectMergeResult{}, errors.New("project merge result could not be recorded")
	}
	if err := tx.Commit(); err != nil {
		return ProjectMergeResult{}, errors.New("project merge transaction could not commit")
	}
	return result, nil
}

func lockDirectActiveProject(ctx context.Context, tx *sql.Tx, projectID string) (projectFence, error) {
	var project projectFence
	err := tx.QueryRowContext(ctx, `SELECT id::text, identity_generation, acl_generation, content_generation, merged_into::text
FROM relay.projects WHERE id = $1 FOR UPDATE`, projectID).Scan(&project.ID, &project.IdentityGeneration, &project.ACLGeneration, &project.ContentGeneration, &project.MergedInto)
	if errors.Is(err, sql.ErrNoRows) {
		return projectFence{}, ErrNotFound
	}
	if err != nil {
		return projectFence{}, errors.New("project could not be locked")
	}
	if project.MergedInto.Valid {
		return projectFence{}, ErrMergedProject
	}
	return project, nil
}

func lockProjectPair(ctx context.Context, tx *sql.Tx, first, second string) (map[string]projectFence, error) {
	ids := []string{first, second}
	sort.Strings(ids)
	rows, err := tx.QueryContext(ctx, `SELECT id::text, identity_generation, acl_generation, content_generation, merged_into::text
FROM relay.projects WHERE id = ANY($1::uuid[]) ORDER BY id FOR UPDATE`, ids)
	if err != nil {
		return nil, errors.New("projects could not be locked")
	}
	defer func() { _ = rows.Close() }()
	projects := make(map[string]projectFence, 2)
	for rows.Next() {
		var project projectFence
		if err := rows.Scan(&project.ID, &project.IdentityGeneration, &project.ACLGeneration, &project.ContentGeneration, &project.MergedInto); err != nil {
			return nil, errors.New("project lock state is unavailable")
		}
		projects[project.ID] = project
	}
	if err := rows.Err(); err != nil || len(projects) != 2 {
		return nil, ErrNotFound
	}
	return projects, nil
}

func lockProjectMergePreviews(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, projectMergePreviewLockKey); err != nil {
		return errors.New("project merge previews could not be serialized")
	}
	return nil
}

func pruneProjectMergePreviews(ctx context.Context, tx *sql.Tx) error {
	result, err := tx.ExecContext(ctx, `WITH candidates AS (
    SELECT id FROM relay.project_merge_previews
    WHERE COALESCE(consumed_at, expires_at) < statement_timestamp() - ($2 * interval '1 microsecond')
    ORDER BY COALESCE(consumed_at, expires_at), id
    LIMIT $1 FOR UPDATE SKIP LOCKED
) DELETE FROM relay.project_merge_previews AS preview USING candidates WHERE preview.id = candidates.id`, projectPreviewPruneBatch, projectPreviewRetention.Microseconds())
	if err != nil {
		return errors.New("project merge previews could not be pruned")
	}
	if count, err := result.RowsAffected(); err != nil || count > projectPreviewPruneBatch {
		return errors.New("project merge preview pruning was not bounded")
	}
	return nil
}

func checkProjectPreviewCapacity(ctx context.Context, tx *sql.Tx, actorPrincipalID string) error {
	var actorCount, totalCount int
	err := tx.QueryRowContext(ctx, `SELECT
    count(*) FILTER (WHERE actor_principal_id = $1), count(*)
FROM relay.project_merge_previews
WHERE consumed_at IS NULL AND expires_at > statement_timestamp()`, actorPrincipalID).Scan(&actorCount, &totalCount)
	if err != nil {
		return errors.New("project merge preview capacity cannot be checked")
	}
	if actorCount >= maxLiveProjectPreviewsActor || totalCount >= maxLiveProjectPreviews {
		return ErrProjectPreviewCapacity
	}
	return nil
}

func projectMergeCounts(ctx context.Context, tx *sql.Tx, actorPrincipalID, sourceID, canonicalID string) (int, int, int, int, int, []string, error) {
	var identityCount, canonicalIdentityCount, grantCount, aliasCount, pendingEnrollmentCount, privateRecordCount int
	var memoryScopesPresent, memoryProposalsPresent, secretExceptionsPresent bool
	if err := tx.QueryRowContext(ctx, `SELECT
    to_regclass('brain.scopes') IS NOT NULL,
	to_regclass('brain.memory_proposals') IS NOT NULL,
    to_regclass('brain.secret_exceptions') IS NOT NULL`).Scan(&memoryScopesPresent, &memoryProposalsPresent, &secretExceptionsPresent); err != nil {
		return 0, 0, 0, 0, 0, nil, errors.New("project memory state is unavailable")
	}
	if memoryScopesPresent {
		var hasMemoryLifecycle bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
    SELECT 1 FROM brain.scopes AS scope
    WHERE scope.project_id=$1 AND (
        EXISTS (SELECT 1 FROM brain.memory_items AS item WHERE item.scope_id=scope.id)
        OR EXISTS (SELECT 1 FROM brain.memory_changes AS change WHERE change.scope_id=scope.id)
        OR EXISTS (SELECT 1 FROM brain.memory_tombstones AS tombstone WHERE tombstone.scope_id=scope.id)
    )
)`, sourceID).Scan(&hasMemoryLifecycle); err != nil {
			return 0, 0, 0, 0, 0, nil, errors.New("project memory state is unavailable")
		}
		if hasMemoryLifecycle {
			return 0, 0, 0, 0, 0, nil, ErrProjectMergeBrainState
		}
	}
	if memoryProposalsPresent {
		var hasPendingProposal bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
    SELECT 1 FROM brain.memory_proposals AS proposal
    JOIN brain.scopes AS scope ON scope.id=proposal.scope_id
    WHERE scope.project_id=$1 AND proposal.state='pending'
)`, sourceID).Scan(&hasPendingProposal); err != nil {
			return 0, 0, 0, 0, 0, nil, errors.New("project memory state is unavailable")
		}
		if hasPendingProposal {
			return 0, 0, 0, 0, 0, nil, ErrProjectMergeBrainState
		}
	}
	if secretExceptionsPresent {
		var hasSecretExceptionHistory bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM brain.secret_exceptions WHERE project_id=$1)`, sourceID).Scan(&hasSecretExceptionHistory); err != nil {
			return 0, 0, 0, 0, 0, nil, errors.New("project memory state is unavailable")
		}
		if hasSecretExceptionHistory {
			return 0, 0, 0, 0, 0, nil, ErrProjectMergeBrainState
		}
	}
	var attachmentLifecyclePresent bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('attachment.uploads') IS NOT NULL`).Scan(&attachmentLifecyclePresent); err != nil {
		return 0, 0, 0, 0, 0, nil, errors.New("project attachment state is unavailable")
	}
	if attachmentLifecyclePresent {
		var hasAttachmentRecords bool
		if err := tx.QueryRowContext(ctx, `SELECT attachment.project_has_records($1,$2)`, actorPrincipalID, sourceID).Scan(&hasAttachmentRecords); err != nil {
			return 0, 0, 0, 0, 0, nil, errors.New("project attachment state is unavailable")
		}
		if hasAttachmentRecords {
			return 0, 0, 0, 0, 0, nil, ErrProjectMergeAttachmentState
		}
		var recipientFenceAvailable bool
		if err := tx.QueryRowContext(ctx, `SELECT to_regprocedure('attachment.project_has_recipient_records(uuid,uuid)') IS NOT NULL`).Scan(&recipientFenceAvailable); err != nil {
			return 0, 0, 0, 0, 0, nil, errors.New("project attachment recipient state is unavailable")
		}
		if recipientFenceAvailable {
			if err := tx.QueryRowContext(ctx, `SELECT attachment.project_has_recipient_records($1,$2)`, actorPrincipalID, sourceID).Scan(&hasAttachmentRecords); err != nil {
				return 0, 0, 0, 0, 0, nil, errors.New("project attachment recipient state is unavailable")
			}
			if hasAttachmentRecords {
				return 0, 0, 0, 0, 0, nil, ErrProjectMergeAttachmentState
			}
		}
	}
	if err := tx.QueryRowContext(ctx, `SELECT
    count(*) FILTER (WHERE project_id = $1), count(*) FILTER (WHERE project_id = $2)
FROM relay.project_identities WHERE project_id IN ($1, $2)`, sourceID, canonicalID).Scan(&identityCount, &canonicalIdentityCount); err != nil {
		return 0, 0, 0, 0, 0, nil, errors.New("project identity count is unavailable")
	}
	if err := tx.QueryRowContext(ctx, `WITH affected_enrollments AS MATERIALIZED (
    SELECT enrollment.id FROM auth.pending_enrollments AS enrollment
    WHERE enrollment.redeemed_at IS NULL AND enrollment.invalidated_at IS NULL
      AND enrollment.expires_at > statement_timestamp()
      AND EXISTS (
          SELECT 1 FROM auth.pending_enrollment_grants AS source_grant
          WHERE source_grant.enrollment_id = enrollment.id
            AND source_grant.scope = 'project' AND source_grant.project_id = $1
      )
)
SELECT
    (SELECT count(*) FROM auth.capability_grants WHERE project_id = $1 AND revoked_at IS NULL)
  + (SELECT count(*) FROM auth.pending_enrollment_grants
     WHERE enrollment_id IN (SELECT id FROM affected_enrollments)),
    (SELECT count(*) FROM affected_enrollments)`, sourceID).Scan(&grantCount, &pendingEnrollmentCount); err != nil {
		return 0, 0, 0, 0, 0, nil, errors.New("project grant count is unavailable")
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM relay.project_lookup_aliases WHERE canonical_project_id = $1`, sourceID).Scan(&aliasCount); err != nil {
		return 0, 0, 0, 0, 0, nil, errors.New("project alias count is unavailable")
	}
	var unsupportedJobCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE kind <> 'project.created')
FROM jobs.outbox WHERE project_id = $1 AND state IN ('queued', 'running')`, sourceID).Scan(&privateRecordCount, &unsupportedJobCount); err != nil {
		return 0, 0, 0, 0, 0, nil, errors.New("project job count is unavailable")
	}
	if unsupportedJobCount > 0 {
		return 0, 0, 0, 0, 0, nil, errors.New("project job kind has no merge behavior")
	}
	if identityCount < 1 || identityCount+canonicalIdentityCount > maxProjectIdentities || grantCount > maxProjectMergeGrants || aliasCount >= maxProjectMergeAliases || pendingEnrollmentCount > maxPendingEnrollments || privateRecordCount > maxProjectMergePrivateRecords {
		return 0, 0, 0, 0, 0, nil, ErrProjectMergeTooLarge
	}
	rows, err := tx.QueryContext(ctx, `WITH canonical_capabilities AS (
    SELECT DISTINCT principal_id, capability FROM auth.capability_grants
    WHERE revoked_at IS NULL
      AND capability = ANY (ARRAY['project.read','project.write','conversation.send','conversation.receive','conversation.administer','memory.search','memory.read','memory.propose','memory.write','memory.administer','memory.purge','attachment.upload','attachment.download','attachment.delete']::text[])
      AND (scope = 'all_projects' OR (scope = 'project' AND project_id = $2))
), source_capabilities AS (
    SELECT DISTINCT principal_id, capability FROM auth.capability_grants
    WHERE revoked_at IS NULL
      AND capability = ANY (ARRAY['project.read','project.write','conversation.send','conversation.receive','conversation.administer','memory.search','memory.read','memory.propose','memory.write','memory.administer','memory.purge','attachment.upload','attachment.download','attachment.delete']::text[])
      AND (scope = 'all_projects' OR (scope = 'project' AND project_id = $1))
), expanded AS (
    SELECT principal_id, capability FROM canonical_capabilities
    EXCEPT
    SELECT principal_id, capability FROM source_capabilities
)
SELECT DISTINCT principal_id::text FROM expanded
ORDER BY principal_id::text LIMIT $3`, sourceID, canonicalID, maxNewlyAuthorizedPrincipals+1)
	if err != nil {
		return 0, 0, 0, 0, 0, nil, errors.New("project authorization preview is unavailable")
	}
	defer func() { _ = rows.Close() }()
	principals := make([]string, 0)
	for rows.Next() {
		var principalID string
		if err := rows.Scan(&principalID); err != nil {
			return 0, 0, 0, 0, 0, nil, errors.New("project authorization preview is malformed")
		}
		principals = append(principals, principalID)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, 0, 0, 0, nil, errors.New("project authorization preview is unavailable")
	}
	if len(principals) > maxNewlyAuthorizedPrincipals {
		return 0, 0, 0, 0, 0, nil, ErrProjectMergeTooLarge
	}
	return identityCount, grantCount, aliasCount, pendingEnrollmentCount, privateRecordCount, principals, nil
}

func currentInstallationState(ctx context.Context, tx *sql.Tx) (InstallationState, error) {
	var state InstallationState
	if err := tx.QueryRowContext(ctx, `SELECT installation_id::text, timeline_id::text, change_sequence FROM jobs.server_state WHERE singleton`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence); err != nil {
		return InstallationState{}, errors.New("PostgreSQL installation metadata is unavailable")
	}
	return state, nil
}

func lockPendingEnrollmentGrantTargets(ctx context.Context, tx *sql.Tx, enrollmentID string) ([]string, bool, error) {
	if err := lockGrantMutations(ctx, tx); err != nil {
		return nil, false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT project_id::text
FROM auth.pending_enrollment_grants
WHERE enrollment_id = $1 AND scope = 'project'
ORDER BY project_id`, enrollmentID)
	if err != nil {
		return nil, false, errors.New("enrollment project grants cannot be locked")
	}
	var projectIDs []string
	for rows.Next() {
		var projectID string
		if err := rows.Scan(&projectID); err != nil {
			_ = rows.Close()
			return nil, false, errors.New("enrollment project grant is malformed")
		}
		projectIDs = append(projectIDs, projectID)
	}
	if err := rows.Close(); err != nil {
		return nil, false, errors.New("enrollment project grants cannot be read")
	}
	if len(projectIDs) > maxEnrollmentProjects {
		return nil, false, ErrProjectMergeTooLarge
	}
	for _, projectID := range projectIDs {
		if _, err := lockDirectActiveProject(ctx, tx, projectID); err != nil {
			return nil, false, err
		}
	}
	var allProjects bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.pending_enrollment_grants WHERE enrollment_id = $1 AND scope = 'all_projects')`, enrollmentID).Scan(&allProjects); err != nil {
		return nil, false, errors.New("enrollment dynamic grants cannot be read")
	}
	if allProjects {
		if err := lockGlobalProjectACL(ctx, tx); err != nil {
			return nil, false, err
		}
	}
	return projectIDs, allProjects, nil
}

// advanceProjectContentGeneration is the shared M-4 mutation fence for later
// project-scoped stores. Callers must perform their content write in the same
// transaction in the future; M-4 uses it to prove stale-preview behavior.
func (d *Database) advanceProjectContentGeneration(ctx context.Context, actorPrincipalID, projectID string) (int64, error) {
	if !validOpaqueID(actorPrincipalID) || !validOpaqueID(projectID) {
		return 0, errors.New("invalid project content mutation")
	}
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return 0, mutationStartError(err, "project content transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	project, err := lockDirectActiveProject(ctx, tx, projectID)
	if err != nil {
		return 0, err
	}
	allowed, err := lockCapability(ctx, tx, actorPrincipalID, project.ID, CapabilityProjectWrite)
	if err != nil {
		return 0, err
	}
	if !allowed {
		return 0, ErrForbidden
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, `UPDATE relay.projects SET content_generation = content_generation + 1 WHERE id = $1 RETURNING content_generation`, project.ID).Scan(&generation); err != nil {
		return 0, errors.New("project content generation could not advance")
	}
	if _, err := (&ControlTx{tx: tx}).AdvanceChange(ctx); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, errors.New("project content transaction could not commit")
	}
	return generation, nil
}
