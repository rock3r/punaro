package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Content-free sentinel errors allow callers to branch without exposing stored data.
var (
	ErrForbidden           = errors.New("operation is not authorized")
	ErrIdempotencyConflict = errors.New("idempotency key conflicts with an earlier operation")
	ErrQueueFull           = errors.New("job queue is full")
	ErrStaleLease          = errors.New("job lease is stale")
	ErrNotFound            = errors.New("control-plane record was not found")
)

const (
	maxJobDelay               = 24 * time.Hour
	projectJobMutationLockKey = int64(0x50756e61726f4a4f)
)

// Grant mutations are rare administrative operations. One transaction-scoped
// lock gives every actor/target pair the same lock order and prevents reciprocal
// revoke or delegate operations from deadlocking.
const grantMutationLockKey int64 = 0x50756e61726f4752

func jobClaimCapability(kind string) (Capability, bool) {
	if kind == "project.created" {
		return CapabilityProjectAdminister, true
	}
	return "", false
}

// PrincipalKind is a closed principal classification. M-3 adds enrollment behavior.
type PrincipalKind string

// Supported principal kinds.
const (
	PrincipalKindOwner         PrincipalKind = "owner"
	PrincipalKindDevice        PrincipalKind = "device"
	PrincipalKindService       PrincipalKind = "service"
	PrincipalKindLegacyMachine PrincipalKind = "legacy_machine"
)

// Principal is an opaque control-plane identity.
type Principal struct {
	ID          string
	Kind        PrincipalKind
	DisplayName string
}

// ProjectCreate is the one concrete M-2 mutation used to prove atomic composition.
type ProjectCreate struct {
	PrincipalID    string
	IdempotencyKey string
	DisplayName    string
}

// ProjectResult is the immutable result returned to exact retries.
type ProjectResult struct {
	ProjectID      string `json:"project_id"`
	ChangeSequence int64  `json:"change_sequence"`
}

// ControlTx exposes only bounded cross-domain transaction primitives.
type ControlTx struct{ tx *sql.Tx }

// JobLease is the complete fencing authority required for publication.
type JobLease struct {
	ID         string
	Token      string
	Generation int64
}

// LeasedJob is one bounded claimed transactional outbox entry.
type LeasedJob struct {
	ID          string
	ProjectID   string
	Kind        string
	Payload     json.RawMessage
	Attempts    int
	MaxAttempts int
	Holder      string
	Token       string
	Generation  int64
	LeaseUntil  time.Time
}

// Lease returns the exact opaque fence required to complete or retry this claim.
func (j LeasedJob) Lease() JobLease {
	return JobLease{ID: j.ID, Token: j.Token, Generation: j.Generation}
}

// JobRetry releases one valid lease for a bounded retry or terminal exhaustion.
type JobRetry struct {
	Lease     JobLease
	ErrorCode string
	Delay     time.Duration
}

// CreatePrincipal adds an opaque principal for later bootstrap/enrollment composition.
func (d *Database) CreatePrincipal(ctx context.Context, kind PrincipalKind, displayName string) (Principal, error) {
	if !validPrincipalKind(kind) || !validDisplayName(displayName) {
		return Principal{}, errors.New("invalid principal")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return Principal{}, errors.New("principal transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	var principal Principal
	err = tx.QueryRowContext(ctx, `INSERT INTO auth.principals (kind, display_name) VALUES ($1, $2) RETURNING id::text, kind, display_name`, kind, displayName).Scan(&principal.ID, &principal.Kind, &principal.DisplayName)
	if err != nil {
		return Principal{}, errors.New("principal could not be created")
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{Action: AuditPrincipalCreate, Outcome: AuditSucceeded, TargetKind: AuditTargetPrincipal, TargetID: principal.ID}); err != nil {
		return Principal{}, err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return Principal{}, err
	}
	if err := tx.Commit(); err != nil {
		return Principal{}, errors.New("principal transaction could not commit")
	}
	return principal, nil
}

// GrantCapability adds or returns one active explicit capability grant after
// locking the actor's authority for the target scope.
func (d *Database) GrantCapability(ctx context.Context, actorPrincipalID string, grant Grant) (string, error) {
	if !validOpaqueID(actorPrincipalID) || grant.Validate() != nil {
		return "", errors.New("invalid grant")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return "", errors.New("grant transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockGrantMutations(ctx, tx); err != nil {
		return "", err
	}
	switch grant.Scope {
	case ScopeProject:
		if _, err := lockDirectActiveProject(ctx, tx, grant.ProjectID); err != nil {
			return "", err
		}
	case ScopeAllProjects:
		if err := lockGlobalProjectACL(ctx, tx); err != nil {
			return "", err
		}
	}
	allowed, err := lockGrantAdministration(ctx, tx, actorPrincipalID, grant.Scope, grant.ProjectID)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", ErrForbidden
	}
	project := nullableID(grant.ProjectID)
	var grantID string
	inserted := true
	err = tx.QueryRowContext(ctx, `INSERT INTO auth.capability_grants (principal_id, scope, project_id, capability)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING
RETURNING id::text`, grant.PrincipalID, grant.Scope, project, grant.Capability).Scan(&grantID)
	if errors.Is(err, sql.ErrNoRows) {
		inserted = false
		err = tx.QueryRowContext(ctx, `SELECT id::text FROM auth.capability_grants
WHERE principal_id = $1 AND scope = $2 AND project_id IS NOT DISTINCT FROM $3::uuid AND capability = $4 AND revoked_at IS NULL`, grant.PrincipalID, grant.Scope, project, grant.Capability).Scan(&grantID)
	}
	if err != nil {
		return "", errors.New("capability grant could not be created")
	}
	if inserted {
		if err := advanceGrantGenerations(ctx, tx, grant.Scope, grant.ProjectID); err != nil {
			return "", err
		}
		control := &ControlTx{tx: tx}
		if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: actorPrincipalID, ProjectID: grant.ProjectID, Action: AuditGrantCreate, Outcome: AuditSucceeded, TargetKind: AuditTargetGrant, TargetID: grantID}); err != nil {
			return "", err
		}
		if _, err := control.AdvanceChange(ctx); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", errors.New("grant transaction could not commit")
	}
	return grantID, nil
}

// RevokeGrant revokes one active grant after locking the actor's authority.
func (d *Database) RevokeGrant(ctx context.Context, actorPrincipalID, grantID string) error {
	if !validOpaqueID(actorPrincipalID) || !validOpaqueID(grantID) {
		return errors.New("invalid grant")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("grant transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockGrantMutations(ctx, tx); err != nil {
		return err
	}
	var projectID sql.NullString
	var scope GrantScope
	err = tx.QueryRowContext(ctx, `SELECT scope, project_id::text
FROM auth.capability_grants WHERE id = $1 AND revoked_at IS NULL`, grantID).Scan(&scope, &projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return errors.New("capability grant could not be locked")
	}
	switch scope {
	case ScopeProject:
		if _, err := lockDirectActiveProject(ctx, tx, projectID.String); err != nil {
			return err
		}
	case ScopeAllProjects:
		if err := lockGlobalProjectACL(ctx, tx); err != nil {
			return err
		}
	}
	allowed, err := lockGrantAdministration(ctx, tx, actorPrincipalID, scope, projectID.String)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrForbidden
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth.capability_grants SET revoked_at = statement_timestamp() WHERE id = $1 AND revoked_at IS NULL`, grantID)
	if err != nil {
		return errors.New("capability grant could not be revoked")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrNotFound
	}
	if err := advanceGrantGenerations(ctx, tx, scope, projectID.String); err != nil {
		return err
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: actorPrincipalID, ProjectID: projectID.String, Action: AuditGrantDelete, Outcome: AuditSucceeded, TargetKind: AuditTargetGrant, TargetID: grantID}); err != nil {
		return err
	}
	if _, err := control.AdvanceChange(ctx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("grant transaction could not commit")
	}
	return nil
}

func lockGrantAdministration(ctx context.Context, tx *sql.Tx, actorPrincipalID string, scope GrantScope, projectID string) (bool, error) {
	switch scope {
	case ScopeInstallation:
		return lockAllProjectsAdministration(ctx, tx, actorPrincipalID)
	case ScopeProject:
		return lockCapability(ctx, tx, actorPrincipalID, projectID, CapabilityProjectAdminister)
	case ScopeAllProjects:
		return lockAllProjectsAdministration(ctx, tx, actorPrincipalID)
	default:
		return false, errors.New("invalid grant administration scope")
	}
}

func lockGrantMutations(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, grantMutationLockKey); err != nil {
		return errors.New("grant mutation could not be serialized")
	}
	return nil
}

func lockGlobalProjectACL(ctx context.Context, tx *sql.Tx) error {
	var singleton bool
	if err := tx.QueryRowContext(ctx, `SELECT singleton FROM auth.project_acl_state WHERE singleton FOR UPDATE`).Scan(&singleton); err != nil || !singleton {
		return errors.New("global project authorization could not be locked")
	}
	return nil
}

func advanceGrantGenerations(ctx context.Context, tx *sql.Tx, scope GrantScope, projectID string) error {
	switch scope {
	case ScopeProject:
		result, err := tx.ExecContext(ctx, `UPDATE relay.projects SET acl_generation = acl_generation + 1, content_generation = content_generation + 1 WHERE id = $1 AND merged_into IS NULL`, projectID)
		if err != nil {
			return errors.New("project authorization generation could not advance")
		}
		if count, err := result.RowsAffected(); err != nil || count != 1 {
			return ErrMergedProject
		}
	case ScopeAllProjects:
		result, err := tx.ExecContext(ctx, `UPDATE auth.project_acl_state SET global_generation = global_generation + 1 WHERE singleton`)
		if err != nil {
			return errors.New("global project authorization generation could not advance")
		}
		if count, err := result.RowsAffected(); err != nil || count != 1 {
			return errors.New("global project authorization generation is unavailable")
		}
	case ScopeInstallation:
		return nil
	default:
		return errors.New("invalid grant generation scope")
	}
	return nil
}

func lockAllProjectsAdministration(ctx context.Context, tx *sql.Tx, actorPrincipalID string) (bool, error) {
	var grantID string
	err := tx.QueryRowContext(ctx, `SELECT capability_grant.id::text
FROM auth.principals AS principal
JOIN auth.capability_grants AS capability_grant ON capability_grant.principal_id = principal.id
WHERE principal.id = $1 AND principal.disabled_at IS NULL AND capability_grant.revoked_at IS NULL
  AND capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL
  AND capability_grant.capability = 'project.administer'
ORDER BY capability_grant.id LIMIT 1 FOR SHARE OF principal, capability_grant`, actorPrincipalID).Scan(&grantID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("grant administration could not be locked")
	}
	return true, nil
}

// HasCapability checks one explicit installation/project/all-project grant.
func (d *Database) HasCapability(ctx context.Context, principalID, projectID string, capability Capability) (bool, error) {
	if !validOpaqueID(principalID) {
		return false, errors.New("invalid authorization query")
	}
	allowedScopes, known := capabilityScopes[capability]
	if !known {
		return false, errors.New("invalid authorization query")
	}
	switch {
	case projectID == "":
		if allowedScopes&allowInstallation == 0 {
			return false, errors.New("invalid authorization query")
		}
	case !validOpaqueID(projectID) || allowedScopes&(allowProject|allowAllProjects) == 0:
		return false, errors.New("invalid authorization query")
	default:
		canonicalID, err := resolveCanonicalActiveProject(ctx, d.db, projectID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return false, nil
			}
			return false, err
		}
		projectID = canonicalID
	}
	return hasCapability(ctx, d.db, principalID, projectID, capability)
}

const capabilityMatchSQL = `
FROM auth.principals AS principal
JOIN auth.capability_grants AS capability_grant ON capability_grant.principal_id = principal.id
WHERE principal.id = $1 AND principal.disabled_at IS NULL AND capability_grant.revoked_at IS NULL
  AND capability_grant.capability = $3
  AND (
      ($2::uuid IS NULL AND capability_grant.scope = 'installation' AND capability_grant.project_id IS NULL)
      OR
      ($2::uuid IS NOT NULL
	       AND EXISTS (SELECT 1 FROM relay.projects WHERE id = $2 AND merged_into IS NULL)
       AND ((capability_grant.scope = 'project' AND capability_grant.project_id = $2) OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL)))
  )`

func hasCapability(ctx context.Context, q queryer, principalID, projectID string, capability Capability) (bool, error) {
	var allowed bool
	project := nullableID(projectID)
	err := q.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 `+capabilityMatchSQL+`)`, principalID, project, capability).Scan(&allowed)
	if err != nil {
		return false, errors.New("authorization could not be evaluated")
	}
	return allowed, nil
}

func resolveCanonicalActiveProject(ctx context.Context, q queryer, projectID string) (string, error) {
	var canonicalID string
	err := q.QueryRowContext(ctx, `SELECT active.id::text
FROM relay.projects AS requested
LEFT JOIN relay.project_lookup_aliases AS alias ON alias.alias_project_id = requested.id
JOIN relay.projects AS active ON active.id = COALESCE(alias.canonical_project_id, requested.id)
WHERE requested.id = $1 AND active.merged_into IS NULL
  AND ((requested.merged_into IS NULL AND alias.alias_project_id IS NULL)
       OR (requested.merged_into = alias.canonical_project_id))`, projectID).Scan(&canonicalID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", errors.New("project lookup alias could not be resolved")
	}
	return canonicalID, nil
}

func lockCapability(ctx context.Context, tx *sql.Tx, principalID, projectID string, capability Capability) (bool, error) {
	var grantID string
	err := tx.QueryRowContext(ctx, `SELECT capability_grant.id::text `+capabilityMatchSQL+`
ORDER BY capability_grant.id LIMIT 1 FOR SHARE OF principal, capability_grant`, principalID, nullableID(projectID), capability).Scan(&grantID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("authorization could not be locked")
	}
	return true, nil
}

// CreateProject atomically composes authorization, idempotency, grants, audit,
// transactional work, and the global change sequence.
func (d *Database) CreateProject(ctx context.Context, create ProjectCreate) (ProjectResult, error) {
	if !validOpaqueID(create.PrincipalID) || !validOpaqueID(create.IdempotencyKey) || !validDisplayName(create.DisplayName) {
		return ProjectResult{}, errors.New("invalid project create request")
	}
	body, err := json.Marshal(struct {
		DisplayName string `json:"display_name"`
	}{DisplayName: create.DisplayName})
	if err != nil {
		return ProjectResult{}, errors.New("project create request cannot be encoded")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return ProjectResult{}, errors.New("project transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: create.PrincipalID, Operation: "project.create", Key: create.IdempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
		allowed, err := lockCapability(ctx, tx, create.PrincipalID, "", CapabilityProjectCreate)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		if !allowed {
			return IdempotencyOutcome{}, ErrForbidden
		}
		var projectID string
		if err := tx.QueryRowContext(ctx, `INSERT INTO relay.projects (display_name, created_by) VALUES ($1, $2) RETURNING id::text`, create.DisplayName, create.PrincipalID).Scan(&projectID); err != nil {
			return IdempotencyOutcome{}, errors.New("project could not be created")
		}
		for _, capability := range []Capability{CapabilityProjectDiscover, CapabilityProjectRead, CapabilityProjectWrite} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO auth.capability_grants (principal_id, scope, project_id, capability) VALUES ($1, 'project', $2, $3)`, create.PrincipalID, projectID, capability); err != nil {
				return IdempotencyOutcome{}, errors.New("project membership could not be created")
			}
		}
		if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: create.PrincipalID, ProjectID: projectID, Action: AuditProjectCreate, Outcome: AuditSucceeded, TargetKind: AuditTargetProject, TargetID: projectID}); err != nil {
			return IdempotencyOutcome{}, err
		}
		payload, _ := json.Marshal(struct {
			ProjectID string `json:"project_id"`
		}{ProjectID: projectID})
		if _, err := control.EnqueueJob(ctx, EnqueueJob{ActorPrincipalID: create.PrincipalID, Kind: "project.created", ProjectID: projectID, Payload: payload, MaxAttempts: 4}); err != nil {
			return IdempotencyOutcome{}, err
		}
		state, err := control.AdvanceChange(ctx)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		result := ProjectResult{ProjectID: projectID, ChangeSequence: state.ChangeSequence}
		encoded, err := json.Marshal(result)
		if err != nil {
			return IdempotencyOutcome{}, errors.New("project result cannot be encoded")
		}
		return IdempotencyOutcome{Status: OutcomeSucceeded, ResourceID: projectID, Result: encoded}, nil
	})
	if err != nil {
		return ProjectResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProjectResult{}, errors.New("project transaction could not commit")
	}
	var result ProjectResult
	if outcome.Status != OutcomeSucceeded || json.Unmarshal(outcome.Result, &result) != nil || !validOpaqueID(result.ProjectID) || result.ChangeSequence < 1 {
		return ProjectResult{}, errors.New("project result is unavailable")
	}
	return result, nil
}

func (d *Database) executeIdempotent(ctx context.Context, request IdempotencyRequest, mutation func(*ControlTx) (IdempotencyOutcome, error)) (IdempotencyOutcome, error) {
	if err := request.Validate(); err != nil {
		return IdempotencyOutcome{}, err
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return IdempotencyOutcome{}, errors.New("idempotency transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, request, mutation)
	if err != nil {
		return IdempotencyOutcome{}, err
	}
	if err := tx.Commit(); err != nil {
		return IdempotencyOutcome{}, errors.New("idempotency transaction could not commit")
	}
	return outcome, nil
}

func executeIdempotentTx(ctx context.Context, tx *sql.Tx, request IdempotencyRequest, mutation func(*ControlTx) (IdempotencyOutcome, error)) (IdempotencyOutcome, error) {
	if err := request.Validate(); err != nil || mutation == nil {
		return IdempotencyOutcome{}, errors.New("invalid idempotency operation")
	}
	digest := requestDigest(request.Body)
	result, err := tx.ExecContext(ctx, `INSERT INTO relay.idempotency_records (key, principal_id, operation, request_hash, status)
VALUES ($1, $2, $3, $4, 'pending') ON CONFLICT DO NOTHING`, request.Key, request.PrincipalID, request.Operation, digest[:])
	if err != nil {
		return IdempotencyOutcome{}, errors.New("idempotency record could not be claimed")
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return IdempotencyOutcome{}, errors.New("idempotency record state is unavailable")
	}
	var storedPrincipal, storedOperation, storedStatus string
	var storedHash []byte
	var storedResource sql.NullString
	var storedResult []byte
	err = tx.QueryRowContext(ctx, `SELECT principal_id::text, operation, request_hash, status, resource_id::text, result
FROM relay.idempotency_records WHERE key = $1 FOR UPDATE`, request.Key).Scan(&storedPrincipal, &storedOperation, &storedHash, &storedStatus, &storedResource, &storedResult)
	if err != nil {
		return IdempotencyOutcome{}, errors.New("idempotency record state is unavailable")
	}
	if storedPrincipal != request.PrincipalID || storedOperation != request.Operation || !bytes.Equal(storedHash, digest[:]) {
		return IdempotencyOutcome{}, ErrIdempotencyConflict
	}
	if inserted == 0 {
		outcome := IdempotencyOutcome{Status: OutcomeStatus(storedStatus), ResourceID: storedResource.String, Result: append(json.RawMessage(nil), storedResult...)}
		if storedStatus == "pending" || outcome.Validate() != nil {
			return IdempotencyOutcome{}, errors.New("idempotency record is incomplete")
		}
		return outcome, nil
	}
	outcome, err := mutation(&ControlTx{tx: tx})
	if err != nil {
		return IdempotencyOutcome{}, err
	}
	if err := outcome.Validate(); err != nil {
		return IdempotencyOutcome{}, err
	}
	update, err := tx.ExecContext(ctx, `UPDATE relay.idempotency_records
SET status = $2, resource_id = $3, result = $4, completed_at = statement_timestamp()
WHERE key = $1 AND status = 'pending'`, request.Key, outcome.Status, nullableID(outcome.ResourceID), []byte(outcome.Result))
	if err != nil {
		return IdempotencyOutcome{}, errors.New("idempotency outcome could not be recorded")
	}
	if count, err := update.RowsAffected(); err != nil || count != 1 {
		return IdempotencyOutcome{}, errors.New("idempotency record changed unexpectedly")
	}
	outcome.Result = append(json.RawMessage(nil), outcome.Result...)
	return outcome, nil
}

// AppendAudit inserts one closed, content-free event in the surrounding transaction.
func (t *ControlTx) AppendAudit(ctx context.Context, event AuditEvent) error {
	if t == nil || t.tx == nil || event.Validate() != nil {
		return errors.New("invalid audit event")
	}
	_, err := t.tx.ExecContext(ctx, `INSERT INTO audit.events (principal_id, project_id, action, outcome, target_kind, target_id)
VALUES ($1, $2, $3, $4, $5, $6)`, nullableID(event.PrincipalID), nullableID(event.ProjectID), event.Action, event.Outcome, event.TargetKind, nullableID(event.TargetID))
	if err != nil {
		return errors.New("audit event could not be recorded")
	}
	return nil
}

// EnqueueJob adds one capacity-checked work item to the surrounding transaction.
func (t *ControlTx) EnqueueJob(ctx context.Context, job EnqueueJob) (string, error) {
	if t == nil || t.tx == nil || job.Validate() != nil {
		return "", errors.New("invalid job")
	}
	if err := lockProjectJobMutations(ctx, t.tx, false); err != nil {
		return "", err
	}
	if _, err := lockDirectActiveProject(ctx, t.tx, job.ProjectID); err != nil {
		return "", err
	}
	var id string
	err := t.tx.QueryRowContext(ctx, `INSERT INTO jobs.outbox (project_id, kind, payload, max_attempts, available_at)
VALUES ($1, $2, $3, $4, statement_timestamp() + ($5 * interval '1 microsecond')) RETURNING id::text`, nullableID(job.ProjectID), job.Kind, []byte(job.Payload), job.MaxAttempts, job.Delay.Microseconds()).Scan(&id)
	if isSQLState(err, "54000") {
		return "", ErrQueueFull
	}
	if err != nil {
		return "", errors.New("job could not be enqueued")
	}
	if err := t.AppendAudit(ctx, AuditEvent{PrincipalID: job.ActorPrincipalID, ProjectID: job.ProjectID, Action: AuditJobEnqueue, Outcome: AuditSucceeded, TargetKind: AuditTargetJob, TargetID: id}); err != nil {
		return "", err
	}
	advanced, err := t.tx.ExecContext(ctx, `UPDATE relay.projects SET content_generation = content_generation + 1 WHERE id = $1 AND merged_into IS NULL`, job.ProjectID)
	if err != nil {
		return "", errors.New("project content generation could not advance")
	}
	if count, err := advanced.RowsAffected(); err != nil || count != 1 {
		return "", ErrMergedProject
	}
	return id, nil
}

// AdvanceChange increments global change metadata in the surrounding transaction.
func (t *ControlTx) AdvanceChange(ctx context.Context) (InstallationState, error) {
	if t == nil || t.tx == nil {
		return InstallationState{}, errors.New("invalid change transaction")
	}
	var state InstallationState
	err := t.tx.QueryRowContext(ctx, `SELECT installation_id::text, timeline_id::text, change_sequence FROM jobs.advance_change_sequence()`).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence)
	if err != nil {
		return InstallationState{}, errors.New("PostgreSQL change sequence could not be advanced")
	}
	return state, nil
}

// ClaimJobs claims disjoint ready or expired jobs with database-time leases.
func (d *Database) ClaimJobs(ctx context.Context, claim ClaimJobs) ([]LeasedJob, error) {
	if err := claim.Validate(); err != nil {
		return nil, err
	}
	capability, knownKind := jobClaimCapability(claim.Kind)
	if !knownKind {
		return []LeasedJob{}, nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.New("job claim transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockProjectJobMutations(ctx, tx, false); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `WITH exhausted AS (
	SELECT job.id, job.project_id, job.lease_holder FROM jobs.outbox AS job
    WHERE job.kind = $1 AND job.state = 'running' AND job.lease_until <= statement_timestamp() AND job.attempts >= job.max_attempts
    ORDER BY job.lease_until, job.created_at, job.id
    FOR UPDATE SKIP LOCKED
    LIMIT $2
), failed AS (
    UPDATE jobs.outbox AS job
    SET state = 'failed', last_error_code = 'attempts_exhausted', lease_holder = NULL, lease_token = NULL, lease_until = NULL, completed_at = statement_timestamp()
    FROM exhausted WHERE job.id = exhausted.id
	RETURNING job.id, exhausted.project_id, exhausted.lease_holder
)
INSERT INTO audit.events (principal_id, project_id, action, outcome, target_kind, target_id)
SELECT lease_holder, project_id, 'job.fail', 'succeeded', 'job', id FROM failed`, claim.Kind, claim.Limit); err != nil {
		return nil, errors.New("expired jobs could not be fenced")
	}
	rows, err := tx.QueryContext(ctx, `WITH pre_candidates AS MATERIALIZED (
	SELECT job.id, job.project_id, job.available_at, job.lease_until, job.created_at
	FROM jobs.outbox AS job
	WHERE job.kind = $1 AND job.attempts < job.max_attempts AND job.project_id IS NOT NULL
	  AND ((job.state = 'queued' AND job.available_at <= statement_timestamp()) OR (job.state = 'running' AND job.lease_until <= statement_timestamp()))
	  AND EXISTS (
		  SELECT 1 FROM auth.principals AS principal
		  JOIN auth.capability_grants AS capability_grant ON capability_grant.principal_id = principal.id
		  WHERE principal.id = $3 AND principal.disabled_at IS NULL AND capability_grant.revoked_at IS NULL
		    AND capability_grant.capability = $4
		    AND ((capability_grant.scope = 'project' AND capability_grant.project_id = job.project_id)
		         OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
	  )
	ORDER BY COALESCE(job.lease_until, job.available_at), job.created_at, job.id
	FOR UPDATE OF job SKIP LOCKED
	LIMIT $2
), authorized_grants AS MATERIALIZED (
    SELECT capability_grant.scope, capability_grant.project_id
    FROM auth.principals AS principal
    JOIN auth.capability_grants AS capability_grant ON capability_grant.principal_id = principal.id
    WHERE principal.id = $3 AND principal.disabled_at IS NULL AND capability_grant.revoked_at IS NULL
      AND capability_grant.capability = $4
      AND capability_grant.scope IN ('project', 'all_projects')
	  AND (capability_grant.scope = 'all_projects'
	       OR capability_grant.project_id IN (SELECT project_id FROM pre_candidates))
    FOR SHARE OF principal, capability_grant
), candidates AS (
	SELECT job.id FROM jobs.outbox AS job
	JOIN pre_candidates AS candidate ON candidate.id = job.id
    WHERE job.kind = $1 AND job.attempts < job.max_attempts
      AND ((job.state = 'queued' AND job.available_at <= statement_timestamp()) OR (job.state = 'running' AND job.lease_until <= statement_timestamp()))
      AND EXISTS (
          SELECT 1 FROM authorized_grants AS capability_grant
          WHERE job.project_id IS NOT NULL
	            AND ((capability_grant.scope = 'project' AND capability_grant.project_id = job.project_id)
	                 OR (capability_grant.scope = 'all_projects' AND capability_grant.project_id IS NULL))
      )
	ORDER BY COALESCE(candidate.lease_until, candidate.available_at), candidate.created_at, candidate.id
    LIMIT $2
)
UPDATE jobs.outbox AS job
SET state = 'running', attempts = job.attempts + 1, lease_holder = $3,
    lease_token = gen_random_uuid(), lease_generation = job.lease_generation + 1,
    lease_until = statement_timestamp() + ($5 * interval '1 microsecond')
FROM candidates WHERE job.id = candidates.id
RETURNING job.id::text, COALESCE(job.project_id::text, ''), job.kind, job.payload,
          job.attempts, job.max_attempts, job.lease_holder::text, job.lease_token::text,
          job.lease_generation, job.lease_until`, claim.Kind, claim.Limit, claim.Holder, capability, claim.LeaseDuration.Microseconds())
	if err != nil {
		return nil, errors.New("jobs could not be claimed")
	}
	defer func() { _ = rows.Close() }()
	claimed := make([]LeasedJob, 0, claim.Limit)
	for rows.Next() {
		var job LeasedJob
		if err := rows.Scan(&job.ID, &job.ProjectID, &job.Kind, &job.Payload, &job.Attempts, &job.MaxAttempts, &job.Holder, &job.Token, &job.Generation, &job.LeaseUntil); err != nil {
			return nil, errors.New("claimed job is malformed")
		}
		job.Payload = append(json.RawMessage(nil), job.Payload...)
		claimed = append(claimed, job)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("jobs could not be claimed")
	}
	if err := tx.Commit(); err != nil {
		return nil, errors.New("job claim transaction could not commit")
	}
	return claimed, nil
}

// CompleteJob publishes success only for the exact unexpired lease fence.
func (d *Database) CompleteJob(ctx context.Context, lease JobLease) error {
	if !validJobLease(lease) {
		return errors.New("invalid job lease")
	}
	locked, err := d.authorizedJobLeaseTx(ctx, lease)
	if err != nil {
		return err
	}
	tx := locked.tx
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE jobs.outbox
SET state = 'succeeded', lease_holder = NULL, lease_token = NULL, lease_until = NULL, completed_at = statement_timestamp()
WHERE id = $1 AND state = 'running' AND lease_token = $2 AND lease_generation = $3 AND lease_until > statement_timestamp()`, lease.ID, lease.Token, lease.Generation)
	if err != nil {
		return errors.New("job could not be completed")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrStaleLease
	}
	if err := (&ControlTx{tx: tx}).AppendAudit(ctx, AuditEvent{PrincipalID: locked.Holder, ProjectID: locked.ProjectID, Action: AuditJobComplete, Outcome: AuditSucceeded, TargetKind: AuditTargetJob, TargetID: lease.ID}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("job completion could not commit")
	}
	return nil
}

// RetryJob conditionally requeues or terminally fails one exact unexpired lease.
func (d *Database) RetryJob(ctx context.Context, retry JobRetry) error {
	if !validJobLease(retry.Lease) || !boundedTokenPattern.MatchString(retry.ErrorCode) || retry.Delay < 0 || retry.Delay > maxJobDelay {
		return errors.New("invalid job retry")
	}
	locked, err := d.authorizedJobLeaseTx(ctx, retry.Lease)
	if err != nil {
		return err
	}
	tx := locked.tx
	defer func() { _ = tx.Rollback() }()
	var state string
	err = tx.QueryRowContext(ctx, `UPDATE jobs.outbox
SET state = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
    available_at = CASE WHEN attempts >= max_attempts THEN available_at ELSE statement_timestamp() + ($4 * interval '1 microsecond') END,
    last_error_code = $5, lease_holder = NULL, lease_token = NULL, lease_until = NULL,
	completed_at = CASE WHEN attempts >= max_attempts THEN statement_timestamp() ELSE NULL END
WHERE id = $1 AND state = 'running' AND lease_token = $2 AND lease_generation = $3 AND lease_until > statement_timestamp()
RETURNING state`, retry.Lease.ID, retry.Lease.Token, retry.Lease.Generation, retry.Delay.Microseconds(), retry.ErrorCode).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStaleLease
	}
	if err != nil {
		return errors.New("job could not be retried")
	}
	action := AuditJobRetry
	if state == "failed" {
		action = AuditJobFail
	}
	if err := (&ControlTx{tx: tx}).AppendAudit(ctx, AuditEvent{PrincipalID: locked.Holder, ProjectID: locked.ProjectID, Action: action, Outcome: AuditSucceeded, TargetKind: AuditTargetJob, TargetID: retry.Lease.ID}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("job retry could not commit")
	}
	return nil
}

// authorizedJobLeaseTx locks and revalidates the opaque lease, then locks its
// active holder and exact grant. Claim, completion, and retry therefore use the
// same job-before-authorization lock order, while revocation or disablement
// fences already-issued leases before publication.
type authorizedJobLease struct {
	tx        *sql.Tx
	Holder    string
	ProjectID string
}

func (d *Database) authorizedJobLeaseTx(ctx context.Context, lease JobLease) (authorizedJobLease, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return authorizedJobLease{}, errors.New("job lease transaction cannot start")
	}
	if err := lockProjectJobMutations(ctx, tx, false); err != nil {
		_ = tx.Rollback()
		return authorizedJobLease{}, err
	}
	var kind, holder, projectID string
	err = tx.QueryRowContext(ctx, `SELECT kind, lease_holder::text, COALESCE(project_id::text, '')
FROM jobs.outbox
WHERE id = $1 AND state = 'running' AND lease_token = $2 AND lease_generation = $3 AND lease_until > statement_timestamp()
FOR UPDATE`, lease.ID, lease.Token, lease.Generation).Scan(&kind, &holder, &projectID)
	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		return authorizedJobLease{}, ErrStaleLease
	}
	if err != nil {
		_ = tx.Rollback()
		return authorizedJobLease{}, errors.New("job lease could not be locked")
	}
	capability, knownKind := jobClaimCapability(kind)
	if !knownKind || projectID == "" {
		_ = tx.Rollback()
		return authorizedJobLease{}, ErrStaleLease
	}
	allowed, err := lockCapability(ctx, tx, holder, projectID, capability)
	if err != nil {
		_ = tx.Rollback()
		return authorizedJobLease{}, err
	}
	if !allowed {
		_ = tx.Rollback()
		return authorizedJobLease{}, ErrStaleLease
	}
	return authorizedJobLease{tx: tx, Holder: holder, ProjectID: projectID}, nil
}

func lockProjectJobMutations(ctx context.Context, tx *sql.Tx, exclusive bool) error {
	routine := "pg_advisory_xact_lock_shared"
	if exclusive {
		routine = "pg_advisory_xact_lock"
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_catalog.`+routine+`($1)`, projectJobMutationLockKey); err != nil {
		return errors.New("project job mutation cannot be serialized")
	}
	return nil
}

// PruneTerminalJobs removes only a bounded batch of old terminal rows.
func (d *Database) PruneTerminalJobs(ctx context.Context, before time.Time, limit int) (int64, error) {
	if before.IsZero() || limit < 1 || limit > 1000 {
		return 0, errors.New("invalid terminal prune request")
	}
	var count int64
	if err := d.db.QueryRowContext(ctx, `SELECT jobs.prune_terminal($1, $2)`, before, limit).Scan(&count); err != nil {
		return 0, errors.New("terminal jobs could not be pruned")
	}
	return count, nil
}

// PruneAuditEvents removes only a bounded batch older than the caller's retention cutoff.
func (d *Database) PruneAuditEvents(ctx context.Context, before time.Time, limit int) (int64, error) {
	if before.IsZero() || limit < 1 || limit > 1000 {
		return 0, errors.New("invalid audit prune request")
	}
	var count int64
	if err := d.db.QueryRowContext(ctx, `SELECT audit.prune_events($1, $2)`, before, limit).Scan(&count); err != nil {
		return 0, errors.New("audit events could not be pruned")
	}
	return count, nil
}

func validPrincipalKind(kind PrincipalKind) bool {
	return kind == PrincipalKindOwner || kind == PrincipalKindDevice || kind == PrincipalKindService || kind == PrincipalKindLegacyMachine
}

func validDisplayName(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) || len(value) > 512 {
		return false
	}
	count := 0
	for _, r := range value {
		count++
		if unicode.IsControl(r) || count > 128 {
			return false
		}
	}
	return true
}

func validJobLease(lease JobLease) bool {
	return validOpaqueID(lease.ID) && validOpaqueID(lease.Token) && lease.Generation > 0
}

func nullableID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

type sqlStateError interface{ SQLState() string }

func isSQLState(err error, state string) bool {
	var candidate sqlStateError
	return errors.As(err, &candidate) && candidate.SQLState() == state
}
