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

const maxJobRetryDelay = 24 * time.Hour

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

// GrantCapability adds or returns one active explicit capability grant.
func (d *Database) GrantCapability(ctx context.Context, grant Grant) (string, error) {
	if err := grant.Validate(); err != nil {
		return "", err
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return "", errors.New("grant transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
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
		control := &ControlTx{tx: tx}
		if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: grant.PrincipalID, ProjectID: grant.ProjectID, Action: AuditGrantCreate, Outcome: AuditSucceeded, TargetKind: AuditTargetGrant, TargetID: grantID}); err != nil {
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

// RevokeGrant revokes one active grant without deleting its audit-relevant identity.
func (d *Database) RevokeGrant(ctx context.Context, grantID string) error {
	if !validOpaqueID(grantID) {
		return errors.New("invalid grant")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("grant transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	var principalID string
	var projectID sql.NullString
	err = tx.QueryRowContext(ctx, `UPDATE auth.capability_grants SET revoked_at = statement_timestamp()
WHERE id = $1 AND revoked_at IS NULL RETURNING principal_id::text, project_id::text`, grantID).Scan(&principalID, &projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return errors.New("capability grant could not be revoked")
	}
	control := &ControlTx{tx: tx}
	if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: principalID, ProjectID: projectID.String, Action: AuditGrantDelete, Outcome: AuditSucceeded, TargetKind: AuditTargetGrant, TargetID: grantID}); err != nil {
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

// HasCapability checks one explicit installation/project/all-project grant.
func (d *Database) HasCapability(ctx context.Context, principalID, projectID string, capability Capability) (bool, error) {
	if !validOpaqueID(principalID) {
		return false, errors.New("invalid authorization query")
	}
	allowedScopes, known := capabilityScopes[capability]
	if !known {
		return false, errors.New("invalid authorization query")
	}
	if projectID == "" {
		if allowedScopes&allowInstallation == 0 {
			return false, errors.New("invalid authorization query")
		}
	} else if !validOpaqueID(projectID) || allowedScopes&(allowProject|allowAllProjects) == 0 {
		return false, errors.New("invalid authorization query")
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
       AND EXISTS (SELECT 1 FROM relay.projects WHERE id = $2)
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
		if _, err := control.EnqueueJob(ctx, EnqueueJob{Kind: "project.created", ProjectID: projectID, Payload: payload, MaxAttempts: 4}); err != nil {
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
	available := job.AvailableAt
	if available.IsZero() {
		available = time.Now().UTC()
	}
	var id string
	err := t.tx.QueryRowContext(ctx, `INSERT INTO jobs.outbox (project_id, kind, payload, max_attempts, available_at)
VALUES ($1, $2, $3, $4, $5) RETURNING id::text`, nullableID(job.ProjectID), job.Kind, []byte(job.Payload), job.MaxAttempts, available).Scan(&id)
	if isSQLState(err, "54000") {
		return "", ErrQueueFull
	}
	if err != nil {
		return "", errors.New("job could not be enqueued")
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
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.New("job claim transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `WITH exhausted AS (
    SELECT id FROM jobs.outbox
    WHERE kind = $1 AND state = 'running' AND lease_until <= statement_timestamp() AND attempts >= max_attempts
    ORDER BY lease_until, created_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT $2
)
UPDATE jobs.outbox AS job
SET state = 'failed', last_error_code = 'attempts_exhausted', lease_holder = NULL, lease_token = NULL, lease_until = NULL, completed_at = statement_timestamp()
FROM exhausted WHERE job.id = exhausted.id`, claim.Kind, claim.Limit); err != nil {
		return nil, errors.New("expired jobs could not be fenced")
	}
	rows, err := tx.QueryContext(ctx, `WITH candidates AS (
    SELECT id FROM jobs.outbox
    WHERE kind = $1 AND attempts < max_attempts
      AND ((state = 'queued' AND available_at <= statement_timestamp()) OR (state = 'running' AND lease_until <= statement_timestamp()))
    ORDER BY COALESCE(lease_until, available_at), created_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT $2
)
UPDATE jobs.outbox AS job
SET state = 'running', attempts = job.attempts + 1, lease_holder = $3,
    lease_token = gen_random_uuid(), lease_generation = job.lease_generation + 1,
    lease_until = statement_timestamp() + ($4 * interval '1 microsecond')
FROM candidates WHERE job.id = candidates.id
RETURNING job.id::text, COALESCE(job.project_id::text, ''), job.kind, job.payload,
          job.attempts, job.max_attempts, job.lease_holder::text, job.lease_token::text,
          job.lease_generation, job.lease_until`, claim.Kind, claim.Limit, claim.Holder, claim.LeaseDuration.Microseconds())
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
	result, err := d.db.ExecContext(ctx, `UPDATE jobs.outbox
SET state = 'succeeded', lease_holder = NULL, lease_token = NULL, lease_until = NULL, completed_at = statement_timestamp()
WHERE id = $1 AND state = 'running' AND lease_token = $2 AND lease_generation = $3 AND lease_until > statement_timestamp()`, lease.ID, lease.Token, lease.Generation)
	if err != nil {
		return errors.New("job could not be completed")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrStaleLease
	}
	return nil
}

// RetryJob conditionally requeues or terminally fails one exact unexpired lease.
func (d *Database) RetryJob(ctx context.Context, retry JobRetry) error {
	if !validJobLease(retry.Lease) || !boundedTokenPattern.MatchString(retry.ErrorCode) || retry.Delay < 0 || retry.Delay > maxJobRetryDelay {
		return errors.New("invalid job retry")
	}
	result, err := d.db.ExecContext(ctx, `UPDATE jobs.outbox
SET state = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
    available_at = CASE WHEN attempts >= max_attempts THEN available_at ELSE statement_timestamp() + ($4 * interval '1 microsecond') END,
    last_error_code = $5, lease_holder = NULL, lease_token = NULL, lease_until = NULL,
    completed_at = CASE WHEN attempts >= max_attempts THEN statement_timestamp() ELSE NULL END
WHERE id = $1 AND state = 'running' AND lease_token = $2 AND lease_generation = $3 AND lease_until > statement_timestamp()`, retry.Lease.ID, retry.Lease.Token, retry.Lease.Generation, retry.Delay.Microseconds(), retry.ErrorCode)
	if err != nil {
		return errors.New("job could not be retried")
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return ErrStaleLease
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
