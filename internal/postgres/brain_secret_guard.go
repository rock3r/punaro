package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/rock3r/punaro/internal/secretguard"
)

// MemorySecretRejection is a structured, non-echoing authoritative rejection.
type MemorySecretRejection = secretguard.RejectionError

// MemorySecretExceptionRequest approves one exact content-free fingerprint.
type MemorySecretExceptionRequest struct {
	PrincipalID    string
	ProjectID      string
	IdempotencyKey string
	RuleID         string
	FieldPath      string
	RuleVersion    int64
	Fingerprint    [sha256.Size]byte
}

// MemorySecretExceptionRevokeRequest revokes one exact exception.
type MemorySecretExceptionRevokeRequest struct {
	PrincipalID    string
	ProjectID      string
	IdempotencyKey string
	ExceptionID    string
}

// MemorySecretExceptionResult contains no suspected value or canonical content.
type MemorySecretExceptionResult struct {
	ExceptionID string `json:"exception_id"`
	Active      bool   `json:"active"`
}

func (r MemorySecretExceptionRequest) validate() error {
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || !validOpaqueID(r.IdempotencyKey) || !secretguard.ValidIdentity(r.RuleID, r.FieldPath, r.RuleVersion, r.Fingerprint) {
		return errors.New("invalid memory secret exception request")
	}
	return nil
}

func (r MemorySecretExceptionRevokeRequest) validate() error {
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || !validOpaqueID(r.IdempotencyKey) || !validOpaqueID(r.ExceptionID) {
		return errors.New("invalid memory secret exception revocation")
	}
	return nil
}

// ApproveMemorySecretException adds only an exact project/rule/path/version/fingerprint exception.
func (d *Database) ApproveMemorySecretException(ctx context.Context, request MemorySecretExceptionRequest) (MemorySecretExceptionResult, error) {
	if err := request.validate(); err != nil {
		return MemorySecretExceptionResult{}, err
	}
	body, _ := json.Marshal(struct {
		ProjectID   string `json:"project_id"`
		RuleID      string `json:"rule_id"`
		FieldPath   string `json:"field_path"`
		RuleVersion int64  `json:"rule_version"`
		Fingerprint string `json:"fingerprint"`
	}{request.ProjectID, request.RuleID, request.FieldPath, request.RuleVersion, hex.EncodeToString(request.Fingerprint[:])})
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return MemorySecretExceptionResult{}, mutationStartError(err, "memory secret exception transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: request.PrincipalID, Operation: "memory.secret-exception.create", Key: request.IdempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
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
		if err := requireSecretGuardIdentity(ctx, tx); err != nil {
			return IdempotencyOutcome{}, err
		}
		var exceptionID string
		inserted := true
		err = tx.QueryRowContext(ctx, `INSERT INTO brain.secret_exceptions (project_id,rule_version,rule_id,field_path,value_fingerprint,approved_by)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (project_id,rule_version,rule_id,field_path,value_fingerprint) WHERE revoked_at IS NULL DO NOTHING
RETURNING id::text`, project.ID, request.RuleVersion, request.RuleID, request.FieldPath, request.Fingerprint[:], request.PrincipalID).Scan(&exceptionID)
		if errors.Is(err, sql.ErrNoRows) {
			inserted = false
			// Approval and revocation both hold the same project row FOR UPDATE,
			// so an active conflict cannot be revoked before this lookup.
			err = tx.QueryRowContext(ctx, `SELECT id::text FROM brain.secret_exceptions
WHERE project_id=$1 AND rule_version=$2 AND rule_id=$3 AND field_path=$4 AND value_fingerprint=$5 AND revoked_at IS NULL`, project.ID, request.RuleVersion, request.RuleID, request.FieldPath, request.Fingerprint[:]).Scan(&exceptionID)
		}
		if err != nil {
			return IdempotencyOutcome{}, errors.New("memory secret exception could not be stored")
		}
		if inserted {
			if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: request.PrincipalID, ProjectID: project.ID, Action: AuditMemorySecretExceptionCreate, Outcome: AuditSucceeded, TargetKind: AuditTargetProject, TargetID: project.ID}); err != nil {
				return IdempotencyOutcome{}, err
			}
		}
		return memorySecretExceptionOutcome(MemorySecretExceptionResult{ExceptionID: exceptionID, Active: true})
	})
	if err != nil {
		return MemorySecretExceptionResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemorySecretExceptionResult{}, errors.New("memory secret exception transaction could not commit")
	}
	return decodeMemorySecretExceptionOutcome(outcome)
}

// RevokeMemorySecretException disables one exact exception without deleting its audit coordinates.
func (d *Database) RevokeMemorySecretException(ctx context.Context, request MemorySecretExceptionRevokeRequest) (MemorySecretExceptionResult, error) {
	if err := request.validate(); err != nil {
		return MemorySecretExceptionResult{}, err
	}
	body, _ := json.Marshal(request)
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return MemorySecretExceptionResult{}, mutationStartError(err, "memory secret exception revocation cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: request.PrincipalID, Operation: "memory.secret-exception.revoke", Key: request.IdempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
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
		var active bool
		if err := tx.QueryRowContext(ctx, `SELECT revoked_at IS NULL FROM brain.secret_exceptions WHERE id=$1 AND project_id=$2 FOR UPDATE`, request.ExceptionID, project.ID).Scan(&active); errors.Is(err, sql.ErrNoRows) {
			return IdempotencyOutcome{}, ErrNotFound
		} else if err != nil {
			return IdempotencyOutcome{}, errors.New("memory secret exception is unavailable")
		}
		if active {
			if _, err := tx.ExecContext(ctx, `UPDATE brain.secret_exceptions SET revoked_at=statement_timestamp() WHERE id=$1 AND revoked_at IS NULL`, request.ExceptionID); err != nil {
				return IdempotencyOutcome{}, errors.New("memory secret exception could not be revoked")
			}
			if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: request.PrincipalID, ProjectID: project.ID, Action: AuditMemorySecretExceptionRevoke, Outcome: AuditSucceeded, TargetKind: AuditTargetProject, TargetID: project.ID}); err != nil {
				return IdempotencyOutcome{}, err
			}
		}
		return memorySecretExceptionOutcome(MemorySecretExceptionResult{ExceptionID: request.ExceptionID, Active: false})
	})
	if err != nil {
		return MemorySecretExceptionResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemorySecretExceptionResult{}, errors.New("memory secret exception revocation could not commit")
	}
	return decodeMemorySecretExceptionOutcome(outcome)
}

func guardMemoryDocument(ctx context.Context, tx *sql.Tx, projectID string, document []byte) error {
	if err := requireSecretGuardIdentity(ctx, tx); err != nil {
		return err
	}
	findings, err := secretguard.ScanDocument(document)
	if err != nil {
		return errors.New("memory secret guard could not scan document")
	}
	for _, finding := range findings {
		var exceptionID string
		err := tx.QueryRowContext(ctx, `SELECT id::text FROM brain.secret_exceptions
WHERE project_id=$1 AND rule_version=$2 AND rule_id=$3 AND field_path=$4 AND value_fingerprint=$5 AND revoked_at IS NULL
FOR SHARE`, projectID, finding.RuleVersion, finding.RuleID, finding.FieldPath, finding.Fingerprint[:]).Scan(&exceptionID)
		if errors.Is(err, sql.ErrNoRows) {
			return secretguard.RejectionError{Finding: finding}
		}
		if err != nil || !validOpaqueID(exceptionID) {
			return errors.New("memory secret guard is unavailable")
		}
	}
	return nil
}

func requireSecretGuardIdentity(ctx context.Context, q queryer) error {
	var version int64
	var digest []byte
	if err := q.QueryRowContext(ctx, `SELECT rule_version,rule_digest FROM brain.secret_guard_state WHERE singleton`).Scan(&version, &digest); err != nil {
		return errors.New("memory secret guard is unavailable")
	}
	expected := secretguard.Digest()
	if version != secretguard.RuleVersion || len(digest) != sha256.Size || !bytes.Equal(digest, expected[:]) {
		return errors.New("memory secret guard is incompatible")
	}
	return nil
}

func memorySecretExceptionOutcome(result MemorySecretExceptionResult) (IdempotencyOutcome, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return IdempotencyOutcome{}, errors.New("memory secret exception result cannot be encoded")
	}
	return IdempotencyOutcome{Status: OutcomeSucceeded, ResourceID: result.ExceptionID, Result: encoded}, nil
}

func decodeMemorySecretExceptionOutcome(outcome IdempotencyOutcome) (MemorySecretExceptionResult, error) {
	var result MemorySecretExceptionResult
	if outcome.Status != OutcomeSucceeded || json.Unmarshal(outcome.Result, &result) != nil || !validOpaqueID(result.ExceptionID) || result.ExceptionID != outcome.ResourceID {
		return MemorySecretExceptionResult{}, errors.New("memory secret exception result is unavailable")
	}
	return result, nil
}
