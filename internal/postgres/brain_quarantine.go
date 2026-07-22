package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/rock3r/punaro/internal/secretguard"
)

const maxMemorySecretRescanBatch = 100

// MemorySecretRescanRequest drives one bounded, restart-safe project rescan batch.
type MemorySecretRescanRequest struct {
	PrincipalID    string
	ProjectID      string
	IdempotencyKey string
	Limit          int
}

// MemorySecretRescanResult is content-free and safe to retain for idempotency.
type MemorySecretRescanResult struct {
	Scanned        int   `json:"scanned"`
	Quarantined    int   `json:"quarantined"`
	Released       int   `json:"released"`
	Remaining      bool  `json:"remaining"`
	ChangeSequence int64 `json:"change_sequence"`
}

// MemorySecretQuarantine exposes canonical content only through explicit administration.
type MemorySecretQuarantine struct {
	Item          MemoryItem          `json:"item"`
	Finding       secretguard.Finding `json:"finding"`
	Active        bool                `json:"active"`
	QuarantinedAt time.Time           `json:"quarantined_at"`
}

func (r MemorySecretRescanRequest) validate() error {
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || !validOpaqueID(r.IdempotencyKey) || r.Limit < 1 || r.Limit > maxMemorySecretRescanBatch {
		return errors.New("invalid memory secret rescan request")
	}
	return nil
}

// RescanMemorySecrets scans only current revisions whose durable coverage is stale.
func (d *Database) RescanMemorySecrets(ctx context.Context, request MemorySecretRescanRequest) (MemorySecretRescanResult, error) {
	if err := request.validate(); err != nil {
		return MemorySecretRescanResult{}, err
	}
	body, _ := json.Marshal(request)
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return MemorySecretRescanResult{}, mutationStartError(err, "memory secret rescan transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: request.PrincipalID, Operation: "memory.secret-rescan", Key: request.IdempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
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
		version, digest, generation, err := memorySecretScanIdentity(ctx, tx, project.ID)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		candidates, err := loadMemorySecretScanCandidates(ctx, tx, project.ID, version, digest, generation, request.Limit)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		result := MemorySecretRescanResult{Scanned: len(candidates)}
		for _, candidate := range candidates {
			finding, err := firstUnexceptedMemorySecretFinding(ctx, tx, project.ID, candidate.Document)
			if err != nil {
				return IdempotencyOutcome{}, err
			}
			if finding == nil {
				released, err := releaseActiveMemoryQuarantine(ctx, tx, request.PrincipalID, candidate.ItemID)
				if err != nil {
					return IdempotencyOutcome{}, err
				}
				if released {
					result.Released++
					state, err := commitMemoryChange(ctx, tx, control, request.PrincipalID, project.ID, candidate.ScopeID, candidate.ItemID, candidate.Revision, MemoryChangeQuarantineRelease, AuditMemoryQuarantineRelease)
					if err != nil {
						return IdempotencyOutcome{}, err
					}
					result.ChangeSequence = state.ChangeSequence
				}
				if err := recordMemorySecretScan(ctx, tx, project.ID, candidate.ItemID, candidate.Revision, request.PrincipalID, "clear"); err != nil {
					return IdempotencyOutcome{}, err
				}
				continue
			}
			becameQuarantined, err := storeActiveMemoryQuarantine(ctx, tx, request.PrincipalID, candidate.ItemID, candidate.Revision, *finding)
			if err != nil {
				return IdempotencyOutcome{}, err
			}
			if becameQuarantined {
				result.Quarantined++
				state, err := commitMemoryChange(ctx, tx, control, request.PrincipalID, project.ID, candidate.ScopeID, candidate.ItemID, candidate.Revision, MemoryChangeQuarantine, AuditMemoryQuarantine)
				if err != nil {
					return IdempotencyOutcome{}, err
				}
				result.ChangeSequence = state.ChangeSequence
			}
			if err := recordMemorySecretScan(ctx, tx, project.ID, candidate.ItemID, candidate.Revision, request.PrincipalID, "quarantined"); err != nil {
				return IdempotencyOutcome{}, err
			}
		}
		if err := tx.QueryRowContext(ctx, memoryRescanRemainingQuery, project.ID, version, digest, generation).Scan(&result.Remaining); err != nil {
			return IdempotencyOutcome{}, errors.New("memory secret rescan progress is unavailable")
		}
		if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: request.PrincipalID, ProjectID: project.ID, Action: AuditMemorySecretRescan, Outcome: AuditSucceeded, TargetKind: AuditTargetProject, TargetID: project.ID}); err != nil {
			return IdempotencyOutcome{}, err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return IdempotencyOutcome{}, errors.New("memory secret rescan result cannot be encoded")
		}
		return IdempotencyOutcome{Status: OutcomeSucceeded, ResourceID: project.ID, Result: encoded}, nil
	})
	if err != nil {
		return MemorySecretRescanResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemorySecretRescanResult{}, errors.New("memory secret rescan transaction could not commit")
	}
	var result MemorySecretRescanResult
	if outcome.Status != OutcomeSucceeded || outcome.ResourceID != request.ProjectID || json.Unmarshal(outcome.Result, &result) != nil || result.Scanned < 0 || result.Scanned > request.Limit || result.Quarantined < 0 || result.Released < 0 || result.Quarantined+result.Released > result.Scanned || result.ChangeSequence < 0 {
		return MemorySecretRescanResult{}, errors.New("memory secret rescan result is unavailable")
	}
	return result, nil
}

type memorySecretScanCandidate struct {
	ItemID   string
	ScopeID  string
	Revision int64
	Document []byte
	Hash     []byte
}

const memoryRescanRemainingQuery = `SELECT EXISTS (
SELECT 1 FROM brain.memory_items AS item
JOIN brain.scopes AS scope ON scope.id=item.scope_id
LEFT JOIN brain.memory_secret_scans AS scan ON scan.item_id=item.id
WHERE scope.project_id=$1 AND (scan.item_id IS NULL OR scan.revision<>item.current_revision OR scan.rule_version<>$2 OR scan.rule_digest<>$3 OR scan.exception_generation<>$4)
)`

func loadMemorySecretScanCandidates(ctx context.Context, tx *sql.Tx, projectID string, version int64, digest []byte, generation int64, limit int) ([]memorySecretScanCandidate, error) {
	rows, err := tx.QueryContext(ctx, `SELECT item.id::text,scope.id::text,item.current_revision,revision.document::text,revision.content_sha256
FROM brain.memory_items AS item
JOIN brain.scopes AS scope ON scope.id=item.scope_id
JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
LEFT JOIN brain.memory_secret_scans AS scan ON scan.item_id=item.id
WHERE scope.project_id=$1 AND (scan.item_id IS NULL OR scan.revision<>item.current_revision OR scan.rule_version<>$2 OR scan.rule_digest<>$3 OR scan.exception_generation<>$4)
ORDER BY item.id LIMIT $5 FOR UPDATE OF item`, projectID, version, digest, generation, limit)
	if err != nil {
		return nil, errors.New("memory secret rescan candidates are unavailable")
	}
	defer func() { _ = rows.Close() }()
	candidates := make([]memorySecretScanCandidate, 0, limit)
	for rows.Next() {
		var candidate memorySecretScanCandidate
		if err := rows.Scan(&candidate.ItemID, &candidate.ScopeID, &candidate.Revision, &candidate.Document, &candidate.Hash); err != nil {
			return nil, errors.New("memory secret rescan candidate is malformed")
		}
		digest := sha256.Sum256(candidate.Document)
		if len(candidate.Hash) != sha256.Size || !bytes.Equal(digest[:], candidate.Hash) {
			return nil, errors.New("memory secret rescan candidate is unavailable")
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("memory secret rescan candidates are unavailable")
	}
	return candidates, nil
}

func memorySecretScanIdentity(ctx context.Context, q queryer, projectID string) (int64, []byte, int64, error) {
	var version, generation int64
	var digest []byte
	if err := q.QueryRowContext(ctx, `SELECT guard.rule_version,guard.rule_digest,
COALESCE((SELECT exception_generation FROM brain.secret_project_state WHERE project_id=$1),0)
FROM brain.secret_guard_state AS guard WHERE guard.singleton`, projectID).Scan(&version, &digest, &generation); err != nil {
		return 0, nil, 0, errors.New("memory secret scan identity is unavailable")
	}
	expected := secretguard.Digest()
	if version != secretguard.RuleVersion || len(digest) != sha256.Size || !bytes.Equal(digest, expected[:]) || generation < 0 {
		return 0, nil, 0, errors.New("memory secret guard is incompatible")
	}
	return version, digest, generation, nil
}

func recordMemorySecretScan(ctx context.Context, tx *sql.Tx, projectID, itemID string, revision int64, principalID, outcome string) error {
	version, digest, generation, err := memorySecretScanIdentity(ctx, tx, projectID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO brain.memory_secret_scans (item_id,revision,rule_version,rule_digest,exception_generation,outcome,scanned_by)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (item_id) DO UPDATE SET revision=EXCLUDED.revision,rule_version=EXCLUDED.rule_version,rule_digest=EXCLUDED.rule_digest,
exception_generation=EXCLUDED.exception_generation,outcome=EXCLUDED.outcome,scanned_by=EXCLUDED.scanned_by,scanned_at=statement_timestamp()`, itemID, revision, version, digest, generation, outcome, principalID)
	if err != nil {
		return errors.New("memory secret scan coverage could not be recorded")
	}
	return nil
}

func storeActiveMemoryQuarantine(ctx context.Context, tx *sql.Tx, principalID, itemID string, revision int64, finding secretguard.Finding) (bool, error) {
	var activeID, ruleID, fieldPath string
	var ruleVersion int64
	var fingerprint []byte
	err := tx.QueryRowContext(ctx, `SELECT id::text,rule_version,rule_id,field_path,value_fingerprint
FROM brain.memory_quarantines WHERE item_id=$1 AND released_at IS NULL FOR UPDATE`, itemID).Scan(&activeID, &ruleVersion, &ruleID, &fieldPath, &fingerprint)
	if err == nil && ruleVersion == finding.RuleVersion && ruleID == finding.RuleID && fieldPath == finding.FieldPath && bytes.Equal(fingerprint, finding.Fingerprint[:]) {
		return false, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, errors.New("memory quarantine is unavailable")
	}
	wasActive := err == nil
	if wasActive {
		if _, err := tx.ExecContext(ctx, `UPDATE brain.memory_quarantines SET released_by=$2,released_at=statement_timestamp() WHERE id=$1 AND released_at IS NULL`, activeID, principalID); err != nil {
			return false, errors.New("memory quarantine could not be superseded")
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_quarantines (item_id,detected_revision,rule_version,rule_id,field_path,value_fingerprint,quarantined_by)
VALUES ($1,$2,$3,$4,$5,$6,$7)`, itemID, revision, finding.RuleVersion, finding.RuleID, finding.FieldPath, finding.Fingerprint[:], principalID); err != nil {
		return false, errors.New("memory quarantine could not be recorded")
	}
	return !wasActive, nil
}

func releaseActiveMemoryQuarantine(ctx context.Context, tx *sql.Tx, principalID, itemID string) (bool, error) {
	result, err := tx.ExecContext(ctx, `UPDATE brain.memory_quarantines SET released_by=$2,released_at=statement_timestamp()
WHERE item_id=$1 AND released_at IS NULL`, itemID, principalID)
	if err != nil {
		return false, errors.New("memory quarantine could not be released")
	}
	count, err := result.RowsAffected()
	if err != nil || count > 1 {
		return false, errors.New("memory quarantine release is unavailable")
	}
	return count == 1, nil
}

// ReviewMemorySecretQuarantine explicitly exposes one active quarantined item to an administrator.
func (d *Database) ReviewMemorySecretQuarantine(ctx context.Context, principalID, projectID, itemID string) (MemorySecretQuarantine, error) {
	if !validOpaqueID(principalID) || !validOpaqueID(projectID) || !validOpaqueID(itemID) {
		return MemorySecretQuarantine{}, errors.New("invalid memory quarantine review")
	}
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemorySecretQuarantine{}, errors.New("memory quarantine review cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	canonicalProjectID, err := resolveCanonicalActiveProject(ctx, tx, projectID)
	if err != nil {
		return MemorySecretQuarantine{}, ErrNotFound
	}
	allowed, err := hasCapability(ctx, tx, principalID, canonicalProjectID, CapabilityMemoryAdminister)
	if err != nil {
		return MemorySecretQuarantine{}, err
	}
	if !allowed {
		return MemorySecretQuarantine{}, ErrNotFound
	}
	var review MemorySecretQuarantine
	var logicalKey sql.NullString
	var document, contentHash, fingerprint []byte
	err = tx.QueryRowContext(ctx, `SELECT item.id::text,scope.id::text,scope.project_id::text,item.logical_key,item.kind,item.state,item.trust,item.layer,
item.current_revision,revision.document::text,revision.content_sha256,revision.author_principal_id::text,item.created_at,revision.created_at,
COALESCE((SELECT max(change.change_sequence) FROM brain.memory_changes AS change WHERE change.scope_id=scope.id AND change.item_id=item.id AND change.revision=item.current_revision AND change.timeline_id=(SELECT timeline_id FROM jobs.server_state WHERE singleton)),0),
quarantine.rule_version,quarantine.rule_id,quarantine.field_path,quarantine.value_fingerprint,quarantine.quarantined_at
FROM brain.memory_items AS item JOIN brain.scopes AS scope ON scope.id=item.scope_id
JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
JOIN brain.memory_quarantines AS quarantine ON quarantine.item_id=item.id AND quarantine.released_at IS NULL
WHERE item.id=$1 AND scope.project_id=$2`, itemID, canonicalProjectID).Scan(
		&review.Item.ItemID, &review.Item.ScopeID, &review.Item.ProjectID, &logicalKey, &review.Item.Kind, &review.Item.State, &review.Item.Trust, &review.Item.Layer,
		&review.Item.Revision, &document, &contentHash, &review.Item.AuthorID, &review.Item.CreatedAt, &review.Item.RevisionAt, &review.Item.ChangeSequence,
		&review.Finding.RuleVersion, &review.Finding.RuleID, &review.Finding.FieldPath, &fingerprint, &review.QuarantinedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return MemorySecretQuarantine{}, ErrNotFound
	}
	documentDigest := sha256.Sum256(document)
	if err != nil || len(contentHash) != sha256.Size || len(fingerprint) != sha256.Size || !bytes.Equal(documentDigest[:], contentHash) {
		return MemorySecretQuarantine{}, errors.New("memory quarantine is unavailable")
	}
	copy(review.Finding.Fingerprint[:], fingerprint)
	if !secretguard.ValidIdentity(review.Finding.RuleID, review.Finding.FieldPath, review.Finding.RuleVersion, review.Finding.Fingerprint) {
		return MemorySecretQuarantine{}, errors.New("memory quarantine is unavailable")
	}
	review.Active = true
	review.Item.LogicalKey = logicalKey.String
	review.Item.Document = append(json.RawMessage(nil), document...)
	review.Item.ContentSHA256 = hex.EncodeToString(contentHash)
	review.Item.ETag = memoryETag(review.Item.ItemID, review.Item.Revision)
	if err := tx.Commit(); err != nil {
		return MemorySecretQuarantine{}, errors.New("memory quarantine review cannot commit")
	}
	return review, nil
}
