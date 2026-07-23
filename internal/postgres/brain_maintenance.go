package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

const (
	maxMemoryDuplicateCandidates = 64
	memoryMaintenanceReadTimeout = 2 * time.Second
)

// MemoryDuplicateRequest asks for one bounded exact-content duplicate report.
type MemoryDuplicateRequest struct {
	PrincipalID string
	ProjectID   string
	Limit       int
}

// MemoryDuplicateCandidate identifies one active current revision that exactly
// matches the deterministic oldest item in its content group.
type MemoryDuplicateCandidate struct {
	ContentSHA256     string      `json:"content_sha256"`
	KeeperItemID      string      `json:"keeper_item_id"`
	KeeperRevision    int64       `json:"keeper_revision"`
	KeeperLayer       MemoryLayer `json:"keeper_layer"`
	DuplicateItemID   string      `json:"duplicate_item_id"`
	DuplicateRevision int64       `json:"duplicate_revision"`
	DuplicateLayer    MemoryLayer `json:"duplicate_layer"`
}

// MemoryDuplicatePage is bounded by candidate rows rather than groups.
type MemoryDuplicatePage struct {
	Candidates []MemoryDuplicateCandidate `json:"candidates"`
	More       bool                       `json:"more"`
}

func (request MemoryDuplicateRequest) normalized() (MemoryDuplicateRequest, error) {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.ProjectID) ||
		request.Limit < 1 || request.Limit > maxMemoryDuplicateCandidates {
		return MemoryDuplicateRequest{}, errors.New("invalid memory duplicate request")
	}
	return request, nil
}

// DetectExactMemoryDuplicates returns a snapshot-consistent, content-free
// report. It never mutates, archives, or merges canonical memory.
func (d *Database) DetectExactMemoryDuplicates(ctx context.Context, raw MemoryDuplicateRequest) (MemoryDuplicatePage, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryDuplicatePage{}, err
	}
	maintenanceCtx, cancel := context.WithTimeout(ctx, memoryMaintenanceReadTimeout)
	defer cancel()
	tx, err := d.brainPool().BeginTx(maintenanceCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryDuplicatePage{}, errors.New("memory duplicate transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(maintenanceCtx, tx, request.ProjectID)
	if err != nil {
		return MemoryDuplicatePage{}, ErrNotFound
	}
	allowed, err := hasCapability(maintenanceCtx, tx, request.PrincipalID, projectID, CapabilityMemoryAdminister)
	if err != nil {
		return MemoryDuplicatePage{}, err
	}
	if !allowed {
		return MemoryDuplicatePage{}, ErrNotFound
	}
	if _, err := tx.ExecContext(maintenanceCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return MemoryDuplicatePage{}, errors.New("memory duplicate timeout cannot be installed")
	}
	page, err := detectExactMemoryDuplicatesInTx(maintenanceCtx, tx, projectID, request.Limit)
	if err != nil {
		return MemoryDuplicatePage{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryDuplicatePage{}, errors.New("memory duplicate transaction could not finish")
	}
	return page, nil
}

func detectExactMemoryDuplicatesInTx(ctx context.Context, tx *sql.Tx, projectID string, limit int) (MemoryDuplicatePage, error) {
	rows, err := tx.QueryContext(ctx, `WITH current_records AS (
	SELECT item.id,item.current_revision,item.layer,revision.content_sha256,
	       row_number() OVER content_group AS group_ordinal,
	       first_value(item.id) OVER content_group AS keeper_item_id,
	       first_value(item.current_revision) OVER content_group AS keeper_revision,
           first_value(item.layer) OVER content_group AS keeper_layer
    FROM brain.memory_items AS item
    JOIN brain.scopes AS scope ON scope.id=item.scope_id
	LEFT JOIN relay.project_lookup_aliases AS alias ON alias.alias_project_id=scope.project_id
	JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
	WHERE item.state='active' AND COALESCE(alias.canonical_project_id,scope.project_id)=$1
	  AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)
	WINDOW content_group AS (
	    PARTITION BY revision.content_sha256,revision.document
	    ORDER BY item.created_at,item.id
	)
)
SELECT content_sha256,keeper_item_id::text,keeper_revision,keeper_layer,
	   id::text,current_revision,layer
FROM current_records
WHERE group_ordinal>1
ORDER BY content_sha256,keeper_item_id,id
LIMIT $2`, projectID, limit+1)
	if err != nil {
		return MemoryDuplicatePage{}, errors.New("memory duplicate report is unavailable")
	}
	defer func() { _ = rows.Close() }()
	candidates := make([]MemoryDuplicateCandidate, 0, limit+1)
	for rows.Next() {
		var candidate MemoryDuplicateCandidate
		var contentHash []byte
		if err := rows.Scan(&contentHash, &candidate.KeeperItemID, &candidate.KeeperRevision, &candidate.KeeperLayer,
			&candidate.DuplicateItemID, &candidate.DuplicateRevision, &candidate.DuplicateLayer); err != nil || len(contentHash) != sha256.Size {
			return MemoryDuplicatePage{}, errors.New("memory duplicate report is unavailable")
		}
		candidate.ContentSHA256 = hex.EncodeToString(contentHash)
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return MemoryDuplicatePage{}, errors.New("memory duplicate report is unavailable")
	}
	page := MemoryDuplicatePage{Candidates: candidates}
	if len(page.Candidates) > limit {
		page.Candidates = page.Candidates[:limit]
		page.More = true
	}
	return page, nil
}
