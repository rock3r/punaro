package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const (
	maxMemoryRecallBatch        = 64
	maxMemoryRecallQueue        = 64
	memoryUsageWriteTimeout     = 150 * time.Millisecond
	maxMemoryArchiveCandidates  = 64
	minMemoryArchiveInactiveFor = 24 * time.Hour
	maxMemoryArchiveInactiveFor = 10 * 365 * 24 * time.Hour
)

type memoryUsageWrite struct {
	projectID string
	itemIDs   []string
}

// MemoryArchiveCandidateRequest supplies one explicit inactivity and usage policy.
type MemoryArchiveCandidateRequest struct {
	PrincipalID    string
	ProjectID      string
	InactiveFor    time.Duration
	MaxRecallCount int64
	Limit          int
}

// MemoryArchiveCandidate is content-free and never changes canonical state.
type MemoryArchiveCandidate struct {
	ItemID         string      `json:"item_id"`
	Revision       int64       `json:"revision"`
	ETag           string      `json:"etag"`
	Kind           string      `json:"kind"`
	Trust          string      `json:"trust"`
	Layer          MemoryLayer `json:"layer"`
	RecallCount    int64       `json:"recall_count"`
	LastRecalledAt *time.Time  `json:"last_recalled_at,omitempty"`
	LastActivityAt time.Time   `json:"last_activity_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

// MemoryArchiveCandidatePage is bounded by candidate rows.
type MemoryArchiveCandidatePage struct {
	Candidates []MemoryArchiveCandidate `json:"candidates"`
	More       bool                     `json:"more"`
}

func (request MemoryArchiveCandidateRequest) normalized() (MemoryArchiveCandidateRequest, error) {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.ProjectID) ||
		request.InactiveFor < minMemoryArchiveInactiveFor || request.InactiveFor > maxMemoryArchiveInactiveFor ||
		request.MaxRecallCount < 0 || request.Limit < 1 || request.Limit > maxMemoryArchiveCandidates {
		return MemoryArchiveCandidateRequest{}, errors.New("invalid memory archive-candidate request")
	}
	return request, nil
}

func uniqueMemoryRecallIDs(input []string, limit int) []string {
	if limit < 1 {
		return nil
	}
	result := make([]string, 0, min(limit, len(input)))
	seen := make(map[string]struct{}, cap(result))
	for _, itemID := range input {
		if !validOpaqueID(itemID) {
			continue
		}
		if _, duplicate := seen[itemID]; duplicate {
			continue
		}
		seen[itemID] = struct{}{}
		result = append(result, itemID)
		if len(result) == limit {
			break
		}
	}
	return result
}

// recordMemoryRecalls is optional derived accounting. It only attempts a
// bounded non-blocking enqueue, so retrieval latency and success never depend
// on the follow-up write.
func (d *Database) recordMemoryRecalls(ctx context.Context, projectID string, rawItemIDs []string) {
	itemIDs := uniqueMemoryRecallIDs(rawItemIDs, maxMemoryRecallBatch)
	if !validOpaqueID(projectID) || len(itemIDs) == 0 || d.memoryUsageWrites == nil || d.memoryUsageStop == nil {
		return
	}
	select {
	case <-d.memoryUsageStop:
		return
	default:
	}
	write := memoryUsageWrite{projectID: projectID, itemIDs: itemIDs}
	select {
	case <-ctx.Done():
	case <-d.memoryUsageStop:
	case d.memoryUsageWrites <- write:
	default:
	}
}

func (d *Database) runMemoryUsageWriter(ctx context.Context) {
	defer close(d.memoryUsageDone)
	workerContext := context.WithoutCancel(ctx)
	for {
		select {
		case <-d.memoryUsageStop:
			return
		default:
		}
		select {
		case <-d.memoryUsageStop:
			return
		case write := <-d.memoryUsageWrites:
			usageCtx, cancel := context.WithTimeout(workerContext, memoryUsageWriteTimeout)
			_, _ = d.brainPool().ExecContext(usageCtx, `SELECT brain.record_memory_recall($1,$2::uuid[])`, write.projectID, write.itemIDs)
			cancel()
		}
	}
}

// FindMemoryArchiveCandidates returns one snapshot-consistent policy report.
// It never archives, proposes, or rewrites canonical memory.
func (d *Database) FindMemoryArchiveCandidates(ctx context.Context, raw MemoryArchiveCandidateRequest) (MemoryArchiveCandidatePage, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryArchiveCandidatePage{}, err
	}
	maintenanceCtx, cancel := context.WithTimeout(ctx, memoryMaintenanceReadTimeout)
	defer cancel()
	tx, err := d.brainPool().BeginTx(maintenanceCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryArchiveCandidatePage{}, errors.New("memory archive-candidate transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(maintenanceCtx, tx, request.ProjectID)
	if err != nil {
		return MemoryArchiveCandidatePage{}, ErrNotFound
	}
	allowed, err := hasCapability(maintenanceCtx, tx, request.PrincipalID, projectID, CapabilityMemoryAdminister)
	if err != nil {
		return MemoryArchiveCandidatePage{}, err
	}
	if !allowed {
		return MemoryArchiveCandidatePage{}, ErrNotFound
	}
	if _, err := tx.ExecContext(maintenanceCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return MemoryArchiveCandidatePage{}, errors.New("memory archive-candidate timeout cannot be installed")
	}
	page, err := findMemoryArchiveCandidatesInTx(maintenanceCtx, tx, projectID, request)
	if err != nil {
		return MemoryArchiveCandidatePage{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryArchiveCandidatePage{}, errors.New("memory archive-candidate transaction could not finish")
	}
	return page, nil
}

func findMemoryArchiveCandidatesInTx(ctx context.Context, tx *sql.Tx, projectID string, request MemoryArchiveCandidateRequest) (MemoryArchiveCandidatePage, error) {
	rows, err := tx.QueryContext(ctx, `SELECT item.id::text,item.current_revision,item.kind,item.trust,item.layer,
       COALESCE(usage.recall_count,0),usage.last_recalled_at,
       GREATEST(item.updated_at,COALESCE(usage.last_recalled_at,item.created_at)) AS last_activity_at,
       item.updated_at
FROM brain.memory_items AS item
JOIN brain.scopes AS scope ON scope.id=item.scope_id
LEFT JOIN relay.project_lookup_aliases AS alias ON alias.alias_project_id=scope.project_id
JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
LEFT JOIN brain.memory_usage AS usage ON usage.item_id=item.id
WHERE item.state='active'
  AND COALESCE(alias.canonical_project_id,scope.project_id)=$1
  AND COALESCE(usage.recall_count,0)<=$3
  AND GREATEST(item.updated_at,COALESCE(usage.last_recalled_at,item.created_at))
      <= statement_timestamp() - ($2 * interval '1 microsecond')
  AND revision.document->'pinned' IS DISTINCT FROM 'true'::jsonb
  AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine
                  WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)
ORDER BY last_activity_at,item.id
LIMIT $4`, projectID, request.InactiveFor.Microseconds(), request.MaxRecallCount, request.Limit+1)
	if err != nil {
		return MemoryArchiveCandidatePage{}, errors.New("memory archive-candidate report is unavailable")
	}
	defer func() { _ = rows.Close() }()
	candidates := make([]MemoryArchiveCandidate, 0, request.Limit+1)
	for rows.Next() {
		var candidate MemoryArchiveCandidate
		var lastRecalled sql.NullTime
		if err := rows.Scan(&candidate.ItemID, &candidate.Revision, &candidate.Kind, &candidate.Trust, &candidate.Layer,
			&candidate.RecallCount, &lastRecalled, &candidate.LastActivityAt, &candidate.UpdatedAt); err != nil ||
			!validOpaqueID(candidate.ItemID) || candidate.Revision < 1 || candidate.RecallCount < 0 {
			return MemoryArchiveCandidatePage{}, errors.New("memory archive-candidate report is unavailable")
		}
		if lastRecalled.Valid {
			value := lastRecalled.Time
			candidate.LastRecalledAt = &value
		}
		candidate.ETag = memoryETag(candidate.ItemID, candidate.Revision)
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return MemoryArchiveCandidatePage{}, errors.New("memory archive-candidate report is unavailable")
	}
	page := MemoryArchiveCandidatePage{Candidates: candidates}
	if len(page.Candidates) > request.Limit {
		page.Candidates = page.Candidates[:request.Limit]
		page.More = true
	}
	return page, nil
}
