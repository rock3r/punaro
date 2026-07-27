package postgres

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strconv"
	"strings"
)

// ErrMemorySemanticNotConfigured reports that no serving embedding generation
// is available. Callers can continue with lexical retrieval.
var ErrMemorySemanticNotConfigured = errors.New("memory semantic retrieval is not configured")

// ErrMemorySemanticGenerationChanged reports that a prepared provider vector
// no longer matches the currently active embedding generation.
var ErrMemorySemanticGenerationChanged = errors.New("memory semantic generation changed")

// MemorySemanticSearchRequest is the bounded, provider-free input to exact
// semantic candidate retrieval. A later hybrid layer supplies the query
// embedding; this primitive never invokes a provider.
type MemorySemanticSearchRequest struct {
	PrincipalID string
	ProjectID   string
	Embedding   []float64
	Limit       int
}

// MemorySemanticSearchResult identifies one current memory item and its exact
// cosine distance from the supplied query embedding.
type MemorySemanticSearchResult struct {
	ItemID   string  `json:"item_id"`
	Revision int64   `json:"revision"`
	Distance float64 `json:"distance"`
}

// MemorySemanticSearchPage carries a bounded candidate set without a total.
type MemorySemanticSearchPage struct {
	Results []MemorySemanticSearchResult `json:"results"`
	More    bool                         `json:"more"`
}

func (r MemorySemanticSearchRequest) normalized() (MemorySemanticSearchRequest, error) {
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || r.Limit < 1 || r.Limit > maxMemorySearchResults ||
		len(r.Embedding) < 1 || len(r.Embedding) > maxMemoryEmbeddingDimensions {
		return MemorySemanticSearchRequest{}, errors.New("invalid memory semantic search request")
	}
	nonzero := false
	for _, value := range r.Embedding {
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > math.MaxFloat32 || (value != 0 && float64(float32(value)) == 0) {
			return MemorySemanticSearchRequest{}, errors.New("invalid memory semantic search request")
		}
		nonzero = nonzero || value != 0
	}
	if !nonzero {
		return MemorySemanticSearchRequest{}, errors.New("invalid memory semantic search request")
	}
	return r, nil
}

func memorySemanticVector(values []float64) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.FormatFloat(value, 'g', -1, 64)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// SearchMemorySemanticCandidates returns authorized exact cosine candidates
// from the active generation only. It deliberately has no ANN index, lexical
// fusion, provider call, or client-facing route.
func (d *Database) SearchMemorySemanticCandidates(ctx context.Context, raw MemorySemanticSearchRequest) (MemorySemanticSearchPage, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemorySemanticSearchPage{}, err
	}
	searchCtx, cancel := context.WithTimeout(ctx, memorySearchTimeout)
	defer cancel()
	tx, err := d.brainPool().BeginTx(searchCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemorySemanticSearchPage{}, errors.New("memory semantic search transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(searchCtx, tx, request.ProjectID)
	if err != nil {
		return MemorySemanticSearchPage{}, ErrNotFound
	}
	allowed, err := hasCapability(searchCtx, tx, request.PrincipalID, projectID, CapabilityMemorySearch)
	if err != nil {
		return MemorySemanticSearchPage{}, err
	}
	if !allowed {
		return MemorySemanticSearchPage{}, ErrNotFound
	}
	if _, err := tx.ExecContext(searchCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return MemorySemanticSearchPage{}, errors.New("memory semantic search timeout cannot be installed")
	}
	page, err := searchMemorySemanticCandidatesInTx(searchCtx, tx, projectID, request.Embedding, request.Limit, "")
	if err != nil {
		return MemorySemanticSearchPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemorySemanticSearchPage{}, errors.New("memory semantic search transaction could not finish")
	}
	return page, nil
}

func searchMemorySemanticCandidatesInTx(ctx context.Context, tx *sql.Tx, projectID string, embedding []float64, limit int, expectedGenerationID string) (MemorySemanticSearchPage, error) {
	var dimensions int
	if err := tx.QueryRowContext(ctx, `SELECT dimensions FROM brain.embedding_generations WHERE state='active' AND ($1='' OR id::text=$1)`, expectedGenerationID).Scan(&dimensions); errors.Is(err, sql.ErrNoRows) {
		if expectedGenerationID != "" {
			return MemorySemanticSearchPage{}, ErrMemorySemanticGenerationChanged
		}
		return MemorySemanticSearchPage{}, ErrMemorySemanticNotConfigured
	} else if err != nil || dimensions < 1 || dimensions > maxMemoryEmbeddingDimensions {
		return MemorySemanticSearchPage{}, errors.New("memory semantic generation is unavailable")
	}
	if len(embedding) != dimensions {
		return MemorySemanticSearchPage{}, errors.New("memory semantic embedding dimensions do not match the active generation")
	}
	rows, err := tx.QueryContext(ctx, `WITH active_generation AS MATERIALIZED (
    SELECT id FROM brain.embedding_generations WHERE state='active'
), candidates AS MATERIALIZED (
    SELECT item.id,item.current_revision,MIN(chunk.embedding <=> $2::public.vector) AS distance,item.updated_at
    FROM active_generation AS generation
    JOIN brain.embedding_chunks AS chunk ON chunk.generation_id=generation.id
    JOIN brain.embedding_jobs AS job ON job.generation_id=chunk.generation_id AND job.item_id=chunk.item_id
        AND job.revision=chunk.revision AND job.state='succeeded'
    JOIN brain.memory_items AS item ON item.id=chunk.item_id AND item.current_revision=chunk.revision
    JOIN brain.scopes AS scope ON scope.id=item.scope_id AND scope.project_id=$1
    WHERE item.state='active'
      AND public.vector_norm(chunk.embedding) > 0
      AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)
    GROUP BY item.id,item.current_revision,item.updated_at
    ORDER BY distance ASC,item.updated_at DESC,item.id
    LIMIT $3
)
SELECT id::text,current_revision,distance FROM candidates ORDER BY distance ASC,updated_at DESC,id`, projectID, memorySemanticVector(embedding), limit+1)
	if err != nil {
		return MemorySemanticSearchPage{}, errors.New("memory semantic search is unavailable")
	}
	defer func() { _ = rows.Close() }()
	page := MemorySemanticSearchPage{Results: make([]MemorySemanticSearchResult, 0, limit)}
	for rows.Next() {
		var result MemorySemanticSearchResult
		if err := rows.Scan(&result.ItemID, &result.Revision, &result.Distance); err != nil || !validOpaqueID(result.ItemID) || result.Revision < 1 || math.IsNaN(result.Distance) || math.IsInf(result.Distance, 0) || result.Distance < 0 {
			return MemorySemanticSearchPage{}, errors.New("memory semantic search result is invalid")
		}
		if len(page.Results) == limit {
			page.More = true
			continue
		}
		page.Results = append(page.Results, result)
	}
	if err := rows.Err(); err != nil {
		return MemorySemanticSearchPage{}, errors.New("memory semantic search is unavailable")
	}
	return page, nil
}
