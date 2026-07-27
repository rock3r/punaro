package postgres

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sort"
	"unicode/utf8"
)

const (
	memorySearchRRFOffset      = 60
	memoryHybridCandidateLimit = maxMemorySearchCandidates
	memoryHybridSearchTimeout  = 2 * memorySearchTimeout
	memoryHybridSurfaceTimeout = 3 * memorySearchTimeout
)

// MemoryHybridSearchResult records the deterministic reciprocal-rank fusion
// coordinate for one current item. Zero means that retrieval mode did not
// select the item.
type MemoryHybridSearchResult struct {
	ItemID       string            `json:"item_id"`
	Revision     int64             `json:"revision"`
	LexicalRank  int               `json:"lexical_rank"`
	SemanticRank int               `json:"semantic_rank"`
	Match        MemorySearchMatch `json:"match"`
	Score        float64           `json:"score"`
}

// MemoryHybridSearchRequest combines a normalized lexical query and an
// already-derived query embedding. It never invokes an embedding provider.
type MemoryHybridSearchRequest struct {
	PrincipalID  string
	ProjectID    string
	GenerationID string
	Query        string
	Embedding    []float64
	Limit        int
}

// MemoryHybridSearchPage carries bounded fused candidate coordinates. A later
// presentation layer reads authorized summaries from the same snapshot.
type MemoryHybridSearchPage struct {
	Results        []MemoryHybridSearchResult       `json:"results"`
	More           bool                             `json:"more"`
	SemanticStatus MemoryHybridSearchSemanticStatus `json:"semantic_status"`
}

// MemoryHybridSearchSurfaceResult pairs a fused rank coordinate with the
// bounded canonical summary from the same authorized snapshot.
type MemoryHybridSearchSurfaceResult struct {
	ItemID       string            `json:"item_id"`
	LogicalKey   string            `json:"logical_key,omitempty"`
	Kind         string            `json:"kind"`
	Trust        string            `json:"trust"`
	Layer        MemoryLayer       `json:"layer"`
	Revision     int64             `json:"revision"`
	ETag         string            `json:"etag"`
	Title        string            `json:"title,omitempty"`
	Summary      string            `json:"summary,omitempty"`
	LexicalRank  int               `json:"lexical_rank"`
	SemanticRank int               `json:"semantic_rank"`
	Match        MemorySearchMatch `json:"match"`
	Score        float64           `json:"score"`
}

// MemoryHybridSearchSurfacePage carries hybrid-ranked, bounded canonical
// summaries without a total result count.
type MemoryHybridSearchSurfacePage struct {
	Results        []MemoryHybridSearchSurfaceResult `json:"results"`
	More           bool                              `json:"more"`
	SemanticStatus MemoryHybridSearchSemanticStatus  `json:"semantic_status"`
}

// SearchMemoryHybridLexicalCandidates returns authorized lexical candidate
// coordinates when semantic retrieval is unavailable. Like the hybrid path it
// deliberately does not record recall usage; a presentation layer owns that.
func (d *Database) SearchMemoryHybridLexicalCandidates(ctx context.Context, raw MemorySearchRequest) (MemoryHybridSearchPage, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryHybridSearchPage{}, err
	}
	searchCtx, cancel := context.WithTimeout(ctx, memorySearchTimeout)
	defer cancel()
	tx, err := d.brainPool().BeginTx(searchCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryHybridSearchPage{}, errors.New("memory hybrid lexical search transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(searchCtx, tx, request.ProjectID)
	if err != nil {
		return MemoryHybridSearchPage{}, ErrNotFound
	}
	allowed, err := hasCapability(searchCtx, tx, request.PrincipalID, projectID, CapabilityMemorySearch)
	if err != nil {
		return MemoryHybridSearchPage{}, err
	}
	if !allowed {
		return MemoryHybridSearchPage{}, ErrNotFound
	}
	if _, err := tx.ExecContext(searchCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return MemoryHybridSearchPage{}, errors.New("memory hybrid lexical search timeout cannot be installed")
	}
	page, err := searchMemoryHybridLexicalCandidatesInTx(searchCtx, tx, projectID, request)
	if err != nil {
		return MemoryHybridSearchPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryHybridSearchPage{}, errors.New("memory hybrid lexical search transaction could not finish")
	}
	return page, nil
}

func searchMemoryHybridLexicalCandidatesInTx(ctx context.Context, tx *sql.Tx, projectID string, request MemorySearchRequest) (MemoryHybridSearchPage, error) {
	lexical, err := searchMemoryInTx(ctx, tx, projectID, request.Query, memoryHybridCandidateLimit, false, false)
	if err != nil {
		return MemoryHybridSearchPage{}, err
	}
	results, more, err := fuseMemorySearchRanks(lexical.Results, nil, request.Limit)
	if err != nil {
		return MemoryHybridSearchPage{}, errors.New("memory hybrid search candidates are unavailable")
	}
	return MemoryHybridSearchPage{Results: results, More: lexical.More || more, SemanticStatus: MemoryHybridSearchSemanticNotConfigured}, nil
}

// SearchMemoryHybridLexical returns lexical-only degraded hybrid results with
// bounded canonical summaries. The candidates and summaries share one
// authorization-filtered repeatable-read snapshot.
func (d *Database) SearchMemoryHybridLexical(ctx context.Context, raw MemorySearchRequest) (MemoryHybridSearchSurfacePage, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, err
	}
	searchCtx, cancel := context.WithTimeout(ctx, memoryHybridSearchTimeout)
	defer cancel()
	tx, err := d.brainPool().BeginTx(searchCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, errors.New("memory hybrid lexical search transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(searchCtx, tx, request.ProjectID)
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, ErrNotFound
	}
	allowed, err := hasCapability(searchCtx, tx, request.PrincipalID, projectID, CapabilityMemorySearch)
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, err
	}
	if !allowed {
		return MemoryHybridSearchSurfacePage{}, ErrNotFound
	}
	if _, err := tx.ExecContext(searchCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return MemoryHybridSearchSurfacePage{}, errors.New("memory hybrid lexical search timeout cannot be installed")
	}
	candidates, err := searchMemoryHybridLexicalCandidatesInTx(searchCtx, tx, projectID, request)
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, err
	}
	results, err := projectMemoryHybridSearchResultsInTx(searchCtx, tx, projectID, candidates.Results)
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryHybridSearchSurfacePage{}, errors.New("memory hybrid lexical search transaction could not finish")
	}
	d.recordMemoryRecalls(ctx, projectID, memoryHybridSearchSurfaceItemIDs(results))
	return MemoryHybridSearchSurfacePage{Results: results, More: candidates.More, SemanticStatus: candidates.SemanticStatus}, nil
}

// PrepareMemoryHybridSearch authorizes one normalized query before a later
// provider call and returns only the active generation's non-secret identity.
// The caller must pass a vector for this exact generation to the subsequent
// retrieval fence; a generation change is never silently accepted.
func (d *Database) PrepareMemoryHybridSearch(ctx context.Context, raw MemorySearchRequest) (MemoryEmbeddingGeneration, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryEmbeddingGeneration{}, err
	}
	searchCtx, cancel := context.WithTimeout(ctx, memorySearchTimeout)
	defer cancel()
	tx, err := d.brainPool().BeginTx(searchCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryEmbeddingGeneration{}, errors.New("memory hybrid preparation transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(searchCtx, tx, request.ProjectID)
	if err != nil {
		return MemoryEmbeddingGeneration{}, ErrNotFound
	}
	allowed, err := hasCapability(searchCtx, tx, request.PrincipalID, projectID, CapabilityMemorySearch)
	if err != nil {
		return MemoryEmbeddingGeneration{}, err
	}
	if !allowed {
		return MemoryEmbeddingGeneration{}, ErrNotFound
	}
	if _, err := tx.ExecContext(searchCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return MemoryEmbeddingGeneration{}, errors.New("memory hybrid preparation timeout cannot be installed")
	}
	var generation MemoryEmbeddingGeneration
	err = tx.QueryRowContext(searchCtx, `SELECT id::text,model,model_revision,dimensions,state FROM brain.embedding_generations WHERE state='active'`).Scan(&generation.ID, &generation.Model, &generation.Revision, &generation.Dimensions, &generation.State)
	if errors.Is(err, sql.ErrNoRows) {
		return MemoryEmbeddingGeneration{}, ErrMemorySemanticNotConfigured
	}
	if err != nil || generation.Validate() != nil || generation.State != MemoryEmbeddingGenerationActive {
		return MemoryEmbeddingGeneration{}, errors.New("memory hybrid generation is unavailable")
	}
	if err := tx.Commit(); err != nil {
		return MemoryEmbeddingGeneration{}, errors.New("memory hybrid preparation transaction could not finish")
	}
	return generation, nil
}

// MemoryHybridSearchSemanticStatus reports whether semantic candidates were
// available without making lexical retrieval depend on them.
type MemoryHybridSearchSemanticStatus string

const (
	// MemoryHybridSearchSemanticReady reports that both candidate paths ran.
	MemoryHybridSearchSemanticReady MemoryHybridSearchSemanticStatus = "ready"
	// MemoryHybridSearchSemanticNotConfigured reports lexical-only degradation.
	MemoryHybridSearchSemanticNotConfigured MemoryHybridSearchSemanticStatus = "not_configured"
)

func (r MemoryHybridSearchRequest) normalized() (MemoryHybridSearchRequest, error) {
	lexical, err := (MemorySearchRequest{PrincipalID: r.PrincipalID, ProjectID: r.ProjectID, Query: r.Query, Limit: r.Limit}).normalized()
	if err != nil {
		return MemoryHybridSearchRequest{}, errors.New("invalid memory hybrid search request")
	}
	semantic, err := (MemorySemanticSearchRequest{PrincipalID: r.PrincipalID, ProjectID: r.ProjectID, Embedding: r.Embedding, Limit: r.Limit}).normalized()
	if err != nil {
		return MemoryHybridSearchRequest{}, errors.New("invalid memory hybrid search request")
	}
	if !validOpaqueID(r.GenerationID) {
		return MemoryHybridSearchRequest{}, errors.New("invalid memory hybrid search request")
	}
	r.PrincipalID, r.ProjectID, r.Query, r.Embedding, r.Limit = lexical.PrincipalID, lexical.ProjectID, lexical.Query, semantic.Embedding, lexical.Limit
	return r, nil
}

// SearchMemoryHybridCandidates fuses authorized lexical and exact semantic
// candidates in one repeatable-read snapshot. It has no provider call, route,
// or client-facing summary projection. A missing active generation degrades to
// lexical-only results and reports not_configured.
func (d *Database) SearchMemoryHybridCandidates(ctx context.Context, raw MemoryHybridSearchRequest) (MemoryHybridSearchPage, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryHybridSearchPage{}, err
	}
	searchCtx, cancel := context.WithTimeout(ctx, memoryHybridSearchTimeout)
	defer cancel()
	tx, err := d.brainPool().BeginTx(searchCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryHybridSearchPage{}, errors.New("memory hybrid search transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(searchCtx, tx, request.ProjectID)
	if err != nil {
		return MemoryHybridSearchPage{}, ErrNotFound
	}
	allowed, err := hasCapability(searchCtx, tx, request.PrincipalID, projectID, CapabilityMemorySearch)
	if err != nil {
		return MemoryHybridSearchPage{}, err
	}
	if !allowed {
		return MemoryHybridSearchPage{}, ErrNotFound
	}
	if _, err := tx.ExecContext(searchCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return MemoryHybridSearchPage{}, errors.New("memory hybrid search timeout cannot be installed")
	}
	page, err := searchMemoryHybridCandidatesInTx(searchCtx, tx, projectID, request)
	if err != nil {
		return MemoryHybridSearchPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryHybridSearchPage{}, errors.New("memory hybrid search transaction could not finish")
	}
	return page, nil
}

func searchMemoryHybridCandidatesInTx(ctx context.Context, tx *sql.Tx, projectID string, request MemoryHybridSearchRequest) (MemoryHybridSearchPage, error) {
	lexical, err := searchMemoryInTx(ctx, tx, projectID, request.Query, memoryHybridCandidateLimit, false, false)
	if err != nil {
		return MemoryHybridSearchPage{}, err
	}
	semantic, semanticErr := searchMemorySemanticCandidatesInTx(ctx, tx, projectID, request.Embedding, memoryHybridCandidateLimit, request.GenerationID)
	status := MemoryHybridSearchSemanticReady
	if errors.Is(semanticErr, ErrMemorySemanticNotConfigured) {
		status = MemoryHybridSearchSemanticNotConfigured
		semantic = MemorySemanticSearchPage{}
	} else if semanticErr != nil {
		return MemoryHybridSearchPage{}, semanticErr
	}
	results, fusedMore, err := fuseMemorySearchRanks(lexical.Results, semantic.Results, request.Limit)
	if err != nil {
		return MemoryHybridSearchPage{}, errors.New("memory hybrid search candidates are unavailable")
	}
	return MemoryHybridSearchPage{Results: results, More: lexical.More || semantic.More || fusedMore, SemanticStatus: status}, nil
}

// SearchMemoryHybrid returns authorized hybrid-ranked, bounded canonical
// summaries from the same snapshot as candidate retrieval. It accepts an
// already-derived fenced embedding and never calls an embedding provider.
func (d *Database) SearchMemoryHybrid(ctx context.Context, raw MemoryHybridSearchRequest) (MemoryHybridSearchSurfacePage, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, err
	}
	searchCtx, cancel := context.WithTimeout(ctx, memoryHybridSurfaceTimeout)
	defer cancel()
	tx, err := d.brainPool().BeginTx(searchCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, errors.New("memory hybrid search transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(searchCtx, tx, request.ProjectID)
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, ErrNotFound
	}
	allowed, err := hasCapability(searchCtx, tx, request.PrincipalID, projectID, CapabilityMemorySearch)
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, err
	}
	if !allowed {
		return MemoryHybridSearchSurfacePage{}, ErrNotFound
	}
	if _, err := tx.ExecContext(searchCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return MemoryHybridSearchSurfacePage{}, errors.New("memory hybrid search timeout cannot be installed")
	}
	candidates, err := searchMemoryHybridCandidatesInTx(searchCtx, tx, projectID, request)
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, err
	}
	results, err := projectMemoryHybridSearchResultsInTx(searchCtx, tx, projectID, candidates.Results)
	if err != nil {
		return MemoryHybridSearchSurfacePage{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryHybridSearchSurfacePage{}, errors.New("memory hybrid search transaction could not finish")
	}
	d.recordMemoryRecalls(ctx, projectID, memoryHybridSearchSurfaceItemIDs(results))
	return MemoryHybridSearchSurfacePage{Results: results, More: candidates.More, SemanticStatus: candidates.SemanticStatus}, nil
}

func projectMemoryHybridSearchResultsInTx(ctx context.Context, tx *sql.Tx, projectID string, candidates []MemoryHybridSearchResult) ([]MemoryHybridSearchSurfaceResult, error) {
	if len(candidates) == 0 {
		return []MemoryHybridSearchSurfaceResult{}, nil
	}
	itemIDs := make([]string, 0, len(candidates))
	revisions := make([]int64, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if !validOpaqueID(candidate.ItemID) || candidate.Revision < 1 || candidate.LexicalRank < 0 || candidate.SemanticRank < 0 || candidate.Score <= 0 || math.IsNaN(candidate.Score) || math.IsInf(candidate.Score, 0) ||
			(candidate.LexicalRank == 0 && candidate.SemanticRank == 0) {
			return nil, errors.New("memory hybrid search result is invalid")
		}
		if _, duplicate := seen[candidate.ItemID]; duplicate {
			return nil, errors.New("memory hybrid search result is invalid")
		}
		seen[candidate.ItemID] = struct{}{}
		itemIDs = append(itemIDs, candidate.ItemID)
		revisions = append(revisions, candidate.Revision)
	}
	rows, err := tx.QueryContext(ctx, `WITH requested AS (
    SELECT candidate.item_id,candidate.revision,candidate.ordinality
    FROM unnest($2::uuid[],$3::bigint[]) WITH ORDINALITY AS candidate(item_id,revision,ordinality)
)
SELECT requested.ordinality,item.id::text,COALESCE(item.logical_key,''),item.kind,item.trust,item.layer,item.current_revision,
       CASE WHEN jsonb_typeof(revision.document->'title')='string' THEN left(revision.document->>'title',$4) ELSE '' END,
       CASE WHEN jsonb_typeof(revision.document->'summary')='string' THEN left(revision.document->>'summary',$5) ELSE '' END
FROM requested
JOIN brain.memory_items AS item ON item.id=requested.item_id AND item.current_revision=requested.revision AND item.state='active'
JOIN brain.scopes AS scope ON scope.id=item.scope_id AND scope.project_id=$1
JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
WHERE NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)
ORDER BY requested.ordinality`, projectID, itemIDs, revisions, maxMemorySearchTitleRunes, maxMemorySearchSummaryRunes)
	if err != nil {
		return nil, errors.New("memory hybrid search projection is unavailable")
	}
	defer func() { _ = rows.Close() }()
	results := make([]MemoryHybridSearchSurfaceResult, 0, len(candidates))
	for rows.Next() {
		var position int
		var result MemoryHybridSearchSurfaceResult
		if err := rows.Scan(&position, &result.ItemID, &result.LogicalKey, &result.Kind, &result.Trust, &result.Layer, &result.Revision, &result.Title, &result.Summary); err != nil ||
			position != len(results)+1 || position > len(candidates) || result.ItemID != candidates[position-1].ItemID || result.Revision != candidates[position-1].Revision ||
			!validOpaqueID(result.ItemID) || result.Revision < 1 || utf8.RuneCountInString(result.Title) > maxMemorySearchTitleRunes || utf8.RuneCountInString(result.Summary) > maxMemorySearchSummaryRunes {
			return nil, errors.New("memory hybrid search projection is invalid")
		}
		candidate := candidates[position-1]
		result.LexicalRank, result.SemanticRank, result.Match, result.Score = candidate.LexicalRank, candidate.SemanticRank, candidate.Match, candidate.Score
		result.ETag = memoryETag(result.ItemID, result.Revision)
		results = append(results, result)
	}
	if err := rows.Err(); err != nil || len(results) != len(candidates) {
		return nil, errors.New("memory hybrid search projection is unavailable")
	}
	return results, nil
}

func memoryHybridSearchSurfaceItemIDs(results []MemoryHybridSearchSurfaceResult) []string {
	itemIDs := make([]string, 0, len(results))
	for _, result := range results {
		itemIDs = append(itemIDs, result.ItemID)
	}
	return itemIDs
}

// fuseMemorySearchRanks combines independently bounded, already-authorized
// candidate lists. It deliberately performs no database read, provider call,
// or result projection; a later search surface supplies one snapshot and the
// canonical memory summaries.
func fuseMemorySearchRanks(lexical []MemorySearchResult, semantic []MemorySemanticSearchResult, limit int) ([]MemoryHybridSearchResult, bool, error) {
	if limit < 1 || limit > maxMemorySearchResults {
		return nil, false, errors.New("invalid memory hybrid search limit")
	}
	results := make(map[string]MemoryHybridSearchResult, len(lexical)+len(semantic))
	for index, candidate := range lexical {
		if !validOpaqueID(candidate.ItemID) || candidate.Revision < 1 {
			return nil, false, errors.New("invalid lexical memory search result")
		}
		if _, exists := results[candidate.ItemID]; exists {
			return nil, false, errors.New("duplicate lexical memory search result")
		}
		results[candidate.ItemID] = MemoryHybridSearchResult{
			ItemID: candidate.ItemID, Revision: candidate.Revision, LexicalRank: index + 1,
			Match: candidate.Match,
			Score: 1.0 / float64(memorySearchRRFOffset+index+1),
		}
	}
	for index, candidate := range semantic {
		if !validOpaqueID(candidate.ItemID) || candidate.Revision < 1 {
			return nil, false, errors.New("invalid semantic memory search result")
		}
		result, exists := results[candidate.ItemID]
		if exists && result.Revision != candidate.Revision {
			return nil, false, errors.New("memory hybrid search result revision mismatch")
		}
		if result.SemanticRank != 0 {
			return nil, false, errors.New("duplicate semantic memory search result")
		}
		result.ItemID = candidate.ItemID
		result.Revision = candidate.Revision
		result.SemanticRank = index + 1
		if result.LexicalRank == 0 {
			result.Match = MemorySearchMatchSemantic
		}
		result.Score += 1.0 / float64(memorySearchRRFOffset+index+1)
		results[candidate.ItemID] = result
	}
	fused := make([]MemoryHybridSearchResult, 0, len(results))
	for _, result := range results {
		fused = append(fused, result)
	}
	sort.Slice(fused, func(i, j int) bool {
		if fused[i].Score != fused[j].Score {
			return fused[i].Score > fused[j].Score
		}
		if fused[i].LexicalRank != fused[j].LexicalRank {
			if fused[i].LexicalRank == 0 || fused[j].LexicalRank == 0 {
				return fused[j].LexicalRank == 0
			}
			return fused[i].LexicalRank < fused[j].LexicalRank
		}
		if fused[i].SemanticRank != fused[j].SemanticRank {
			if fused[i].SemanticRank == 0 || fused[j].SemanticRank == 0 {
				return fused[j].SemanticRank == 0
			}
			return fused[i].SemanticRank < fused[j].SemanticRank
		}
		return fused[i].ItemID < fused[j].ItemID
	})
	more := len(fused) > limit
	if more {
		fused = fused[:limit]
	}
	return fused, more, nil
}
