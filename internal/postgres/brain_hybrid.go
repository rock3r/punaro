package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sort"
)

const (
	memorySearchRRFOffset      = 60
	memoryHybridCandidateLimit = maxMemorySearchCandidates
	memoryHybridSearchTimeout  = 2 * memorySearchTimeout
)

// MemoryHybridSearchResult records the deterministic reciprocal-rank fusion
// coordinate for one current item. Zero means that retrieval mode did not
// select the item.
type MemoryHybridSearchResult struct {
	ItemID       string  `json:"item_id"`
	Revision     int64   `json:"revision"`
	LexicalRank  int     `json:"lexical_rank"`
	SemanticRank int     `json:"semantic_rank"`
	Score        float64 `json:"score"`
}

// MemoryHybridSearchRequest combines a normalized lexical query and an
// already-derived query embedding. It never invokes an embedding provider.
type MemoryHybridSearchRequest struct {
	PrincipalID string
	ProjectID   string
	Query       string
	Embedding   []float64
	Limit       int
}

// MemoryHybridSearchPage carries bounded fused candidate coordinates. A later
// presentation layer reads authorized summaries from the same snapshot.
type MemoryHybridSearchPage struct {
	Results        []MemoryHybridSearchResult       `json:"results"`
	More           bool                             `json:"more"`
	SemanticStatus MemoryHybridSearchSemanticStatus `json:"semantic_status"`
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
	lexical, err := searchMemoryInTx(searchCtx, tx, projectID, request.Query, memoryHybridCandidateLimit, false, false)
	if err != nil {
		return MemoryHybridSearchPage{}, err
	}
	semantic, semanticErr := searchMemorySemanticCandidatesInTx(searchCtx, tx, projectID, request.Embedding, memoryHybridCandidateLimit)
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
	if err := tx.Commit(); err != nil {
		return MemoryHybridSearchPage{}, errors.New("memory hybrid search transaction could not finish")
	}
	return MemoryHybridSearchPage{Results: results, More: lexical.More || semantic.More || fusedMore, SemanticStatus: status}, nil
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
