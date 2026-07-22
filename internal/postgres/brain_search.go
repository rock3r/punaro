package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxMemorySearchQueryRunes   = 256
	maxMemorySearchQueryBytes   = 1024
	maxMemorySearchResults      = 50
	maxMemorySearchTitleRunes   = 256
	maxMemorySearchSummaryRunes = 1024
	maxMemorySearchCandidates   = 200
	memorySearchTimeout         = 2 * time.Second
)

// MemorySearchRequest describes one bounded project-scoped lexical search.
type MemorySearchRequest struct {
	PrincipalID string
	ProjectID   string
	Query       string
	Limit       int
}

// MemorySearchMatch identifies the strongest lexical match used for ordering.
type MemorySearchMatch string

const (
	// MemorySearchMatchLexical marks a full-text lexical match.
	MemorySearchMatchLexical MemorySearchMatch = "lexical"
	// MemorySearchMatchTitle marks an exact title match.
	MemorySearchMatchTitle MemorySearchMatch = "title"
	// MemorySearchMatchLogicalKey marks an exact logical-key match.
	MemorySearchMatchLogicalKey MemorySearchMatch = "logical_key"
)

// MemorySearchResult is a bounded summary of one authorized current revision.
// The canonical document remains available only through GetMemory.
type MemorySearchResult struct {
	ItemID     string            `json:"item_id"`
	LogicalKey string            `json:"logical_key,omitempty"`
	Kind       string            `json:"kind"`
	Trust      string            `json:"trust"`
	Layer      MemoryLayer       `json:"layer"`
	Revision   int64             `json:"revision"`
	ETag       string            `json:"etag"`
	Title      string            `json:"title,omitempty"`
	Summary    string            `json:"summary,omitempty"`
	Match      MemorySearchMatch `json:"match"`
	Score      float64           `json:"score"`
}

// MemorySearchPage carries bounded results without a potentially leaky count.
type MemorySearchPage struct {
	Results []MemorySearchResult `json:"results"`
	More    bool                 `json:"more"`
}

func (r MemorySearchRequest) normalized() (MemorySearchRequest, error) {
	r.Query = strings.TrimSpace(r.Query)
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || r.Query == "" ||
		!utf8.ValidString(r.Query) || len(r.Query) > maxMemorySearchQueryBytes ||
		utf8.RuneCountInString(r.Query) > maxMemorySearchQueryRunes ||
		strings.IndexFunc(r.Query, unicode.IsControl) >= 0 ||
		r.Limit < 1 || r.Limit > maxMemorySearchResults {
		return MemorySearchRequest{}, errors.New("invalid memory search request")
	}
	return r, nil
}

// SearchMemory returns authorized, active, non-quarantined current revisions.
func (d *Database) SearchMemory(ctx context.Context, raw MemorySearchRequest) (MemorySearchPage, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemorySearchPage{}, err
	}
	searchCtx, cancel := context.WithTimeout(ctx, memorySearchTimeout)
	defer cancel()
	tx, err := d.brainPool().BeginTx(searchCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemorySearchPage{}, errors.New("memory search transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(searchCtx, tx, request.ProjectID)
	if err != nil {
		return MemorySearchPage{}, ErrNotFound
	}
	allowed, err := hasCapability(searchCtx, tx, request.PrincipalID, projectID, CapabilityMemorySearch)
	if err != nil {
		return MemorySearchPage{}, err
	}
	if !allowed {
		return MemorySearchPage{}, ErrNotFound
	}
	if _, err := tx.ExecContext(searchCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return MemorySearchPage{}, errors.New("memory search timeout cannot be installed")
	}
	page, err := searchMemoryInTx(searchCtx, tx, projectID, request.Query, request.Limit, false, false)
	if err != nil {
		return MemorySearchPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemorySearchPage{}, errors.New("memory search transaction could not finish")
	}
	return page, nil
}

func searchMemoryInTx(ctx context.Context, tx *sql.Tx, projectID, query string, limit int, curatedOnly, requireProjection bool) (MemorySearchPage, error) {
	rows, err := tx.QueryContext(ctx, `WITH search_query AS (
    SELECT websearch_to_tsquery('simple'::regconfig,$2) AS query
), exact_key AS MATERIALIZED (
    SELECT item.id,item.logical_key,item.kind,item.trust,item.layer,item.current_revision,item.updated_at,
           revision.document,2 AS match_tier,ts_rank_cd(revision.search_vector,search_query.query,32) AS lexical_score
    FROM brain.memory_items AS item
    JOIN brain.scopes AS scope ON scope.id=item.scope_id AND scope.project_id=$1
    JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
    CROSS JOIN search_query
    WHERE item.state='active' AND item.logical_key=$2 AND (NOT $7 OR item.layer='curated')
      AND (NOT $8 OR (jsonb_typeof(revision.document->'title')='string' AND btrim(revision.document->>'title')<>'')
                  OR (jsonb_typeof(revision.document->'summary')='string' AND btrim(revision.document->>'summary')<>''))
      AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)
    LIMIT 1
), exact_title AS MATERIALIZED (
	SELECT item.id,item.logical_key,item.kind,item.trust,item.layer,item.current_revision,item.updated_at,
	       revision.document,1 AS match_tier,ts_rank_cd(revision.search_vector,search_query.query,32) AS lexical_score
	FROM brain.memory_revisions AS revision
	JOIN brain.memory_items AS item ON item.id=revision.item_id AND item.current_revision=revision.revision
	JOIN brain.scopes AS scope ON scope.id=item.scope_id AND scope.project_id=$1
	CROSS JOIN search_query
	WHERE item.state='active' AND revision.search_title=$2 AND (NOT $7 OR item.layer='curated')
	  AND (NOT $8 OR (jsonb_typeof(revision.document->'title')='string' AND btrim(revision.document->>'title')<>'')
	              OR (jsonb_typeof(revision.document->'summary')='string' AND btrim(revision.document->>'summary')<>''))
	  AND octet_length(revision.search_title)<=1024
	  AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)
	ORDER BY lexical_score DESC,item.updated_at DESC,item.id
	LIMIT $6
), lexical_candidates AS MATERIALIZED (
	SELECT item.id,item.logical_key,item.kind,item.trust,item.layer,item.current_revision,item.updated_at,
	       revision.document,
	       CASE WHEN revision.search_title=$2 THEN 1 ELSE 0 END AS match_tier,
	       ts_rank_cd(revision.search_vector,search_query.query,32) AS lexical_score
    FROM brain.memory_items AS item
    JOIN brain.scopes AS scope ON scope.id=item.scope_id AND scope.project_id=$1
    JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
    CROSS JOIN search_query
    WHERE item.state='active' AND revision.search_vector @@ search_query.query AND (NOT $7 OR item.layer='curated')
      AND (NOT $8 OR (jsonb_typeof(revision.document->'title')='string' AND btrim(revision.document->>'title')<>'')
                  OR (jsonb_typeof(revision.document->'summary')='string' AND btrim(revision.document->>'summary')<>''))
      AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)
	ORDER BY match_tier DESC,lexical_score DESC,item.updated_at DESC,item.id
	LIMIT $6
), candidates AS (
    SELECT * FROM exact_key
    UNION ALL
	SELECT title.* FROM exact_title AS title
	WHERE NOT EXISTS (SELECT 1 FROM exact_key WHERE exact_key.id=title.id)
	UNION ALL
	SELECT lexical.* FROM lexical_candidates AS lexical
	WHERE NOT EXISTS (SELECT 1 FROM exact_key WHERE exact_key.id=lexical.id)
	  AND NOT EXISTS (SELECT 1 FROM exact_title WHERE exact_title.id=lexical.id)
)
SELECT id::text,COALESCE(logical_key,''),kind,trust,layer,current_revision,
	   CASE WHEN jsonb_typeof(revision.document->'title')='string'
	        THEN left(CASE WHEN $8 THEN btrim(revision.document->>'title') ELSE revision.document->>'title' END,$4) ELSE '' END,
	   CASE WHEN jsonb_typeof(revision.document->'summary')='string'
	        THEN left(CASE WHEN $8 THEN btrim(revision.document->>'summary') ELSE revision.document->>'summary' END,$5) ELSE '' END,
	   match_tier,lexical_score
FROM candidates AS revision
ORDER BY match_tier DESC,lexical_score DESC,updated_at DESC,id
LIMIT $3`, projectID, query, limit+1, maxMemorySearchTitleRunes, maxMemorySearchSummaryRunes, maxMemorySearchCandidates, curatedOnly, requireProjection)
	if err != nil {
		return MemorySearchPage{}, errors.New("memory search is unavailable")
	}
	defer func() { _ = rows.Close() }()
	page := MemorySearchPage{Results: make([]MemorySearchResult, 0, limit)}
	for rows.Next() {
		var result MemorySearchResult
		var matchTier int
		if err := rows.Scan(&result.ItemID, &result.LogicalKey, &result.Kind, &result.Trust, &result.Layer, &result.Revision, &result.Title, &result.Summary, &matchTier, &result.Score); err != nil {
			return MemorySearchPage{}, errors.New("memory search result is unavailable")
		}
		if !validOpaqueID(result.ItemID) || result.Revision < 1 || utf8.RuneCountInString(result.Title) > maxMemorySearchTitleRunes || utf8.RuneCountInString(result.Summary) > maxMemorySearchSummaryRunes {
			return MemorySearchPage{}, errors.New("memory search result is invalid")
		}
		switch matchTier {
		case 2:
			result.Match = MemorySearchMatchLogicalKey
		case 1:
			result.Match = MemorySearchMatchTitle
		case 0:
			result.Match = MemorySearchMatchLexical
		default:
			return MemorySearchPage{}, errors.New("memory search result has invalid match tier")
		}
		result.ETag = memoryETag(result.ItemID, result.Revision)
		if len(page.Results) == limit {
			page.More = true
			continue
		}
		page.Results = append(page.Results, result)
	}
	if err := rows.Err(); err != nil {
		return MemorySearchPage{}, errors.New("memory search is unavailable")
	}
	return page, nil
}

func (d *Database) brainPool() *sql.DB {
	if d.brainDB != nil {
		return d.brainDB
	}
	return d.db
}
