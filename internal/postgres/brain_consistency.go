package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
)

const maxMemoryConsistencyRows = 64

// MemoryConsistencyRequest asks for one bounded canonical consistency page.
type MemoryConsistencyRequest struct {
	PrincipalID string
	ProjectID   string
	AfterItemID string
	Limit       int
}

// MemoryConsistencyIssueClass is a closed content-free inconsistency class.
type MemoryConsistencyIssueClass string

const (
	// MemoryConsistencyContentHash reports a canonical document/digest mismatch.
	MemoryConsistencyContentHash MemoryConsistencyIssueClass = "content_hash"
	// MemoryConsistencyLexicalTitle reports a generated lexical-title mismatch.
	MemoryConsistencyLexicalTitle MemoryConsistencyIssueClass = "lexical_title"
	// MemoryConsistencyLexicalVector reports a generated lexical-vector mismatch.
	MemoryConsistencyLexicalVector MemoryConsistencyIssueClass = "lexical_vector"
)

// MemoryConsistencyIssue identifies one inconsistent current revision without
// returning its content or derived values.
type MemoryConsistencyIssue struct {
	ItemID   string                      `json:"item_id"`
	Revision int64                       `json:"revision"`
	Class    MemoryConsistencyIssueClass `json:"class"`
}

// MemoryConsistencyPage is one stable scan page. NextAfterItemID is populated
// only when More is true.
type MemoryConsistencyPage struct {
	Checked                   int                      `json:"checked"`
	LexicalControlsConsistent bool                     `json:"lexical_controls_consistent"`
	Issues                    []MemoryConsistencyIssue `json:"issues"`
	NextAfterItemID           string                   `json:"next_after_item_id,omitempty"`
	More                      bool                     `json:"more"`
}

func (request MemoryConsistencyRequest) normalized() (MemoryConsistencyRequest, error) {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.ProjectID) ||
		(request.AfterItemID != "" && !validOpaqueID(request.AfterItemID)) ||
		request.Limit < 1 || request.Limit > maxMemoryConsistencyRows {
		return MemoryConsistencyRequest{}, errors.New("invalid memory consistency request")
	}
	return request, nil
}

// VerifyMemoryConsistency returns a bounded, snapshot-consistent and
// content-free canonical/lexical consistency report. It never repairs data.
func (d *Database) VerifyMemoryConsistency(ctx context.Context, raw MemoryConsistencyRequest) (MemoryConsistencyPage, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryConsistencyPage{}, err
	}
	verificationCtx, cancel := context.WithTimeout(ctx, memoryMaintenanceReadTimeout)
	defer cancel()
	tx, err := d.brainPool().BeginTx(verificationCtx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryConsistencyPage{}, errors.New("memory consistency transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(verificationCtx, tx, request.ProjectID)
	if err != nil || !strings.EqualFold(projectID, request.ProjectID) {
		return MemoryConsistencyPage{}, ErrNotFound
	}
	allowed, err := hasCapability(verificationCtx, tx, request.PrincipalID, projectID, CapabilityMemoryAdminister)
	if err != nil {
		return MemoryConsistencyPage{}, err
	}
	if !allowed {
		return MemoryConsistencyPage{}, ErrNotFound
	}
	if _, err := tx.ExecContext(verificationCtx, `SET LOCAL statement_timeout = '2s'`); err != nil {
		return MemoryConsistencyPage{}, errors.New("memory consistency timeout cannot be installed")
	}
	lexicalControls, err := memoryLexicalControlsAvailable(verificationCtx, tx)
	if err != nil {
		return MemoryConsistencyPage{}, errors.New("memory lexical controls cannot be inspected")
	}
	page := MemoryConsistencyPage{
		LexicalControlsConsistent: lexicalControls,
		Issues:                    make([]MemoryConsistencyIssue, 0),
	}
	if lexicalControls {
		page, err = verifyMemoryConsistencyInTx(verificationCtx, tx, projectID, request.AfterItemID, request.Limit)
		if err != nil {
			return MemoryConsistencyPage{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return MemoryConsistencyPage{}, errors.New("memory consistency transaction could not finish")
	}
	return page, nil
}

func verifyMemoryConsistencyInTx(ctx context.Context, tx *sql.Tx, projectID, afterItemID string, limit int) (MemoryConsistencyPage, error) {
	var cursor any
	if afterItemID != "" {
		cursor = afterItemID
	}
	rows, err := tx.QueryContext(ctx, `SELECT item.id::text,item.current_revision,revision.document::text,
       revision.content_sha256,
       revision.search_title = CASE
         WHEN jsonb_typeof(revision.document -> 'title')='string' THEN revision.document ->> 'title'
         ELSE ''
       END AS title_consistent,
       revision.search_vector = (
         setweight(to_tsvector('simple'::regconfig,
           CASE WHEN jsonb_typeof(revision.document -> 'title')='string' THEN revision.document ->> 'title' ELSE '' END),'A')
         || setweight(to_tsvector('simple'::regconfig,
           CASE WHEN jsonb_typeof(revision.document -> 'summary')='string' THEN revision.document ->> 'summary' ELSE '' END),'B')
         || setweight(to_tsvector('simple'::regconfig,
           CASE WHEN jsonb_typeof(revision.document -> 'keywords') IN ('string','array') THEN revision.document ->> 'keywords' ELSE '' END),'C')
         || setweight(to_tsvector('simple'::regconfig,
           CASE WHEN jsonb_typeof(revision.document -> 'body')='string' THEN revision.document ->> 'body' ELSE '' END),'D')
       ) AS vector_consistent
FROM brain.memory_items AS item
JOIN brain.scopes AS scope ON scope.id=item.scope_id
JOIN relay.projects AS source_project ON source_project.id=scope.project_id
JOIN brain.memory_revisions AS revision
  ON revision.item_id=item.id AND revision.revision=item.current_revision
WHERE ((source_project.id=$1 AND source_project.merged_into IS NULL)
       OR source_project.merged_into=$1)
  AND ($2::uuid IS NULL OR item.id>$2::uuid)
ORDER BY item.id
LIMIT $3`, projectID, cursor, limit+1)
	if err != nil {
		return MemoryConsistencyPage{}, errors.New("memory consistency report is unavailable")
	}
	defer func() { _ = rows.Close() }()
	type checkedRevision struct {
		itemID           string
		revision         int64
		document         []byte
		contentHash      []byte
		titleConsistent  bool
		vectorConsistent bool
	}
	checked := make([]checkedRevision, 0, limit+1)
	for rows.Next() {
		var revision checkedRevision
		if err := rows.Scan(&revision.itemID, &revision.revision, &revision.document, &revision.contentHash,
			&revision.titleConsistent, &revision.vectorConsistent); err != nil ||
			!validOpaqueID(revision.itemID) || revision.revision < 1 || len(revision.contentHash) != sha256.Size {
			return MemoryConsistencyPage{}, errors.New("memory consistency report is unavailable")
		}
		checked = append(checked, revision)
	}
	if err := rows.Err(); err != nil {
		return MemoryConsistencyPage{}, errors.New("memory consistency report is unavailable")
	}
	page := MemoryConsistencyPage{
		Checked:                   min(len(checked), limit),
		LexicalControlsConsistent: true,
		Issues:                    make([]MemoryConsistencyIssue, 0),
	}
	if len(checked) > limit {
		checked = checked[:limit]
		page.More = true
		page.NextAfterItemID = checked[len(checked)-1].itemID
	}
	for _, revision := range checked {
		documentHash := sha256.Sum256(revision.document)
		if !bytes.Equal(documentHash[:], revision.contentHash) {
			page.Issues = append(page.Issues, MemoryConsistencyIssue{
				ItemID: revision.itemID, Revision: revision.revision, Class: MemoryConsistencyContentHash,
			})
		}
		if !revision.titleConsistent {
			page.Issues = append(page.Issues, MemoryConsistencyIssue{
				ItemID: revision.itemID, Revision: revision.revision, Class: MemoryConsistencyLexicalTitle,
			})
		}
		if !revision.vectorConsistent {
			page.Issues = append(page.Issues, MemoryConsistencyIssue{
				ItemID: revision.itemID, Revision: revision.revision, Class: MemoryConsistencyLexicalVector,
			})
		}
	}
	return page, nil
}
