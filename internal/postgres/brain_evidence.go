package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ErrImmutableMemoryEvidence rejects ordinary content replacement of evidence.
var ErrImmutableMemoryEvidence = errors.New("memory evidence is immutable")

const (
	maxMemoryEvidenceDocumentBytes = 64 << 10
	maxMemoryEvidenceSources       = 8
	maxMemoryEvidenceClaims        = 16
)

// MemoryLayer distinguishes curated knowledge from explicit evidence.
type MemoryLayer string

const (
	// MemoryLayerCurated is ordinary user-curated canonical memory.
	MemoryLayerCurated MemoryLayer = "curated"
	// MemoryLayerEvidence is immutable explicit evidence with revision-bound provenance.
	MemoryLayerEvidence MemoryLayer = "evidence"
)

// MemorySourceMode distinguishes target-scoped copied origins from live links.
type MemorySourceMode string

const (
	// MemorySourceCopied retains only a reference digest.
	MemorySourceCopied MemorySourceMode = "copied"
	// MemorySourceLive retains an opaque locator that is reauthorized on retrieval.
	MemorySourceLive MemorySourceMode = "live"
)

// MemorySourceKind is a closed source namespace.
type MemorySourceKind string

const (
	// MemorySourceMessage identifies an immutable relay message.
	MemorySourceMessage MemorySourceKind = "message"
	// MemorySourceAttachment identifies a trusted attachment artifact.
	MemorySourceAttachment MemorySourceKind = "attachment"
	// MemorySourceMemory identifies one exact canonical memory revision.
	MemorySourceMemory MemorySourceKind = "memory"
	// MemorySourceSession is available only for copied references in this slice.
	MemorySourceSession MemorySourceKind = "session"
	// MemorySourceImport is available only for copied references in this slice.
	MemorySourceImport MemorySourceKind = "import"
	// MemorySourceExternal is available only for copied references in this slice.
	MemorySourceExternal MemorySourceKind = "external"
)

// MemoryEdgeType is a revision-bound provenance or semantic claim.
type MemoryEdgeType string

const (
	// MemoryEdgeDerivedFrom records direct derivation from a target revision.
	MemoryEdgeDerivedFrom MemoryEdgeType = "derived_from"
	// MemoryEdgeSupports records supporting evidence for a target revision.
	MemoryEdgeSupports MemoryEdgeType = "supports"
	// MemoryEdgeContradicts records contradictory evidence for a target revision.
	MemoryEdgeContradicts MemoryEdgeType = "contradicts"
	// MemoryEdgeSupersedes records evidence superseding a target revision.
	MemoryEdgeSupersedes MemoryEdgeType = "supersedes"
)

// MemoryEvidenceSourceInput contains no source excerpt or raw external locator.
type MemoryEvidenceSourceInput struct {
	Mode             MemorySourceMode `json:"mode"`
	Kind             MemorySourceKind `json:"kind"`
	ProjectID        string           `json:"project_id,omitempty"`
	ResourceID       string           `json:"resource_id,omitempty"`
	ResourceRevision int64            `json:"resource_revision,omitempty"`
	ReferenceSHA256  string           `json:"reference_sha256,omitempty"`
}

// MemoryEvidenceClaimInput binds the new evidence revision to one exact target revision.
type MemoryEvidenceClaimInput struct {
	Type           MemoryEdgeType `json:"type"`
	TargetItemID   string         `json:"target_item_id"`
	TargetRevision int64          `json:"target_revision"`
}

// MemoryEvidenceCreateRequest creates one explicit bounded evidence record.
type MemoryEvidenceCreateRequest struct {
	PrincipalID    string                      `json:"principal_id"`
	ProjectID      string                      `json:"project_id"`
	IdempotencyKey string                      `json:"idempotency_key"`
	LogicalKey     string                      `json:"logical_key,omitempty"`
	Kind           string                      `json:"kind"`
	Trust          string                      `json:"trust"`
	Document       json.RawMessage             `json:"document"`
	Sources        []MemoryEvidenceSourceInput `json:"sources"`
	Claims         []MemoryEvidenceClaimInput  `json:"claims,omitempty"`
}

// MemoryEvidenceGetRequest fetches one target-authorized evidence revision.
type MemoryEvidenceGetRequest struct {
	PrincipalID string `json:"principal_id"`
	ProjectID   string `json:"project_id"`
	ItemID      string `json:"item_id"`
}

// MemoryEvidenceSource is one copied origin or independently authorized live link.
type MemoryEvidenceSource struct {
	SourceID         string           `json:"source_id"`
	Ordinal          int              `json:"ordinal"`
	Mode             MemorySourceMode `json:"mode"`
	Kind             MemorySourceKind `json:"kind,omitempty"`
	ProjectID        string           `json:"project_id,omitempty"`
	ResourceID       string           `json:"resource_id,omitempty"`
	ResourceRevision int64            `json:"resource_revision,omitempty"`
	ReferenceSHA256  string           `json:"reference_sha256,omitempty"`
	Redacted         bool             `json:"redacted"`
}

// MemoryEvidenceClaim is one target-authorized exact-revision edge.
type MemoryEvidenceClaim struct {
	EdgeID         string         `json:"edge_id"`
	Ordinal        int            `json:"ordinal"`
	Type           MemoryEdgeType `json:"type"`
	TargetItemID   string         `json:"target_item_id"`
	TargetRevision int64          `json:"target_revision"`
	CreatedAt      time.Time      `json:"created_at"`
}

// MemoryEvidence returns canonical evidence content plus bounded provenance.
type MemoryEvidence struct {
	Item    MemoryItem             `json:"item"`
	Sources []MemoryEvidenceSource `json:"sources"`
	Claims  []MemoryEvidenceClaim  `json:"claims"`
}

func (request MemoryEvidenceCreateRequest) normalized() (MemoryEvidenceCreateRequest, error) {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.ProjectID) || !validOpaqueID(request.IdempotencyKey) ||
		!validMemoryLogicalKey(request.LogicalKey) || !validMemoryToken(request.Kind) || !validMemoryToken(request.Trust) ||
		len(request.Sources) < 1 || len(request.Sources) > maxMemoryEvidenceSources || len(request.Claims) > maxMemoryEvidenceClaims {
		return MemoryEvidenceCreateRequest{}, errors.New("invalid memory evidence request")
	}
	document, err := canonicalMemoryDocument(request.Document)
	if err != nil || len(document) > maxMemoryEvidenceDocumentBytes {
		return MemoryEvidenceCreateRequest{}, errors.New("invalid memory evidence document")
	}
	request.Document = document
	sources := make([]MemoryEvidenceSourceInput, len(request.Sources))
	seenSources := make(map[string]struct{}, len(request.Sources))
	for index, source := range request.Sources {
		if !validMemoryEvidenceSource(source) {
			return MemoryEvidenceCreateRequest{}, errors.New("invalid memory evidence source")
		}
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%s", source.Mode, source.Kind, source.ProjectID, source.ResourceID, source.ResourceRevision, source.ReferenceSHA256)
		if _, exists := seenSources[key]; exists {
			return MemoryEvidenceCreateRequest{}, errors.New("duplicate memory evidence source")
		}
		seenSources[key] = struct{}{}
		sources[index] = source
	}
	claims := make([]MemoryEvidenceClaimInput, len(request.Claims))
	seenClaims := make(map[string]struct{}, len(request.Claims))
	for index, claim := range request.Claims {
		if !validMemoryEdgeType(claim.Type) || !validOpaqueID(claim.TargetItemID) || claim.TargetRevision < 1 {
			return MemoryEvidenceCreateRequest{}, errors.New("invalid memory evidence claim")
		}
		key := fmt.Sprintf("%s\x00%s\x00%d", claim.Type, claim.TargetItemID, claim.TargetRevision)
		if _, exists := seenClaims[key]; exists {
			return MemoryEvidenceCreateRequest{}, errors.New("duplicate memory evidence claim")
		}
		seenClaims[key] = struct{}{}
		claims[index] = claim
	}
	request.Sources = sources
	request.Claims = claims
	return request, nil
}

func validMemoryEvidenceSource(source MemoryEvidenceSourceInput) bool {
	switch source.Mode {
	case MemorySourceCopied:
		return validMemorySourceKind(source.Kind) && source.ProjectID == "" && source.ResourceID == "" && source.ResourceRevision == 0 && validSHA256Hex(source.ReferenceSHA256)
	case MemorySourceLive:
		if !validLiveMemorySourceKind(source.Kind) || !validOpaqueID(source.ProjectID) || !validOpaqueID(source.ResourceID) || source.ReferenceSHA256 != "" {
			return false
		}
		return source.Kind == MemorySourceMemory && source.ResourceRevision >= 1 || source.Kind != MemorySourceMemory && source.ResourceRevision == 0
	default:
		return false
	}
}

func validMemorySourceKind(kind MemorySourceKind) bool {
	switch kind {
	case MemorySourceMessage, MemorySourceAttachment, MemorySourceMemory, MemorySourceSession, MemorySourceImport, MemorySourceExternal:
		return true
	default:
		return false
	}
}

func validLiveMemorySourceKind(kind MemorySourceKind) bool {
	return kind == MemorySourceMessage || kind == MemorySourceAttachment || kind == MemorySourceMemory
}

func validMemoryEdgeType(edge MemoryEdgeType) bool {
	switch edge {
	case MemoryEdgeDerivedFrom, MemoryEdgeSupports, MemoryEdgeContradicts, MemoryEdgeSupersedes:
		return true
	default:
		return false
	}
}

func validSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func (request MemoryEvidenceGetRequest) validate() error {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.ProjectID) || !validOpaqueID(request.ItemID) {
		return errors.New("invalid memory evidence lookup")
	}
	return nil
}

// CreateMemoryEvidence atomically creates a bounded evidence revision and its provenance.
func (d *Database) CreateMemoryEvidence(ctx context.Context, raw MemoryEvidenceCreateRequest) (MemoryMutationResult, error) {
	request, err := raw.normalized()
	if err != nil {
		return MemoryMutationResult{}, err
	}
	body, _ := json.Marshal(request)
	tx, err := beginMutation(ctx, d.db)
	if err != nil {
		return MemoryMutationResult{}, mutationStartError(err, "memory evidence transaction cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	outcome, err := executeIdempotentTx(ctx, tx, IdempotencyRequest{PrincipalID: request.PrincipalID, Operation: "memory.evidence.create", Key: request.IdempotencyKey, Body: body}, func(control *ControlTx) (IdempotencyOutcome, error) {
		projectIDs := map[string]struct{}{request.ProjectID: {}}
		for _, source := range request.Sources {
			if source.Mode == MemorySourceLive {
				projectIDs[source.ProjectID] = struct{}{}
			}
		}
		if err := lockActiveEvidenceProjects(ctx, tx, projectIDs); err != nil {
			return IdempotencyOutcome{}, ErrNotFound
		}
		allowed, err := lockCapability(ctx, tx, request.PrincipalID, request.ProjectID, CapabilityMemoryWrite)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		if !allowed {
			return IdempotencyOutcome{}, ErrNotFound
		}
		if len(request.Claims) > 0 {
			allowed, err = lockCapability(ctx, tx, request.PrincipalID, request.ProjectID, CapabilityMemoryRead)
			if err != nil {
				return IdempotencyOutcome{}, err
			}
			if !allowed {
				return IdempotencyOutcome{}, ErrNotFound
			}
		}
		if err := guardMemoryDocument(ctx, tx, request.ProjectID, request.Document); err != nil {
			return IdempotencyOutcome{}, err
		}
		type sourceAuthority struct {
			projectID  string
			capability Capability
		}
		authorities := make(map[sourceAuthority]struct{})
		for _, source := range request.Sources {
			if source.Mode != MemorySourceLive {
				continue
			}
			capability := CapabilityMemoryRead
			switch source.Kind {
			case MemorySourceMessage:
				capability = CapabilityConversationReceive
			case MemorySourceAttachment:
				capability = CapabilityAttachmentDownload
			}
			authorities[sourceAuthority{source.ProjectID, capability}] = struct{}{}
		}
		orderedAuthorities := make([]sourceAuthority, 0, len(authorities))
		for authority := range authorities {
			orderedAuthorities = append(orderedAuthorities, authority)
		}
		sort.Slice(orderedAuthorities, func(i, j int) bool {
			if orderedAuthorities[i].projectID == orderedAuthorities[j].projectID {
				return orderedAuthorities[i].capability < orderedAuthorities[j].capability
			}
			return orderedAuthorities[i].projectID < orderedAuthorities[j].projectID
		})
		for _, authority := range orderedAuthorities {
			allowed, err := lockCapability(ctx, tx, request.PrincipalID, authority.projectID, authority.capability)
			if err != nil {
				return IdempotencyOutcome{}, err
			}
			if !allowed {
				return IdempotencyOutcome{}, ErrNotFound
			}
		}
		orderedLiveSources := make([]MemoryEvidenceSourceInput, 0, len(request.Sources))
		for _, source := range request.Sources {
			if source.Mode == MemorySourceLive {
				orderedLiveSources = append(orderedLiveSources, source)
			}
		}
		sort.Slice(orderedLiveSources, func(i, j int) bool {
			left := fmt.Sprintf("%s\x00%s\x00%s\x00%020d", orderedLiveSources[i].ProjectID, orderedLiveSources[i].Kind, orderedLiveSources[i].ResourceID, orderedLiveSources[i].ResourceRevision)
			right := fmt.Sprintf("%s\x00%s\x00%s\x00%020d", orderedLiveSources[j].ProjectID, orderedLiveSources[j].Kind, orderedLiveSources[j].ResourceID, orderedLiveSources[j].ResourceRevision)
			return left < right
		})
		for _, source := range orderedLiveSources {
			allowed, err := evidenceSourceLocked(ctx, tx, request.PrincipalID, source.Kind, source.ProjectID, source.ResourceID, source.ResourceRevision)
			if err != nil {
				return IdempotencyOutcome{}, err
			}
			if !allowed {
				return IdempotencyOutcome{}, ErrNotFound
			}
		}
		for _, claim := range request.Claims {
			var exists bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1 FROM brain.memory_items AS item
JOIN brain.scopes AS scope ON scope.id=item.scope_id
JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=$3
			WHERE item.id=$2 AND scope.project_id=$1
  AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)
)`, request.ProjectID, claim.TargetItemID, claim.TargetRevision).Scan(&exists); err != nil {
				return IdempotencyOutcome{}, errors.New("memory evidence claim could not be authorized")
			}
			if !exists {
				return IdempotencyOutcome{}, ErrNotFound
			}
		}
		scopeID, err := ensureMemoryScope(ctx, tx, request.ProjectID, request.PrincipalID)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		var itemID string
		err = tx.QueryRowContext(ctx, `INSERT INTO brain.memory_items (scope_id,kind,state,trust,logical_key,current_revision,created_by,layer)
VALUES ($1,$2,'active',$3,$4,1,$5,'evidence') RETURNING id::text`, scopeID, request.Kind, request.Trust, nullableMemoryKey(request.LogicalKey), request.PrincipalID).Scan(&itemID)
		if isSQLState(err, "23505") {
			return IdempotencyOutcome{}, ErrMemoryLogicalKeyConflict
		}
		if err != nil {
			return IdempotencyOutcome{}, errors.New("memory evidence item could not be created")
		}
		if err := insertMemoryRevision(ctx, tx, itemID, 1, request.Document, request.PrincipalID, MemoryChangeEvidenceCreate); err != nil {
			return IdempotencyOutcome{}, err
		}
		for ordinal, source := range request.Sources {
			var sourceProject, sourceResource any
			var sourceRevision any
			var referenceDigest any
			if source.Mode == MemorySourceLive {
				sourceProject, sourceResource = source.ProjectID, source.ResourceID
				if source.ResourceRevision > 0 {
					sourceRevision = source.ResourceRevision
				}
			} else {
				decoded, _ := hex.DecodeString(source.ReferenceSHA256)
				referenceDigest = decoded
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_sources
(item_id,revision,ordinal,mode,kind,source_project_id,source_resource_id,source_revision,reference_sha256,created_by)
VALUES ($1,1,$2,$3,$4,$5,$6,$7,$8,$9)`, itemID, ordinal, source.Mode, source.Kind, sourceProject, sourceResource, sourceRevision, referenceDigest, request.PrincipalID); err != nil {
				return IdempotencyOutcome{}, errors.New("memory evidence source could not be recorded")
			}
		}
		for ordinal, claim := range request.Claims {
			if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_edges
(from_item_id,from_revision,ordinal,edge_type,to_item_id,to_revision,created_by)
VALUES ($1,1,$2,$3,$4,$5,$6)`, itemID, ordinal, claim.Type, claim.TargetItemID, claim.TargetRevision, request.PrincipalID); err != nil {
				return IdempotencyOutcome{}, errors.New("memory evidence claim could not be recorded")
			}
		}
		if err := recordMemorySecretScan(ctx, tx, request.ProjectID, itemID, 1, request.PrincipalID, "clear"); err != nil {
			return IdempotencyOutcome{}, err
		}
		state, err := commitMemoryChange(ctx, tx, control, request.PrincipalID, request.ProjectID, scopeID, itemID, 1, MemoryChangeEvidenceCreate, AuditMemoryEvidenceCreate)
		if err != nil {
			return IdempotencyOutcome{}, err
		}
		return memoryOutcome(MemoryMutationResult{ItemID: itemID, Revision: 1, ETag: memoryETag(itemID, 1), State: MemoryActive, ChangeSequence: state.ChangeSequence})
	})
	if err != nil {
		return MemoryMutationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return MemoryMutationResult{}, errors.New("memory evidence transaction could not commit")
	}
	return decodeMemoryOutcome(outcome)
}

func lockActiveEvidenceProjects(ctx context.Context, tx *sql.Tx, requested map[string]struct{}) error {
	ids := make([]string, 0, len(requested))
	for projectID := range requested {
		ids = append(ids, projectID)
	}
	sort.Strings(ids)
	rows, err := tx.QueryContext(ctx, `SELECT id::text,merged_into::text FROM relay.projects WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, ids)
	if err != nil {
		return errors.New("memory evidence projects could not be locked")
	}
	defer func() { _ = rows.Close() }()
	seen := 0
	for rows.Next() {
		var projectID string
		var mergedInto sql.NullString
		if err := rows.Scan(&projectID, &mergedInto); err != nil || mergedInto.Valid {
			return ErrNotFound
		}
		seen++
	}
	if err := rows.Close(); err != nil {
		return errors.New("memory evidence projects could not be locked")
	}
	if seen != len(ids) {
		return ErrNotFound
	}
	return nil
}

// GetMemoryEvidence returns evidence only when the target is readable, redacting each live source independently.
func (d *Database) GetMemoryEvidence(ctx context.Context, request MemoryEvidenceGetRequest) (MemoryEvidence, error) {
	if err := request.validate(); err != nil {
		return MemoryEvidence{}, err
	}
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return MemoryEvidence{}, errors.New("memory evidence snapshot cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := resolveCanonicalActiveProject(ctx, tx, request.ProjectID)
	if err != nil {
		return MemoryEvidence{}, ErrNotFound
	}
	allowed, err := hasCapability(ctx, tx, request.PrincipalID, projectID, CapabilityMemoryRead)
	if err != nil {
		return MemoryEvidence{}, err
	}
	if !allowed {
		return MemoryEvidence{}, ErrNotFound
	}
	var result MemoryEvidence
	var logicalKey sql.NullString
	var document, contentHash []byte
	err = tx.QueryRowContext(ctx, `SELECT item.id::text,scope.id::text,scope.project_id::text,item.logical_key,item.kind,item.state,item.trust,item.layer,
item.current_revision,revision.document::text,revision.content_sha256,revision.author_principal_id::text,item.created_at,revision.created_at,
COALESCE((SELECT max(change.change_sequence) FROM brain.memory_changes AS change
 WHERE change.scope_id=scope.id AND change.item_id=item.id AND change.revision=item.current_revision
 AND change.timeline_id=(SELECT timeline_id FROM jobs.server_state WHERE singleton)),0)
FROM brain.memory_items AS item
JOIN brain.scopes AS scope ON scope.id=item.scope_id
JOIN brain.memory_revisions AS revision ON revision.item_id=item.id AND revision.revision=item.current_revision
WHERE item.id=$1 AND scope.project_id=$2 AND item.layer='evidence'
AND NOT EXISTS (SELECT 1 FROM brain.memory_quarantines AS quarantine WHERE quarantine.item_id=item.id AND quarantine.released_at IS NULL)`, request.ItemID, projectID).Scan(
		&result.Item.ItemID, &result.Item.ScopeID, &result.Item.ProjectID, &logicalKey, &result.Item.Kind, &result.Item.State, &result.Item.Trust, &result.Item.Layer,
		&result.Item.Revision, &document, &contentHash, &result.Item.AuthorID, &result.Item.CreatedAt, &result.Item.RevisionAt, &result.Item.ChangeSequence)
	if errors.Is(err, sql.ErrNoRows) {
		return MemoryEvidence{}, ErrNotFound
	}
	digest := sha256.Sum256(document)
	if err != nil || len(contentHash) != sha256.Size || !bytes.Equal(digest[:], contentHash) {
		return MemoryEvidence{}, errors.New("memory evidence is unavailable")
	}
	result.Item.LogicalKey = logicalKey.String
	result.Item.Document = append(json.RawMessage(nil), document...)
	result.Item.ContentSHA256 = hex.EncodeToString(contentHash)
	result.Item.ETag = memoryETag(result.Item.ItemID, result.Item.Revision)
	rows, err := tx.QueryContext(ctx, `SELECT id::text,ordinal,mode,kind,source_project_id::text,source_resource_id::text,source_revision,reference_sha256
FROM brain.memory_sources WHERE item_id=$1 AND revision=$2 ORDER BY ordinal`, request.ItemID, result.Item.Revision)
	if err != nil {
		return MemoryEvidence{}, errors.New("memory evidence sources are unavailable")
	}
	type storedEvidenceSource struct {
		source                MemoryEvidenceSource
		projectID, resourceID string
		resourceRevision      int64
	}
	storedSources := make([]storedEvidenceSource, 0, maxMemoryEvidenceSources)
	for rows.Next() {
		var stored storedEvidenceSource
		var sourceProject, sourceResource sql.NullString
		var sourceRevision sql.NullInt64
		var reference []byte
		if err := rows.Scan(&stored.source.SourceID, &stored.source.Ordinal, &stored.source.Mode, &stored.source.Kind, &sourceProject, &sourceResource, &sourceRevision, &reference); err != nil {
			_ = rows.Close()
			return MemoryEvidence{}, errors.New("memory evidence source is malformed")
		}
		if stored.source.Mode == MemorySourceCopied {
			stored.source.ReferenceSHA256 = hex.EncodeToString(reference)
		} else {
			stored.projectID, stored.resourceID, stored.resourceRevision = sourceProject.String, sourceResource.String, sourceRevision.Int64
		}
		storedSources = append(storedSources, stored)
	}
	if err := rows.Close(); err != nil {
		return MemoryEvidence{}, errors.New("memory evidence sources are unavailable")
	}
	for _, stored := range storedSources {
		source := stored.source
		if source.Mode == MemorySourceLive {
			authorized, authErr := evidenceSourceAuthorized(ctx, tx, request.PrincipalID, source.Kind, stored.projectID, stored.resourceID, stored.resourceRevision)
			if authErr != nil {
				return MemoryEvidence{}, authErr
			}
			if authorized {
				source.ProjectID, source.ResourceID, source.ResourceRevision = stored.projectID, stored.resourceID, stored.resourceRevision
			} else {
				source.Kind, source.Redacted = "", true
			}
		}
		result.Sources = append(result.Sources, source)
	}
	edgeRows, err := tx.QueryContext(ctx, `SELECT id::text,ordinal,edge_type,to_item_id::text,to_revision,created_at
FROM brain.memory_edges WHERE from_item_id=$1 AND from_revision=$2 ORDER BY ordinal LIMIT $3`, request.ItemID, result.Item.Revision, maxMemoryEvidenceClaims+1)
	if err != nil {
		return MemoryEvidence{}, errors.New("memory evidence claims are unavailable")
	}
	for edgeRows.Next() {
		var claim MemoryEvidenceClaim
		if err := edgeRows.Scan(&claim.EdgeID, &claim.Ordinal, &claim.Type, &claim.TargetItemID, &claim.TargetRevision, &claim.CreatedAt); err != nil {
			_ = edgeRows.Close()
			return MemoryEvidence{}, errors.New("memory evidence claim is malformed")
		}
		result.Claims = append(result.Claims, claim)
		if len(result.Claims) > maxMemoryEvidenceClaims {
			_ = edgeRows.Close()
			return MemoryEvidence{}, errors.New("memory evidence claims exceed the supported bound")
		}
	}
	if err := edgeRows.Close(); err != nil {
		return MemoryEvidence{}, errors.New("memory evidence claims are unavailable")
	}
	if result.Sources == nil {
		result.Sources = []MemoryEvidenceSource{}
	}
	if result.Claims == nil {
		result.Claims = []MemoryEvidenceClaim{}
	}
	if err := tx.Commit(); err != nil {
		return MemoryEvidence{}, errors.New("memory evidence snapshot cannot commit")
	}
	return result, nil
}

func evidenceSourceAuthorized(ctx context.Context, q queryer, principalID string, kind MemorySourceKind, projectID, resourceID string, revision int64) (bool, error) {
	var nullableRevision any
	if revision > 0 {
		nullableRevision = revision
	}
	var allowed bool
	if err := q.QueryRowContext(ctx, `SELECT brain.authorize_evidence_source($1,$2,$3,$4,$5)`, principalID, kind, projectID, resourceID, nullableRevision).Scan(&allowed); err != nil {
		return false, errors.New("memory evidence source authorization is unavailable")
	}
	return allowed, nil
}

func evidenceSourceLocked(ctx context.Context, q queryer, principalID string, kind MemorySourceKind, projectID, resourceID string, revision int64) (bool, error) {
	var nullableRevision any
	if revision > 0 {
		nullableRevision = revision
	}
	var allowed bool
	if err := q.QueryRowContext(ctx, `SELECT brain.lock_evidence_source($1,$2,$3,$4,$5)`, principalID, kind, projectID, resourceID, nullableRevision).Scan(&allowed); err != nil {
		return false, errors.New("memory evidence source lock is unavailable")
	}
	return allowed, nil
}

func copyMemoryEvidenceProvenance(ctx context.Context, tx *sql.Tx, itemID string, fromRevision, toRevision int64, principalID string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_sources
(item_id,revision,ordinal,mode,kind,source_project_id,source_resource_id,source_revision,reference_sha256,created_by)
SELECT item_id,$3,ordinal,mode,kind,source_project_id,source_resource_id,source_revision,reference_sha256,$4
FROM brain.memory_sources WHERE item_id=$1 AND revision=$2`, itemID, fromRevision, toRevision, principalID); err != nil {
		return errors.New("memory evidence sources could not advance")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO brain.memory_edges
(from_item_id,from_revision,ordinal,edge_type,to_item_id,to_revision,created_by)
SELECT from_item_id,$3,ordinal,edge_type,to_item_id,to_revision,$4
FROM brain.memory_edges WHERE from_item_id=$1 AND from_revision=$2`, itemID, fromRevision, toRevision, principalID); err != nil {
		return errors.New("memory evidence claims could not advance")
	}
	return nil
}
