package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	maxAttachmentBytes            int64 = 16 << 30
	minAttachmentReservation            = 5 * time.Minute
	maxAttachmentReservation            = time.Hour
	minAttachmentClaim                  = 30 * time.Second
	maxAttachmentClaim                  = 10 * time.Minute
	minAttachmentGCClaim                = 30 * time.Second
	maxAttachmentGCClaim                = 10 * time.Minute
	maxAttachmentReconcileBatch         = 100
	attachmentGCAdvisoryKeyClass        = 1347768658
	attachmentGCAdvisoryKeyObject       = 1094927683
)

var attachmentMediaTypePattern = regexp.MustCompile(`^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$`)

var (
	// ErrAttachmentQuota reports a rejected reservation at a configured bound.
	ErrAttachmentQuota = errors.New("attachment quota is exhausted")
	// ErrAttachmentBusy reports an unexpired claim held by another attempt.
	ErrAttachmentBusy = errors.New("attachment upload is already active")
	// ErrAttachmentStale reports a claim or timeline that can no longer publish.
	ErrAttachmentStale = errors.New("attachment upload authority is stale")
)

// AttachmentState is the closed server-side publication lifecycle for M-10.
type AttachmentState string

const (
	// AttachmentReserved holds quota but has no visible immutable blob.
	AttachmentReserved AttachmentState = "reserved"
	// AttachmentReaping fences publication while hidden bytes are deleted.
	AttachmentReaping AttachmentState = "reaping"
	// AttachmentReady has an exact durable blob and backup-visible projection.
	AttachmentReady AttachmentState = "ready"
	// AttachmentCorrupt has been withdrawn from the READY projection.
	AttachmentCorrupt AttachmentState = "corrupt"
	// AttachmentExpired has released its reservation quota after byte cleanup.
	AttachmentExpired AttachmentState = "expired"
)

// AttachmentReservationRequest binds authority, immutable metadata, and one
// operation-specific idempotency key without including attachment bytes.
type AttachmentReservationRequest struct {
	PrincipalID    string
	ProjectID      string
	IdempotencyKey string
	SizeBytes      int64
	SHA256         [sha256.Size]byte
	DisplayName    string
	MediaType      string
	Lifetime       time.Duration
}

// Validate enforces the same portable bounds as schema v10 before database
// access. Display metadata never becomes a filesystem path.
func (request AttachmentReservationRequest) Validate() error {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.ProjectID) || !validOpaqueID(request.IdempotencyKey) ||
		request.SizeBytes < 1 || request.SizeBytes > maxAttachmentBytes ||
		request.Lifetime < minAttachmentReservation || request.Lifetime > maxAttachmentReservation ||
		!validAttachmentDisplayName(request.DisplayName) || !attachmentMediaTypePattern.MatchString(request.MediaType) {
		return errors.New("invalid attachment reservation request")
	}
	return nil
}

// AttachmentReservation is the content-free durable RESERVED record.
type AttachmentReservation struct {
	ArtifactID        string
	ProjectID         string
	PrincipalID       string
	TimelineID        string
	SizeBytes         int64
	SHA256            [sha256.Size]byte
	DisplayName       string
	MediaType         string
	State             AttachmentState
	AttemptGeneration int64
	ExpiresAt         time.Time
	ReadyAt           time.Time
}

// AttachmentClaim fences one bounded filesystem publication attempt.
type AttachmentClaim struct {
	ArtifactID        string
	ProjectID         string
	PrincipalID       string
	TimelineID        string
	SizeBytes         int64
	SHA256            [sha256.Size]byte
	State             AttachmentState
	AttemptGeneration int64
	ClaimToken        string
	ClaimUntil        time.Time
	ExpiresAt         time.Time
}

// AttachmentArtifact is the exact READY projection committed after durable
// filesystem publication and current authorization revalidation.
type AttachmentArtifact struct {
	ArtifactID  string
	ProjectID   string
	StoragePath string
	SizeBytes   int64
	SHA256      [sha256.Size]byte
	State       AttachmentState
	ReadyAt     time.Time
}

// AttachmentDownloadRequest is the generation-fenced principal authority for
// one recipient-snapshot download authorization.
type AttachmentDownloadRequest struct {
	PrincipalID          string
	CredentialLookupID   string
	CredentialGeneration int64
	ArtifactID           string
}

// Validate rejects labels and incomplete credential-generation tuples before
// an artifact lookup can become an existence oracle.
func (request AttachmentDownloadRequest) Validate() error {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.CredentialLookupID) || request.CredentialGeneration < 1 || !validOpaqueID(request.ArtifactID) {
		return errors.New("invalid attachment download request")
	}
	return nil
}

// AttachmentDownload is the exact authorized immutable file declaration.
type AttachmentDownload struct {
	ArtifactID  string
	ProjectID   string
	StoragePath string
	SizeBytes   int64
	SHA256      [sha256.Size]byte
	DisplayName string
	MediaType   string
	ReadyAt     time.Time
}

// AttachmentDeleteRequest binds one current device principal to an
// operation-specific idempotency key. The artifact's project is always read
// from authoritative metadata rather than accepted from the caller.
type AttachmentDeleteRequest struct {
	PrincipalID          string
	CredentialLookupID   string
	CredentialGeneration int64
	ArtifactID           string
	IdempotencyKey       string
}

// Validate rejects incomplete current-device authority and friendly labels
// before a lookup can reveal attachment existence.
func (request AttachmentDeleteRequest) Validate() error {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.CredentialLookupID) || request.CredentialGeneration < 1 ||
		!validOpaqueID(request.ArtifactID) || !validOpaqueID(request.IdempotencyKey) {
		return errors.New("invalid attachment delete request")
	}
	return nil
}

// AttachmentDeletionState is the durable physical-removal lifecycle. It is
// separate from upload publication state so a content-free tombstone survives
// final removal of the publication row.
type AttachmentDeletionState string

const (
	// AttachmentTombstoned is hidden while its immutable bytes remain charged
	// through the backup/restore safety window.
	AttachmentTombstoned AttachmentDeletionState = "tombstoned"
	// AttachmentGCClaimed is owned by one generation/token/lease worker.
	AttachmentGCClaimed AttachmentDeletionState = "gc_claimed"
	// AttachmentDeleted records completed physical removal and quota release.
	AttachmentDeleted AttachmentDeletionState = "deleted"
)

// AttachmentDeletion is the hidden, backup-window-fenced deletion record.
type AttachmentDeletion struct {
	ArtifactID   string
	ProjectID    string
	StoragePath  string
	SizeBytes    int64
	SHA256       [sha256.Size]byte
	State        AttachmentDeletionState
	GCGeneration int64
	GCAfter      time.Time
	DeletedAt    time.Time
}

// AttachmentGCClaim fences one physical removal worker and contains only
// server-derived immutable paths and integrity metadata.
type AttachmentGCClaim struct {
	AttachmentDeletion
	GCToken      string
	GCLeaseUntil time.Time
}

// AttachmentPublishRequest binds completion to one database claim and the
// exact immutable blob proven by the filesystem layer.
type AttachmentPublishRequest struct {
	PrincipalID          string
	CredentialLookupID   string
	CredentialGeneration int64
	ArtifactID           string
	AttemptGeneration    int64
	ClaimToken           string
	StoragePath          string
	SizeBytes            int64
	SHA256               [sha256.Size]byte
}

// Validate rejects a publication that is not bound to its derived opaque path.
func (request AttachmentPublishRequest) Validate() error {
	if !validOpaqueID(request.PrincipalID) || !validOpaqueID(request.CredentialLookupID) || request.CredentialGeneration < 1 ||
		!validOpaqueID(request.ArtifactID) || !validOpaqueID(request.ClaimToken) ||
		request.AttemptGeneration < 1 || request.SizeBytes < 1 || request.SizeBytes > maxAttachmentBytes ||
		request.StoragePath != "ready/"+request.ArtifactID+".blob" {
		return errors.New("invalid attachment publication request")
	}
	return nil
}

// AttachmentReconcileCursor is a stable exclusive cursor over the bounded
// state/expiry/artifact ordering returned by schema v10.
type AttachmentReconcileCursor struct {
	State      AttachmentState
	ExpiresAt  time.Time
	ArtifactID string
}

// Validate requires either an empty cursor or one complete exclusive key.
func (cursor AttachmentReconcileCursor) Validate() error {
	empty := cursor.State == "" && cursor.ExpiresAt.IsZero() && cursor.ArtifactID == ""
	if empty {
		return nil
	}
	if !validAttachmentReconcileState(cursor.State) || cursor.ExpiresAt.IsZero() || !validOpaqueID(cursor.ArtifactID) {
		return errors.New("invalid attachment reconciliation cursor")
	}
	return nil
}

// AttachmentReconcileCandidate is content-free filesystem reconciliation
// metadata. It never grants download or recipient authority.
type AttachmentReconcileCandidate struct {
	ArtifactID        string
	ProjectID         string
	PrincipalID       string
	TimelineID        string
	SizeBytes         int64
	SHA256            [sha256.Size]byte
	State             AttachmentState
	AttemptGeneration int64
	CleanupToken      string
	ClaimUntil        time.Time
	ExpiresAt         time.Time
	StoragePath       string
	CurrentTimeline   bool
}

// ReserveAttachment authorizes and quota-reserves one idempotent upload.
func (d *Database) ReserveAttachment(ctx context.Context, request AttachmentReservationRequest) (AttachmentReservation, error) {
	if request.Validate() != nil {
		return AttachmentReservation{}, errors.New("invalid attachment reservation request")
	}
	body, err := json.Marshal(struct {
		ProjectID      string `json:"project_id"`
		SizeBytes      int64  `json:"size_bytes"`
		SHA256         string `json:"sha256"`
		DisplayName    string `json:"display_name"`
		MediaType      string `json:"media_type"`
		LifetimeMicros int64  `json:"lifetime_microseconds"`
	}{request.ProjectID, request.SizeBytes, hex.EncodeToString(request.SHA256[:]), request.DisplayName, request.MediaType, request.Lifetime.Microseconds()})
	if err != nil {
		return AttachmentReservation{}, errors.New("attachment reservation cannot be encoded")
	}
	requestHash := sha256.Sum256(body)
	row := d.db.QueryRowContext(ctx, `SELECT artifact_id::text,project_id::text,principal_id::text,timeline_id::text,size_bytes,sha256,display_name,media_type,state,attempt_generation,expires_at,ready_at
FROM attachment.reserve_upload($1,$2,$3,$4,$5,$6,$7,$8,$9::interval)`, request.PrincipalID, request.ProjectID, request.IdempotencyKey, requestHash[:], request.SizeBytes, hex.EncodeToString(request.SHA256[:]), request.DisplayName, request.MediaType, attachmentInterval(request.Lifetime))
	reservation, err := scanAttachmentReservation(row)
	if err != nil {
		return AttachmentReservation{}, attachmentStoreError(err, "attachment reservation failed")
	}
	return reservation, nil
}

// ClaimAttachmentUpload obtains one generation- and token-fenced stream claim.
func (d *Database) ClaimAttachmentUpload(ctx context.Context, principalID, artifactID string, lifetime time.Duration) (AttachmentClaim, error) {
	if !validOpaqueID(principalID) || !validOpaqueID(artifactID) || lifetime < minAttachmentClaim || lifetime > maxAttachmentClaim {
		return AttachmentClaim{}, errors.New("invalid attachment upload claim")
	}
	var claim AttachmentClaim
	var digestText string
	err := d.db.QueryRowContext(ctx, `SELECT artifact_id::text,project_id::text,principal_id::text,timeline_id::text,size_bytes,sha256,state,attempt_generation,claim_token::text,claim_until,expires_at
FROM attachment.claim_upload($1,$2,$3::interval)`, principalID, artifactID, attachmentInterval(lifetime)).Scan(
		&claim.ArtifactID, &claim.ProjectID, &claim.PrincipalID, &claim.TimelineID, &claim.SizeBytes,
		&digestText, &claim.State, &claim.AttemptGeneration, &claim.ClaimToken, &claim.ClaimUntil, &claim.ExpiresAt)
	if err != nil {
		return AttachmentClaim{}, attachmentStoreError(err, "attachment upload claim failed")
	}
	if !decodeAttachmentDigest(digestText, &claim.SHA256) || !validAttachmentState(claim.State) || !validOpaqueID(claim.ClaimToken) {
		return AttachmentClaim{}, errors.New("attachment upload claim is malformed")
	}
	return claim, nil
}

// PublishAttachment reauthorizes and conditionally commits an exact READY blob.
func (d *Database) PublishAttachment(ctx context.Context, request AttachmentPublishRequest) (AttachmentArtifact, error) {
	if request.Validate() != nil {
		return AttachmentArtifact{}, errors.New("invalid attachment publication request")
	}
	var artifact AttachmentArtifact
	var digestText string
	err := d.db.QueryRowContext(ctx, `SELECT artifact_id::text,project_id::text,storage_path,size_bytes,sha256,state,ready_at
FROM attachment.publish_upload($1,$2,$3,$4,$5,$6,$7,$8,$9)`, request.PrincipalID, request.CredentialLookupID, request.CredentialGeneration, request.ArtifactID, request.AttemptGeneration, request.ClaimToken, request.StoragePath, request.SizeBytes, hex.EncodeToString(request.SHA256[:])).Scan(
		&artifact.ArtifactID, &artifact.ProjectID, &artifact.StoragePath, &artifact.SizeBytes, &digestText, &artifact.State, &artifact.ReadyAt)
	if err != nil {
		return AttachmentArtifact{}, attachmentStoreError(err, "attachment publication failed")
	}
	if !decodeAttachmentDigest(digestText, &artifact.SHA256) || artifact.State != AttachmentReady || artifact.StoragePath != "ready/"+artifact.ArtifactID+".blob" {
		return AttachmentArtifact{}, errors.New("attachment publication result is malformed")
	}
	return artifact, nil
}

// AuthorizeAttachmentDownload applies current device, capability, immutable
// recipient-grant, READY, and manifest checks in one content-free routine.
func (d *Database) AuthorizeAttachmentDownload(ctx context.Context, request AttachmentDownloadRequest) (AttachmentDownload, error) {
	if request.Validate() != nil {
		return AttachmentDownload{}, errors.New("invalid attachment download request")
	}
	var download AttachmentDownload
	var digestText string
	err := d.db.QueryRowContext(ctx, `SELECT artifact_id::text,project_id::text,storage_path,size_bytes,sha256,display_name,media_type,ready_at
FROM attachment.authorize_download($1,$2,$3,$4)`, request.PrincipalID, request.CredentialLookupID, request.CredentialGeneration, request.ArtifactID).Scan(
		&download.ArtifactID, &download.ProjectID, &download.StoragePath, &download.SizeBytes,
		&digestText, &download.DisplayName, &download.MediaType, &download.ReadyAt)
	if err != nil {
		return AttachmentDownload{}, attachmentStoreError(err, "attachment download is unavailable")
	}
	if !decodeAttachmentDigest(digestText, &download.SHA256) || download.ArtifactID != request.ArtifactID || download.StoragePath != "ready/"+download.ArtifactID+".blob" || download.SizeBytes < 1 || download.SizeBytes > maxAttachmentBytes || !validAttachmentDisplayName(download.DisplayName) || !attachmentMediaTypePattern.MatchString(download.MediaType) {
		return AttachmentDownload{}, errors.New("attachment download result is malformed")
	}
	return download, nil
}

// DeleteAttachment reauthorizes one current device operation and commits the
// visibility tombstone before any filesystem mutation is attempted.
func (d *Database) DeleteAttachment(ctx context.Context, request AttachmentDeleteRequest) (AttachmentDeletion, error) {
	if request.Validate() != nil {
		return AttachmentDeletion{}, errors.New("invalid attachment delete request")
	}
	body, err := json.Marshal(struct {
		ArtifactID string `json:"artifact_id"`
	}{ArtifactID: request.ArtifactID})
	if err != nil {
		return AttachmentDeletion{}, errors.New("attachment delete request cannot be encoded")
	}
	requestHash := sha256.Sum256(body)
	row := d.db.QueryRowContext(ctx, `SELECT artifact_id::text,project_id::text,storage_path,size_bytes,sha256,state,gc_generation,gc_after,deleted_at
FROM attachment.tombstone_artifact($1,$2,$3,$4,$5,$6)`, request.PrincipalID, request.CredentialLookupID, request.CredentialGeneration, request.ArtifactID, request.IdempotencyKey, requestHash[:])
	deletion, err := scanAttachmentDeletion(row)
	if err != nil {
		return AttachmentDeletion{}, attachmentStoreError(err, "attachment delete failed")
	}
	return deletion, nil
}

// BeginAttachmentPhysicalGC holds a transaction-scoped shared advisory lock
// until its release function is called. Backup fence acquisition takes the
// matching exclusive lock before publishing its durable fence, so a permitted
// holder remains backup-exclusive across filesystem unlink and finalization.
func (d *Database) BeginAttachmentPhysicalGC(ctx context.Context) (func() error, bool, error) {
	if d == nil || d.attachmentPhysicalGCSlots == nil {
		return nil, false, errors.New("attachment physical GC is unavailable")
	}
	select {
	case d.attachmentPhysicalGCSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	releaseSlot := true
	defer func() {
		if releaseSlot {
			<-d.attachmentPhysicalGCSlots
		}
	}()
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return nil, false, attachmentStoreError(err, "attachment physical GC connection is unavailable")
	}
	tx, err := conn.BeginTx(context.WithoutCancel(ctx), nil)
	if err != nil {
		_ = conn.Close()
		return nil, false, attachmentStoreError(err, "attachment physical GC fence could not start")
	}
	var closeOnce sync.Once
	var closeErr error
	closeFence := func() error {
		closeOnce.Do(func() {
			rollbackErr := tx.Rollback()
			connectionErr := conn.Close()
			<-d.attachmentPhysicalGCSlots
			if rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				closeErr = rollbackErr
			} else {
				closeErr = connectionErr
			}
		})
		return closeErr
	}
	releaseSlot = false
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared($1::integer,$2::integer)`, attachmentGCAdvisoryKeyClass, attachmentGCAdvisoryKeyObject); err != nil {
		_ = closeFence()
		return nil, false, attachmentStoreError(err, "attachment physical GC fence could not be acquired")
	}
	var permitted bool
	if err := tx.QueryRowContext(ctx, `SELECT jobs.physical_blob_gc_permitted()`).Scan(&permitted); err != nil {
		_ = closeFence()
		return nil, false, attachmentStoreError(err, "attachment physical GC permission is unavailable")
	}
	if !permitted {
		if err := closeFence(); err != nil {
			return nil, false, attachmentStoreError(err, "attachment physical GC fence could not be released")
		}
		return nil, false, nil
	}
	return closeFence, true, nil
}

// ClaimAttachmentGC acquires one generation/token/lease fence only after the
// backup safety cutoff and while physical blob GC is currently permitted.
func (d *Database) ClaimAttachmentGC(ctx context.Context, artifactID string, lifetime time.Duration) (AttachmentGCClaim, bool, error) {
	if !validOpaqueID(artifactID) || lifetime < minAttachmentGCClaim || lifetime > maxAttachmentGCClaim {
		return AttachmentGCClaim{}, false, errors.New("invalid attachment GC claim")
	}
	var claim AttachmentGCClaim
	var digestText string
	var token sql.NullString
	var lease sql.NullTime
	var deletedAt sql.NullTime
	err := d.db.QueryRowContext(ctx, `SELECT artifact_id::text,project_id::text,storage_path,size_bytes,sha256,state,gc_generation,gc_token::text,gc_lease_until,gc_after,deleted_at
FROM attachment.claim_artifact_gc($1,$2::interval)`, artifactID, attachmentInterval(lifetime)).Scan(
		&claim.ArtifactID, &claim.ProjectID, &claim.StoragePath, &claim.SizeBytes, &digestText, &claim.State,
		&claim.GCGeneration, &token, &lease, &claim.GCAfter, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AttachmentGCClaim{}, false, nil
	}
	if err != nil {
		return AttachmentGCClaim{}, false, attachmentStoreError(err, "attachment GC claim failed")
	}
	if !token.Valid || !lease.Valid || deletedAt.Valid || !validOpaqueID(token.String) || !decodeAttachmentDigest(digestText, &claim.SHA256) || claim.State != AttachmentGCClaimed {
		return AttachmentGCClaim{}, false, errors.New("attachment GC claim is malformed")
	}
	claim.GCToken = token.String
	claim.GCLeaseUntil = lease.Time
	return claim, true, nil
}

// FinalizeAttachmentGC conditionally releases used quota exactly once after
// the claimed immutable final and stages have been durably removed.
func (d *Database) FinalizeAttachmentGC(ctx context.Context, artifactID string, generation int64, token string) (AttachmentDeletion, bool, error) {
	if !validOpaqueID(artifactID) || generation < 1 || !validOpaqueID(token) {
		return AttachmentDeletion{}, false, errors.New("invalid attachment GC finalization")
	}
	row := d.db.QueryRowContext(ctx, `SELECT artifact_id::text,project_id::text,storage_path,size_bytes,sha256,state,gc_generation,gc_after,deleted_at
FROM attachment.finalize_artifact_gc($1,$2,$3)`, artifactID, generation, token)
	deletion, err := scanAttachmentDeletion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AttachmentDeletion{}, false, nil
	}
	if err != nil {
		return AttachmentDeletion{}, false, attachmentStoreError(err, "attachment GC finalization failed")
	}
	return deletion, true, nil
}

// AttachmentOrphanGCAllowed rechecks authoritative database absence and the
// backup fence immediately before filesystem-only skew cleanup.
func (d *Database) AttachmentOrphanGCAllowed(ctx context.Context, artifactID string) (bool, error) {
	if !validOpaqueID(artifactID) {
		return false, errors.New("invalid attachment orphan query")
	}
	var allowed bool
	if err := d.db.QueryRowContext(ctx, `SELECT attachment.orphan_gc_allowed($1)`, artifactID).Scan(&allowed); err != nil {
		return false, attachmentStoreError(err, "attachment orphan authority is unavailable")
	}
	return allowed, nil
}

// BeginAttachmentReap fences an expired or restored-timeline reservation.
func (d *Database) BeginAttachmentReap(ctx context.Context, artifactID string) (string, bool, error) {
	if !validOpaqueID(artifactID) {
		return "", false, errors.New("invalid attachment reap request")
	}
	var token sql.NullString
	if err := d.db.QueryRowContext(ctx, `SELECT attachment.begin_reap_upload($1)::text`, artifactID).Scan(&token); err != nil {
		return "", false, attachmentStoreError(err, "attachment reap could not be fenced")
	}
	if !token.Valid {
		return "", false, nil
	}
	if !validOpaqueID(token.String) {
		return "", false, errors.New("attachment reap fence is malformed")
	}
	return token.String, true, nil
}

// ReleaseExpiredAttachment releases held quota after fenced byte deletion.
func (d *Database) ReleaseExpiredAttachment(ctx context.Context, artifactID, cleanupToken string) (bool, error) {
	if !validOpaqueID(artifactID) || !validOpaqueID(cleanupToken) {
		return false, errors.New("invalid expired attachment release")
	}
	var released bool
	if err := d.db.QueryRowContext(ctx, `SELECT attachment.release_expired_upload($1,$2)`, artifactID, cleanupToken).Scan(&released); err != nil {
		return false, attachmentStoreError(err, "expired attachment release failed")
	}
	return released, nil
}

// MarkAttachmentCorrupt withdraws a broken blob from the READY manifest.
func (d *Database) MarkAttachmentCorrupt(ctx context.Context, artifactID string) (bool, error) {
	if !validOpaqueID(artifactID) {
		return false, errors.New("invalid corrupt attachment marker")
	}
	var marked bool
	if err := d.db.QueryRowContext(ctx, `SELECT attachment.mark_corrupt($1)`, artifactID).Scan(&marked); err != nil {
		return false, attachmentStoreError(err, "attachment corruption marker failed")
	}
	return marked, nil
}

// AttachmentReconcileCandidates returns one bounded stable recovery page.
func (d *Database) AttachmentReconcileCandidates(ctx context.Context, cursor AttachmentReconcileCursor, limit int) ([]AttachmentReconcileCandidate, AttachmentReconcileCursor, error) {
	if cursor.Validate() != nil || limit < 1 || limit > maxAttachmentReconcileBatch {
		return nil, AttachmentReconcileCursor{}, errors.New("invalid attachment reconciliation request")
	}
	var afterState, afterArtifact any
	var afterExpires any
	if cursor.State != "" {
		afterState, afterExpires, afterArtifact = cursor.State, cursor.ExpiresAt, cursor.ArtifactID
	}
	rows, err := d.db.QueryContext(ctx, `SELECT artifact_id::text,project_id::text,principal_id::text,timeline_id::text,size_bytes,sha256,state,attempt_generation,cleanup_token::text,claim_until,expires_at,storage_path,current_timeline
FROM attachment.reconcile_candidates($1,$2,$3,$4)`, afterState, afterExpires, afterArtifact, limit)
	if err != nil {
		return nil, AttachmentReconcileCursor{}, attachmentStoreError(err, "attachment reconciliation query failed")
	}
	defer func() { _ = rows.Close() }()
	candidates := make([]AttachmentReconcileCandidate, 0, limit)
	next := cursor
	for rows.Next() {
		var candidate AttachmentReconcileCandidate
		var digestText string
		var cleanupToken sql.NullString
		var claimUntil sql.NullTime
		var storagePath sql.NullString
		if err := rows.Scan(&candidate.ArtifactID, &candidate.ProjectID, &candidate.PrincipalID, &candidate.TimelineID,
			&candidate.SizeBytes, &digestText, &candidate.State, &candidate.AttemptGeneration, &cleanupToken, &claimUntil,
			&candidate.ExpiresAt, &storagePath, &candidate.CurrentTimeline); err != nil {
			return nil, AttachmentReconcileCursor{}, errors.New("attachment reconciliation result is malformed")
		}
		if !decodeAttachmentDigest(digestText, &candidate.SHA256) || !validAttachmentReconcileState(candidate.State) {
			return nil, AttachmentReconcileCursor{}, errors.New("attachment reconciliation result is malformed")
		}
		if claimUntil.Valid {
			candidate.ClaimUntil = claimUntil.Time
		}
		if cleanupToken.Valid {
			if !validOpaqueID(cleanupToken.String) || candidate.State != AttachmentReaping {
				return nil, AttachmentReconcileCursor{}, errors.New("attachment reconciliation result is malformed")
			}
			candidate.CleanupToken = cleanupToken.String
		} else if candidate.State == AttachmentReaping {
			return nil, AttachmentReconcileCursor{}, errors.New("attachment reconciliation result is malformed")
		}
		if storagePath.Valid {
			candidate.StoragePath = storagePath.String
		}
		candidates = append(candidates, candidate)
		next = AttachmentReconcileCursor{State: candidate.State, ExpiresAt: candidate.ExpiresAt, ArtifactID: candidate.ArtifactID}
	}
	if err := rows.Err(); err != nil {
		return nil, AttachmentReconcileCursor{}, errors.New("attachment reconciliation query failed")
	}
	return candidates, next, nil
}

// ProjectHasAttachmentRecords authorizes an administer-scoped merge fence read.
func (d *Database) ProjectHasAttachmentRecords(ctx context.Context, principalID, projectID string) (bool, error) {
	if !validOpaqueID(principalID) || !validOpaqueID(projectID) {
		return false, errors.New("invalid attachment project query")
	}
	var found bool
	if err := d.db.QueryRowContext(ctx, `SELECT attachment.project_has_records($1,$2)`, principalID, projectID).Scan(&found); err != nil {
		return false, attachmentStoreError(err, "attachment project state is unavailable")
	}
	if found {
		return true, nil
	}
	var recipientFenceAvailable bool
	if err := d.db.QueryRowContext(ctx, `SELECT to_regprocedure('attachment.project_has_recipient_records(uuid,uuid)') IS NOT NULL`).Scan(&recipientFenceAvailable); err != nil {
		return false, errors.New("attachment recipient project state is unavailable")
	}
	if recipientFenceAvailable {
		if err := d.db.QueryRowContext(ctx, `SELECT attachment.project_has_recipient_records($1,$2)`, principalID, projectID).Scan(&found); err != nil {
			return false, attachmentStoreError(err, "attachment recipient project state is unavailable")
		}
	}
	return found, nil
}

type attachmentReservationScanner interface {
	Scan(...any) error
}

func scanAttachmentDeletion(row attachmentReservationScanner) (AttachmentDeletion, error) {
	var deletion AttachmentDeletion
	var digestText string
	var deletedAt sql.NullTime
	if err := row.Scan(&deletion.ArtifactID, &deletion.ProjectID, &deletion.StoragePath, &deletion.SizeBytes,
		&digestText, &deletion.State, &deletion.GCGeneration, &deletion.GCAfter, &deletedAt); err != nil {
		return AttachmentDeletion{}, err
	}
	if !validOpaqueID(deletion.ArtifactID) || !validOpaqueID(deletion.ProjectID) ||
		deletion.StoragePath != "ready/"+deletion.ArtifactID+".blob" || deletion.SizeBytes < 1 || deletion.SizeBytes > maxAttachmentBytes ||
		!decodeAttachmentDigest(digestText, &deletion.SHA256) || !validAttachmentDeletionState(deletion.State) || deletion.GCGeneration < 0 || deletion.GCAfter.IsZero() {
		return AttachmentDeletion{}, errors.New("attachment deletion result is malformed")
	}
	if deletedAt.Valid {
		deletion.DeletedAt = deletedAt.Time
	}
	if (deletion.State == AttachmentDeleted) != deletedAt.Valid {
		return AttachmentDeletion{}, errors.New("attachment deletion result is malformed")
	}
	return deletion, nil
}

func scanAttachmentReservation(row attachmentReservationScanner) (AttachmentReservation, error) {
	var reservation AttachmentReservation
	var digestText string
	var readyAt sql.NullTime
	err := row.Scan(&reservation.ArtifactID, &reservation.ProjectID, &reservation.PrincipalID, &reservation.TimelineID,
		&reservation.SizeBytes, &digestText, &reservation.DisplayName, &reservation.MediaType, &reservation.State,
		&reservation.AttemptGeneration, &reservation.ExpiresAt, &readyAt)
	if err != nil {
		return AttachmentReservation{}, err
	}
	if readyAt.Valid {
		reservation.ReadyAt = readyAt.Time
	}
	if !decodeAttachmentDigest(digestText, &reservation.SHA256) || !validAttachmentState(reservation.State) {
		return AttachmentReservation{}, errors.New("attachment reservation result is malformed")
	}
	return reservation, nil
}

func attachmentStoreError(err error, fallback string) error {
	if isMaintenanceError(err) {
		return ErrMaintenance
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "42501":
			return ErrForbidden
		case "23505":
			return ErrIdempotencyConflict
		case "54000":
			return ErrAttachmentQuota
		case "55P03":
			return ErrAttachmentBusy
		case "55000":
			return ErrAttachmentStale
		}
	}
	return errors.New(fallback)
}

func decodeAttachmentDigest(value string, destination *[sha256.Size]byte) bool {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return false
	}
	copy(destination[:], decoded)
	return true
}

func attachmentInterval(value time.Duration) string {
	return strconv.FormatInt(value.Microseconds(), 10) + " microseconds"
}

func validAttachmentDisplayName(value string) bool {
	if !utf8.ValidString(value) || len(value) < 1 || len(value) > 1020 {
		return false
	}
	count := 0
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
		count++
	}
	return count >= 1 && count <= 255
}

func validAttachmentState(state AttachmentState) bool {
	return state == AttachmentReserved || state == AttachmentReaping || state == AttachmentReady || state == AttachmentCorrupt || state == AttachmentExpired
}

func validAttachmentReconcileState(state AttachmentState) bool {
	return state == AttachmentReserved || state == AttachmentReaping || state == AttachmentReady || state == AttachmentCorrupt
}

func validAttachmentDeletionState(state AttachmentDeletionState) bool {
	return state == AttachmentTombstoned || state == AttachmentGCClaimed || state == AttachmentDeleted
}
