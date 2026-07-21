package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/relay"
)

const mailCutoverLockKey int64 = 0x50554e414d41494c

var mailCutoverDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MailCutoverPhase is the durable PostgreSQL-side authority staging phase.
type MailCutoverPhase string

const (
	// MailCutoverImporting fences application mail writes during staging.
	MailCutoverImporting MailCutoverPhase = "importing"
	// MailCutoverVerified records a fully verified but inactive epoch.
	MailCutoverVerified MailCutoverPhase = "verified"
	// MailCutoverActive records PostgreSQL as the published mail authority.
	MailCutoverActive MailCutoverPhase = "active"
	// MailCutoverAborted is the terminal pre-activation rollback outcome.
	MailCutoverAborted MailCutoverPhase = "aborted"
)

// MailCutoverRequest binds one typed SQLite manifest to one PostgreSQL target.
type MailCutoverRequest struct {
	EpochID           string
	SourceID          string
	TargetIdentity    string
	SourceFingerprint string
	Manifest          json.RawMessage
	ManifestSHA256    string
}

// Validate rejects incomplete, noncanonical, or internally inconsistent bindings.
func (r MailCutoverRequest) Validate() error {
	if _, err := canonicalMailCutoverManifest(r); err != nil {
		return errors.New("invalid mail cutover request")
	}
	return nil
}

func canonicalMailCutoverManifest(request MailCutoverRequest) ([]byte, error) {
	if uuid.Validate(request.EpochID) != nil || uuid.Validate(request.SourceID) != nil || !mailCutoverDigestPattern.MatchString(request.TargetIdentity) || !mailCutoverDigestPattern.MatchString(request.SourceFingerprint) || !mailCutoverDigestPattern.MatchString(request.ManifestSHA256) || len(request.Manifest) == 0 || len(request.Manifest) > 8192 {
		return nil, errors.New("invalid mail cutover request")
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Manifest))
	decoder.DisallowUnknownFields()
	var manifest relay.MigrationSourceManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, errors.New("invalid mail cutover manifest")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid mail cutover manifest")
	}
	counts := []int64{manifest.Counts.Endpoints, manifest.Counts.Conversations, manifest.Counts.Memberships, manifest.Counts.Messages, manifest.Counts.Deliveries, manifest.Counts.RecipientCursors, manifest.Counts.MessageIdempotency, manifest.Counts.ConversationIdempotency, manifest.Counts.RequestNonces}
	hashes := []string{manifest.TableSHA256.Endpoints, manifest.TableSHA256.Conversations, manifest.TableSHA256.Memberships, manifest.TableSHA256.Messages, manifest.TableSHA256.Deliveries, manifest.TableSHA256.RecipientCursors, manifest.TableSHA256.MessageIdempotency, manifest.TableSHA256.ConversationIdempotency, manifest.TableSHA256.RequestNonces}
	if manifest.Version != 1 || manifest.SourceID != request.SourceID || manifest.Phase != relay.MigrationSourcePrepared || manifest.EpochID != request.EpochID || manifest.TargetIdentity != request.TargetIdentity || manifest.Fingerprint != request.SourceFingerprint {
		return nil, errors.New("mail cutover manifest binding does not match")
	}
	for _, count := range counts {
		if count < 0 {
			return nil, errors.New("mail cutover manifest count is invalid")
		}
	}
	for _, hash := range hashes {
		if !mailCutoverDigestPattern.MatchString(hash) {
			return nil, errors.New("mail cutover manifest hash is invalid")
		}
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || len(canonical) > 8192 {
		return nil, errors.New("mail cutover manifest is too large")
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != request.ManifestSHA256 {
		return nil, errors.New("mail cutover manifest digest does not match")
	}
	return canonical, nil
}

// MailCutoverEpoch is the owner-side durable view of one cutover attempt.
type MailCutoverEpoch struct {
	MailCutoverRequest
	Phase       MailCutoverPhase
	CreatedAt   time.Time
	UpdatedAt   time.Time
	VerifiedAt  sql.NullTime
	ActivatedAt sql.NullTime
	AbortedAt   sql.NullTime
}

// BeginMailCutover drains application writers and creates one dark import epoch.
func (a *Administration) BeginMailCutover(ctx context.Context, actorPrincipalID string, request MailCutoverRequest) (MailCutoverEpoch, error) {
	if !validOpaqueID(actorPrincipalID) || request.Validate() != nil {
		return MailCutoverEpoch{}, errors.New("invalid mail cutover request")
	}
	canonicalManifest, err := canonicalMailCutoverManifest(request)
	if err != nil {
		return MailCutoverEpoch{}, errors.New("invalid mail cutover request")
	}
	request.Manifest = canonicalManifest
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := guardMutation(ctx, tx); err != nil {
		return MailCutoverEpoch{}, err
	}
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return MailCutoverEpoch{}, errors.New("mail cutover is not authorized")
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, mailCutoverLockKey); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover cannot be serialized")
	}
	identity, err := databaseIdentity(ctx, tx)
	if err != nil || identity != request.TargetIdentity {
		return MailCutoverEpoch{}, errors.New("mail cutover target identity does not match")
	}
	var existing MailCutoverEpoch
	err = scanMailCutover(tx.QueryRowContext(ctx, mailCutoverSelect+` WHERE epoch_id=$1`, request.EpochID), &existing)
	if err == nil {
		if !sameMailCutoverRequest(existing.MailCutoverRequest, request) {
			return MailCutoverEpoch{}, ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return MailCutoverEpoch{}, errors.New("mail cutover retry cannot commit")
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return MailCutoverEpoch{}, errors.New("mail cutover state is unavailable")
	}
	var rows int64
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM relay.mail_endpoints)+(SELECT count(*) FROM relay.mail_conversations)+(SELECT count(*) FROM relay.mail_memberships)+(SELECT count(*) FROM relay.mail_messages)+(SELECT count(*) FROM relay.mail_deliveries)+(SELECT count(*) FROM relay.mail_recipient_cursors)+(SELECT count(*) FROM relay.mail_message_idempotency)+(SELECT count(*) FROM relay.mail_conversation_idempotency)+(SELECT count(*) FROM relay.mail_request_nonces)`).Scan(&rows); err != nil || rows != 0 {
		return MailCutoverEpoch{}, errors.New("mail cutover target is not empty")
	}
	if err := scanMailCutover(tx.QueryRowContext(ctx, `INSERT INTO relay.mail_cutover_epochs(epoch_id,source_id,target_identity,source_fingerprint,source_manifest,manifest_sha256,phase) VALUES($1,$2,$3,$4,$5,$6,'importing') RETURNING epoch_id::text,source_id::text,target_identity,source_fingerprint,source_manifest,manifest_sha256,phase,created_at,updated_at,verified_at,activated_at,aborted_at`, request.EpochID, request.SourceID, request.TargetIdentity, request.SourceFingerprint, string(request.Manifest), request.ManifestSHA256), &existing); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover cannot be recorded")
	}
	if err := tx.Commit(); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover cannot commit")
	}
	return existing, nil
}

const mailCutoverSelect = `SELECT epoch_id::text,source_id::text,target_identity,source_fingerprint,source_manifest,manifest_sha256,phase,created_at,updated_at,verified_at,activated_at,aborted_at FROM relay.mail_cutover_epochs`

type mailCutoverRowScanner interface{ Scan(...any) error }

func scanMailCutover(row mailCutoverRowScanner, epoch *MailCutoverEpoch) error {
	var manifest string
	if err := row.Scan(&epoch.EpochID, &epoch.SourceID, &epoch.TargetIdentity, &epoch.SourceFingerprint, &manifest, &epoch.ManifestSHA256, &epoch.Phase, &epoch.CreatedAt, &epoch.UpdatedAt, &epoch.VerifiedAt, &epoch.ActivatedAt, &epoch.AbortedAt); err != nil {
		return err
	}
	epoch.Manifest = json.RawMessage(manifest)
	return nil
}

func sameMailCutoverRequest(left, right MailCutoverRequest) bool {
	return left.EpochID == right.EpochID && left.SourceID == right.SourceID && left.TargetIdentity == right.TargetIdentity && left.SourceFingerprint == right.SourceFingerprint && left.ManifestSHA256 == right.ManifestSHA256
}

// MailCutoverStatus returns one epoch to the installation owner.
func (a *Administration) MailCutoverStatus(ctx context.Context, actorPrincipalID, epochID string) (MailCutoverEpoch, error) {
	if !validOpaqueID(actorPrincipalID) || uuid.Validate(epochID) != nil {
		return MailCutoverEpoch{}, errors.New("invalid mail cutover status request")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover status is unavailable")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return MailCutoverEpoch{}, errors.New("mail cutover status is not authorized")
	}
	var epoch MailCutoverEpoch
	if err := scanMailCutover(tx.QueryRowContext(ctx, mailCutoverSelect+` WHERE epoch_id=$1`, epochID), &epoch); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover status is unavailable")
	}
	if err := tx.Commit(); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover status cannot commit")
	}
	return epoch, nil
}

// AbortMailCutover reopens PostgreSQL mail writes before activation.
func (a *Administration) AbortMailCutover(ctx context.Context, actorPrincipalID, epochID, sourceFingerprint string) error {
	if !validOpaqueID(actorPrincipalID) || uuid.Validate(epochID) != nil || !mailCutoverDigestPattern.MatchString(sourceFingerprint) {
		return errors.New("invalid mail cutover abort request")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("mail cutover abort cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := guardMutation(ctx, tx); err != nil {
		return err
	}
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return errors.New("mail cutover abort is not authorized")
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, mailCutoverLockKey); err != nil {
		return errors.New("mail cutover abort cannot be serialized")
	}
	var phase MailCutoverPhase
	var fingerprint string
	if err := tx.QueryRowContext(ctx, `SELECT phase,source_fingerprint FROM relay.mail_cutover_epochs WHERE epoch_id=$1 FOR UPDATE`, epochID).Scan(&phase, &fingerprint); err != nil {
		return errors.New("mail cutover epoch is unavailable")
	}
	if fingerprint != sourceFingerprint {
		return ErrIdempotencyConflict
	}
	if phase == MailCutoverActive {
		return errors.New("active mail cutover cannot be aborted")
	}
	if phase != MailCutoverAborted {
		if _, err := tx.ExecContext(ctx, `DELETE FROM relay.mail_cutover_staging WHERE epoch_id=$1`, epochID); err != nil {
			return errors.New("mail cutover cannot be aborted")
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM relay.mail_cutover_checkpoints WHERE epoch_id=$1`, epochID); err != nil {
			return errors.New("mail cutover cannot be aborted")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE relay.mail_cutover_epochs SET phase='aborted',updated_at=statement_timestamp(),verified_at=NULL,aborted_at=statement_timestamp() WHERE epoch_id=$1`, epochID); err != nil {
			return errors.New("mail cutover cannot be aborted")
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.New("mail cutover abort cannot commit")
	}
	return nil
}

func mailCutoverControlsAvailable(ctx context.Context, q queryer) (bool, error) {
	var available bool
	err := q.QueryRowContext(ctx, `
WITH objects AS (
    SELECT to_regclass('relay.mail_cutover_epochs') AS epochs_oid,
           to_regclass('relay.mail_cutover_staging') AS staging_oid,
           to_regclass('relay.mail_cutover_checkpoints') AS checkpoints_oid,
		   to_regclass('relay.mail_cutover_epochs_one_authority') AS active_index_oid,
           to_regprocedure('relay.guard_mail_mutation()') AS guard_oid
), expected_columns(table_oid,column_name,type_oid,required) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (epochs_oid,'epoch_id','uuid'::regtype,true),(epochs_oid,'source_id','uuid'::regtype,true),
        (epochs_oid,'target_identity','bpchar'::regtype,true),(epochs_oid,'source_fingerprint','bpchar'::regtype,true),
		(epochs_oid,'source_manifest','text'::regtype,true),(epochs_oid,'manifest_sha256','bpchar'::regtype,true),
        (epochs_oid,'phase','text'::regtype,true),(epochs_oid,'created_at','timestamptz'::regtype,true),
        (epochs_oid,'updated_at','timestamptz'::regtype,true),(epochs_oid,'verified_at','timestamptz'::regtype,false),
        (epochs_oid,'activated_at','timestamptz'::regtype,false),(epochs_oid,'aborted_at','timestamptz'::regtype,false),
        (staging_oid,'epoch_id','uuid'::regtype,true),(staging_oid,'table_name','text'::regtype,true),
        (staging_oid,'row_key','text'::regtype,true),(staging_oid,'payload','jsonb'::regtype,true),(staging_oid,'row_sha256','bpchar'::regtype,true),
        (checkpoints_oid,'epoch_id','uuid'::regtype,true),(checkpoints_oid,'table_name','text'::regtype,true),
        (checkpoints_oid,'last_key','text'::regtype,false),(checkpoints_oid,'row_count','bigint'::regtype,true),
        (checkpoints_oid,'rolling_sha256','bpchar'::regtype,true),(checkpoints_oid,'updated_at','timestamptz'::regtype,true)
    ) AS expected(table_oid,column_name,type_oid,required)
), actual_columns AS (
    SELECT attribute.attrelid,attribute.attname,attribute.atttypid,attribute.attnotnull
    FROM objects JOIN pg_attribute AS attribute
      ON attribute.attrelid=ANY(ARRAY[epochs_oid,staging_oid,checkpoints_oid])
     AND attribute.attnum>0 AND NOT attribute.attisdropped
), columns AS (
    SELECT NOT EXISTS (SELECT * FROM expected_columns EXCEPT SELECT * FROM actual_columns)
       AND NOT EXISTS (SELECT * FROM actual_columns EXCEPT SELECT * FROM expected_columns)
		AND (SELECT count(*)=5 FROM pg_attribute WHERE attrelid=ANY(ARRAY[epochs_oid,staging_oid,checkpoints_oid]) AND atttypid='bpchar'::regtype AND atttypmod=68)
       AND NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=ANY(ARRAY[epochs_oid,staging_oid,checkpoints_oid]) AND attnum>0 AND NOT attisdropped AND atttypid<>'bpchar'::regtype AND atttypmod<>-1) AS exact
    FROM objects
), ownership AS (
    SELECT count(*)=3 AND bool_and(pg_get_userbyid(relation.relowner)='punaro_owner' AND relation.relkind='r' AND relation.relpersistence='p' AND NOT relation.relrowsecurity AND NOT relation.relforcerowsecurity) AS exact
    FROM objects JOIN pg_class AS relation ON relation.oid=ANY(ARRAY[epochs_oid,staging_oid,checkpoints_oid])
), expected_defaults(table_oid,column_name,expression) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (epochs_oid,'created_at','statement_timestamp()'),(epochs_oid,'updated_at','statement_timestamp()'),
        (checkpoints_oid,'row_count','0'),(checkpoints_oid,'updated_at','statement_timestamp()')
    ) AS expected(table_oid,column_name,expression)
), actual_defaults AS (
    SELECT default_value.adrelid,attribute.attname,pg_get_expr(default_value.adbin,default_value.adrelid)
    FROM objects JOIN pg_attrdef AS default_value ON default_value.adrelid=ANY(ARRAY[epochs_oid,staging_oid,checkpoints_oid])
    JOIN pg_attribute AS attribute ON attribute.attrelid=default_value.adrelid AND attribute.attnum=default_value.adnum
), defaults AS (
    SELECT NOT EXISTS (SELECT * FROM expected_defaults EXCEPT SELECT * FROM actual_defaults)
       AND NOT EXISTS (SELECT * FROM actual_defaults EXCEPT SELECT * FROM expected_defaults) AS exact
), expected_constraints(table_oid,constraint_name,constraint_type,column_keys,foreign_table_oid,foreign_column_keys) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (epochs_oid,'mail_cutover_epochs_pkey','p'::"char",ARRAY[1]::smallint[],0::oid,'{}'::smallint[]),
        (epochs_oid,'mail_cutover_epochs_target_identity_check','c'::"char",ARRAY[3]::smallint[],0::oid,'{}'::smallint[]),
        (epochs_oid,'mail_cutover_epochs_source_fingerprint_check','c'::"char",ARRAY[4]::smallint[],0::oid,'{}'::smallint[]),
        (epochs_oid,'mail_cutover_epochs_source_manifest_check','c'::"char",ARRAY[5]::smallint[],0::oid,'{}'::smallint[]),
        (epochs_oid,'mail_cutover_epochs_manifest_sha256_check','c'::"char",ARRAY[6]::smallint[],0::oid,'{}'::smallint[]),
        (epochs_oid,'mail_cutover_epochs_phase_check','c'::"char",ARRAY[7]::smallint[],0::oid,'{}'::smallint[]),
        (epochs_oid,'mail_cutover_epochs_verified_at_check','c'::"char",ARRAY[7,10]::smallint[],0::oid,'{}'::smallint[]),
        (epochs_oid,'mail_cutover_epochs_activated_at_check','c'::"char",ARRAY[7,11]::smallint[],0::oid,'{}'::smallint[]),
        (epochs_oid,'mail_cutover_epochs_aborted_at_check','c'::"char",ARRAY[7,12]::smallint[],0::oid,'{}'::smallint[]),
        (staging_oid,'mail_cutover_staging_pkey','p'::"char",ARRAY[1,2,3]::smallint[],0::oid,'{}'::smallint[]),
        (staging_oid,'mail_cutover_staging_epoch_fkey','f'::"char",ARRAY[1]::smallint[],epochs_oid,ARRAY[1]::smallint[]),
        (staging_oid,'mail_cutover_staging_table_name_check','c'::"char",ARRAY[2]::smallint[],0::oid,'{}'::smallint[]),
        (staging_oid,'mail_cutover_staging_row_key_check','c'::"char",ARRAY[3]::smallint[],0::oid,'{}'::smallint[]),
        (staging_oid,'mail_cutover_staging_payload_check','c'::"char",ARRAY[4]::smallint[],0::oid,'{}'::smallint[]),
        (staging_oid,'mail_cutover_staging_row_sha256_check','c'::"char",ARRAY[5]::smallint[],0::oid,'{}'::smallint[]),
        (checkpoints_oid,'mail_cutover_checkpoints_pkey','p'::"char",ARRAY[1,2]::smallint[],0::oid,'{}'::smallint[]),
        (checkpoints_oid,'mail_cutover_checkpoints_epoch_fkey','f'::"char",ARRAY[1]::smallint[],epochs_oid,ARRAY[1]::smallint[]),
        (checkpoints_oid,'mail_cutover_checkpoints_table_name_check','c'::"char",ARRAY[2]::smallint[],0::oid,'{}'::smallint[]),
        (checkpoints_oid,'mail_cutover_checkpoints_last_key_check','c'::"char",ARRAY[3]::smallint[],0::oid,'{}'::smallint[]),
        (checkpoints_oid,'mail_cutover_checkpoints_row_count_check','c'::"char",ARRAY[4]::smallint[],0::oid,'{}'::smallint[]),
        (checkpoints_oid,'mail_cutover_checkpoints_rolling_sha256_check','c'::"char",ARRAY[5]::smallint[],0::oid,'{}'::smallint[])
    ) AS expected(table_oid,constraint_name,constraint_type,column_keys,foreign_table_oid,foreign_column_keys)
), actual_constraints AS (
    SELECT con.conrelid,con.conname,con.contype,con.conkey,con.confrelid,COALESCE(con.confkey,'{}'::smallint[])
    FROM objects JOIN pg_constraint AS con ON con.conrelid=ANY(ARRAY[epochs_oid,staging_oid,checkpoints_oid]) AND con.contype<>'n'
), constraints AS (
    SELECT NOT EXISTS (SELECT * FROM expected_constraints EXCEPT SELECT * FROM actual_constraints)
       AND NOT EXISTS (SELECT * FROM actual_constraints EXCEPT SELECT * FROM expected_constraints)
       AND (SELECT count(*)=21 AND bool_and(con.convalidated AND NOT con.condeferrable AND NOT con.condeferred
           AND (con.contype<>'f' OR (con.confupdtype='a' AND con.confdeltype='a' AND con.confmatchtype='s')))
           FROM objects JOIN pg_constraint AS con ON con.conrelid=ANY(ARRAY[epochs_oid,staging_oid,checkpoints_oid]) AND con.contype<>'n')
       AND (SELECT bool_and(CASE con.conname
           WHEN 'mail_cutover_epochs_target_identity_check' THEN pg_get_expr(con.conbin,con.conrelid)='(target_identity ~ ''^[0-9a-f]{64}$''::text)'
           WHEN 'mail_cutover_epochs_source_fingerprint_check' THEN pg_get_expr(con.conbin,con.conrelid)='(source_fingerprint ~ ''^[0-9a-f]{64}$''::text)'
		WHEN 'mail_cutover_epochs_source_manifest_check' THEN pg_get_expr(con.conbin,con.conrelid)='((jsonb_typeof((source_manifest)::jsonb) = ''object''::text) AND (octet_length(source_manifest) <= 8192))'
           WHEN 'mail_cutover_epochs_manifest_sha256_check' THEN pg_get_expr(con.conbin,con.conrelid)='(manifest_sha256 ~ ''^[0-9a-f]{64}$''::text)'
           WHEN 'mail_cutover_epochs_phase_check' THEN pg_get_expr(con.conbin,con.conrelid)='(phase = ANY (ARRAY[''importing''::text, ''verified''::text, ''active''::text, ''aborted''::text]))'
           WHEN 'mail_cutover_epochs_verified_at_check' THEN pg_get_expr(con.conbin,con.conrelid)='((phase = ANY (ARRAY[''verified''::text, ''active''::text])) = (verified_at IS NOT NULL))'
           WHEN 'mail_cutover_epochs_activated_at_check' THEN pg_get_expr(con.conbin,con.conrelid)='((phase = ''active''::text) = (activated_at IS NOT NULL))'
           WHEN 'mail_cutover_epochs_aborted_at_check' THEN pg_get_expr(con.conbin,con.conrelid)='((phase = ''aborted''::text) = (aborted_at IS NOT NULL))'
           WHEN 'mail_cutover_staging_table_name_check' THEN pg_get_expr(con.conbin,con.conrelid)='(table_name = ANY (ARRAY[''mail_endpoints''::text, ''mail_conversations''::text, ''mail_memberships''::text, ''mail_messages''::text, ''mail_deliveries''::text, ''mail_recipient_cursors''::text, ''mail_message_idempotency''::text, ''mail_conversation_idempotency''::text, ''mail_request_nonces''::text]))'
           WHEN 'mail_cutover_staging_row_key_check' THEN pg_get_expr(con.conbin,con.conrelid)='((octet_length(row_key) >= 1) AND (octet_length(row_key) <= 4096))'
           WHEN 'mail_cutover_staging_payload_check' THEN pg_get_expr(con.conbin,con.conrelid)='((jsonb_typeof(payload) = ''object''::text) AND (octet_length((payload)::text) <= 65536))'
           WHEN 'mail_cutover_staging_row_sha256_check' THEN pg_get_expr(con.conbin,con.conrelid)='(row_sha256 ~ ''^[0-9a-f]{64}$''::text)'
           WHEN 'mail_cutover_checkpoints_table_name_check' THEN pg_get_expr(con.conbin,con.conrelid)='(table_name = ANY (ARRAY[''mail_endpoints''::text, ''mail_conversations''::text, ''mail_memberships''::text, ''mail_messages''::text, ''mail_deliveries''::text, ''mail_recipient_cursors''::text, ''mail_message_idempotency''::text, ''mail_conversation_idempotency''::text, ''mail_request_nonces''::text]))'
           WHEN 'mail_cutover_checkpoints_last_key_check' THEN pg_get_expr(con.conbin,con.conrelid)='((last_key IS NULL) OR ((octet_length(last_key) >= 1) AND (octet_length(last_key) <= 4096)))'
           WHEN 'mail_cutover_checkpoints_row_count_check' THEN pg_get_expr(con.conbin,con.conrelid)='(row_count >= 0)'
           WHEN 'mail_cutover_checkpoints_rolling_sha256_check' THEN pg_get_expr(con.conbin,con.conrelid)='(rolling_sha256 ~ ''^[0-9a-f]{64}$''::text)'
           ELSE con.contype<>'c' END)
           FROM objects JOIN pg_constraint AS con ON con.conrelid=ANY(ARRAY[epochs_oid,staging_oid,checkpoints_oid])) AS exact
), active_index AS (
    SELECT count(*)=1 AND bool_and(index.indrelid=objects.epochs_oid AND index.indisunique AND index.indisvalid AND index.indisready AND index.indislive
       AND index.indnkeyatts=1 AND index.indnatts=1 AND pg_get_expr(index.indexprs,index.indrelid)='true'
		AND pg_get_expr(index.indpred,index.indrelid)='(phase = ANY (ARRAY[''importing''::text, ''verified''::text, ''active''::text]))'
       AND pg_get_userbyid(relation.relowner)='punaro_owner' AND access_method.amname='btree') AS exact
    FROM objects JOIN pg_index AS index ON index.indexrelid=objects.active_index_oid
	JOIN pg_class AS relation ON relation.oid=index.indexrelid
	JOIN pg_am AS access_method ON access_method.oid=relation.relam
), routine AS (
    SELECT count(*)=1 AND bool_and(pg_get_userbyid(proc.proowner)='punaro_owner' AND NOT proc.prosecdef AND proc.prokind='f'
       AND proc.provolatile='v' AND NOT proc.proretset AND proc.prorettype='trigger'::regtype AND proc.pronargs=0
		AND COALESCE(proc.proconfig=ARRAY['search_path=pg_catalog']::text[],false)
		AND md5(regexp_replace(proc.prosrc,'^\s+|\s+$','','g'))='a272f27743f82a8cfcf434328ed10180'
       AND NOT EXISTS (SELECT 1 FROM aclexplode(COALESCE(proc.proacl,acldefault('f',proc.proowner))) AS acl WHERE acl.grantee<>proc.proowner)) AS exact
    FROM objects JOIN pg_proc AS proc ON proc.oid=guard_oid
), expected_guards(table_oid,trigger_name) AS (
    SELECT expected.* FROM objects, LATERAL (VALUES
        (to_regclass('relay.mail_endpoints'),'mail_endpoints_mutation_guard'),
        (to_regclass('relay.mail_conversations'),'mail_conversations_mutation_guard'),
        (to_regclass('relay.mail_memberships'),'mail_memberships_mutation_guard'),
        (to_regclass('relay.mail_messages'),'mail_messages_mutation_guard'),
        (to_regclass('relay.mail_deliveries'),'mail_deliveries_mutation_guard'),
        (to_regclass('relay.mail_recipient_cursors'),'mail_recipient_cursors_mutation_guard'),
        (to_regclass('relay.mail_message_idempotency'),'mail_message_idempotency_mutation_guard'),
        (to_regclass('relay.mail_conversation_idempotency'),'mail_conversation_idempotency_mutation_guard'),
        (to_regclass('relay.mail_request_nonces'),'mail_request_nonces_mutation_guard')
    ) AS expected(table_oid,trigger_name)
), guards AS (
    SELECT count(*)=9 AND count(DISTINCT trigger.tgrelid)=9
       AND bool_and(trigger.tgfoid=objects.guard_oid AND trigger.tgenabled='O' AND NOT trigger.tgisinternal
       AND trigger.tgtype=30 AND trigger.tgconstraint=0 AND NOT trigger.tgdeferrable AND NOT trigger.tginitdeferred
       AND trigger.tgnargs=0 AND trigger.tgqual IS NULL AND trigger.tgnewtable IS NULL AND trigger.tgoldtable IS NULL AND trigger.tgattr::text='')
       AND (SELECT count(*) FROM pg_trigger AS inventory
			WHERE inventory.tgrelid IN (SELECT table_oid FROM expected_guards) AND NOT inventory.tgisinternal)=9
	   AND (SELECT count(*) FROM pg_trigger AS inventory
			WHERE inventory.tgrelid=ANY(ARRAY[to_regclass('relay.mail_cutover_epochs'),to_regclass('relay.mail_cutover_staging'),to_regclass('relay.mail_cutover_checkpoints')]) AND NOT inventory.tgisinternal)=0 AS exact
    FROM objects JOIN expected_guards ON true
    JOIN pg_trigger AS trigger ON trigger.tgrelid=expected_guards.table_oid AND trigger.tgname=expected_guards.trigger_name
), table_acl AS (
    SELECT has_table_privilege('punaro_app',epochs_oid,'SELECT')
       AND NOT has_table_privilege('punaro_app',epochs_oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND NOT has_any_column_privilege('punaro_app',epochs_oid,'INSERT,UPDATE,REFERENCES')
       AND NOT has_table_privilege('punaro_app',staging_oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND NOT has_any_column_privilege('punaro_app',staging_oid,'INSERT,UPDATE,REFERENCES')
       AND NOT has_table_privilege('punaro_app',checkpoints_oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       AND NOT has_any_column_privilege('punaro_app',checkpoints_oid,'INSERT,UPDATE,REFERENCES')
       AND NOT EXISTS (
           SELECT 1 FROM pg_class AS relation
           CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) AS acl
           WHERE relation.oid=ANY(ARRAY[epochs_oid,staging_oid,checkpoints_oid])
             AND acl.grantee NOT IN (relation.relowner,(SELECT oid FROM pg_roles WHERE rolname='punaro_app'))
       ) AS exact
    FROM objects
)
SELECT objects.epochs_oid IS NOT NULL AND objects.staging_oid IS NOT NULL AND objects.checkpoints_oid IS NOT NULL
   AND objects.active_index_oid IS NOT NULL AND objects.guard_oid IS NOT NULL
   AND ownership.exact AND columns.exact AND defaults.exact AND constraints.exact AND active_index.exact AND routine.exact AND guards.exact AND table_acl.exact
   AND NOT has_function_privilege('punaro_app',objects.guard_oid,'EXECUTE')
FROM objects,ownership,columns,defaults,constraints,active_index,routine,guards,table_acl`).Scan(&available)
	return available, err
}
