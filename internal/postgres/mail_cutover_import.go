package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/relay"
)

var mailCutoverTables = []string{
	"mail_endpoints", "mail_conversations", "mail_memberships", "mail_messages", "mail_deliveries",
	"mail_recipient_cursors", "mail_message_idempotency", "mail_conversation_idempotency", "mail_request_nonces",
}

var emptyMailCutoverDigest = func() string {
	digest := sha256.Sum256(nil)
	return hex.EncodeToString(digest[:])
}()

// MailCutoverBatch is one bounded, ordered source page and its exact resume
// binding. Done marks that the page reached the source table boundary.
type MailCutoverBatch struct {
	EpochID  string
	Table    string
	AfterKey string
	Rows     []relay.MigrationSourceRow
	Done     bool
}

// Validate rejects malformed, oversized, reordered, or cross-table pages.
func (b MailCutoverBatch) Validate() error {
	if uuid.Validate(b.EpochID) != nil || len(b.AfterKey) > 4096 || len(b.Rows) > 256 || len(b.Rows) == 0 && (!b.Done || b.AfterKey != "") {
		return errors.New("invalid mail cutover batch")
	}
	hasher, err := relay.NewMigrationTableHasher(b.Table)
	if err != nil {
		return errors.New("invalid mail cutover batch")
	}
	previous := b.AfterKey
	for _, row := range b.Rows {
		if previous != "" && row.Key <= previous {
			return errors.New("invalid mail cutover batch")
		}
		if err := hasher.Add(row); err != nil {
			return errors.New("invalid mail cutover batch")
		}
		previous = row.Key
	}
	return nil
}

// MailCutoverCheckpoint is the durable resume position for one source table.
type MailCutoverCheckpoint struct {
	EpochID       string
	Table         string
	LastKey       sql.NullString
	RowCount      int64
	RollingSHA256 string
	UpdatedAt     time.Time
}

// MailCutoverCheckpoint returns the current owner-authorized resume position.
// A missing table checkpoint is returned as the zero row with the empty digest.
func (a *Administration) MailCutoverCheckpoint(ctx context.Context, actorPrincipalID, epochID, table string) (MailCutoverCheckpoint, error) {
	if !validOpaqueID(actorPrincipalID) || uuid.Validate(epochID) != nil {
		return MailCutoverCheckpoint{}, errors.New("invalid mail cutover checkpoint request")
	}
	if _, err := relay.NewMigrationTableHasher(table); err != nil {
		return MailCutoverCheckpoint{}, errors.New("invalid mail cutover checkpoint request")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return MailCutoverCheckpoint{}, errors.New("mail cutover checkpoint is unavailable")
	}
	defer func() { _ = tx.Rollback() }()
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return MailCutoverCheckpoint{}, errors.New("mail cutover checkpoint is not authorized")
	}
	var phase MailCutoverPhase
	if err := tx.QueryRowContext(ctx, `SELECT phase FROM relay.mail_cutover_epochs WHERE epoch_id=$1`, epochID).Scan(&phase); err != nil || phase == MailCutoverAborted {
		return MailCutoverCheckpoint{}, errors.New("mail cutover checkpoint is unavailable")
	}
	checkpoint := MailCutoverCheckpoint{EpochID: epochID, Table: table, RollingSHA256: emptyMailCutoverDigest}
	err = tx.QueryRowContext(ctx, `SELECT last_key,row_count,rolling_sha256,updated_at FROM relay.mail_cutover_checkpoints WHERE epoch_id=$1 AND table_name=$2`, epochID, table).Scan(&checkpoint.LastKey, &checkpoint.RowCount, &checkpoint.RollingSHA256, &checkpoint.UpdatedAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return MailCutoverCheckpoint{}, errors.New("mail cutover checkpoint is unavailable")
	}
	if err := tx.Commit(); err != nil {
		return MailCutoverCheckpoint{}, errors.New("mail cutover checkpoint cannot commit")
	}
	return checkpoint, nil
}

func nextMailCutoverDigest(previous string, rows []relay.MigrationSourceRow) string {
	h := sha256.New()
	previousBytes, err := hex.DecodeString(previous)
	if err != nil || len(previousBytes) != sha256.Size {
		return ""
	}
	if len(rows) == 0 {
		return previous
	}
	_, _ = h.Write(previousBytes)
	for _, row := range rows {
		digest, err := hex.DecodeString(row.SHA256)
		if err != nil {
			return ""
		}
		_, _ = h.Write(digest)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// StageMailCutoverBatch durably appends one exact source page and advances its
// checkpoint. Retrying the immediately committed page is idempotent.
func (a *Administration) StageMailCutoverBatch(ctx context.Context, actorPrincipalID string, batch MailCutoverBatch) (MailCutoverCheckpoint, error) {
	if !validOpaqueID(actorPrincipalID) || batch.Validate() != nil {
		return MailCutoverCheckpoint{}, errors.New("invalid mail cutover batch")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return MailCutoverCheckpoint{}, errors.New("mail cutover batch cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := guardMutation(ctx, tx); err != nil {
		return MailCutoverCheckpoint{}, err
	}
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return MailCutoverCheckpoint{}, errors.New("mail cutover batch is not authorized")
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, mailCutoverLockKey); err != nil {
		return MailCutoverCheckpoint{}, errors.New("mail cutover batch cannot be serialized")
	}
	var phase MailCutoverPhase
	if err := tx.QueryRowContext(ctx, `SELECT phase FROM relay.mail_cutover_epochs WHERE epoch_id=$1 FOR UPDATE`, batch.EpochID).Scan(&phase); err != nil || phase != MailCutoverImporting {
		return MailCutoverCheckpoint{}, errors.New("mail cutover is not importing")
	}
	checkpoint := MailCutoverCheckpoint{EpochID: batch.EpochID, Table: batch.Table, RollingSHA256: emptyMailCutoverDigest}
	err = tx.QueryRowContext(ctx, `SELECT last_key,row_count,rolling_sha256,updated_at FROM relay.mail_cutover_checkpoints WHERE epoch_id=$1 AND table_name=$2 FOR UPDATE`, batch.EpochID, batch.Table).Scan(&checkpoint.LastKey, &checkpoint.RowCount, &checkpoint.RollingSHA256, &checkpoint.UpdatedAt)
	checkpointExists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return MailCutoverCheckpoint{}, errors.New("mail cutover checkpoint is unavailable")
	}
	currentKey := ""
	if checkpoint.LastKey.Valid {
		currentKey = checkpoint.LastKey.String
	}
	lastKey := batch.AfterKey
	if len(batch.Rows) != 0 {
		lastKey = batch.Rows[len(batch.Rows)-1].Key
	}
	if currentKey != batch.AfterKey {
		if currentKey != lastKey || len(batch.Rows) == 0 {
			return MailCutoverCheckpoint{}, ErrIdempotencyConflict
		}
		if err := verifyStagedMailRows(ctx, tx, batch); err != nil {
			return MailCutoverCheckpoint{}, err
		}
		if err := tx.Commit(); err != nil {
			return MailCutoverCheckpoint{}, errors.New("mail cutover batch retry cannot commit")
		}
		return checkpoint, nil
	}
	if checkpointExists && len(batch.Rows) == 0 {
		if err := tx.Commit(); err != nil {
			return MailCutoverCheckpoint{}, errors.New("mail cutover batch retry cannot commit")
		}
		return checkpoint, nil
	}
	for _, row := range batch.Rows {
		result, err := tx.ExecContext(ctx, `INSERT INTO relay.mail_cutover_staging(epoch_id,table_name,row_key,payload,row_sha256) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, batch.EpochID, batch.Table, row.Key, string(row.Payload), row.SHA256)
		if err != nil {
			return MailCutoverCheckpoint{}, errors.New("mail cutover row cannot be staged")
		}
		if count, err := result.RowsAffected(); err != nil || count != 1 {
			return MailCutoverCheckpoint{}, ErrIdempotencyConflict
		}
	}
	rolling := nextMailCutoverDigest(checkpoint.RollingSHA256, batch.Rows)
	if rolling == "" {
		return MailCutoverCheckpoint{}, errors.New("mail cutover checkpoint digest is invalid")
	}
	var nullableLast any
	if lastKey != "" {
		nullableLast = lastKey
	}
	if err := tx.QueryRowContext(ctx, `INSERT INTO relay.mail_cutover_checkpoints(epoch_id,table_name,last_key,row_count,rolling_sha256) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT(epoch_id,table_name) DO UPDATE SET last_key=excluded.last_key,row_count=excluded.row_count,rolling_sha256=excluded.rolling_sha256,updated_at=statement_timestamp()
		RETURNING last_key,row_count,rolling_sha256,updated_at`, batch.EpochID, batch.Table, nullableLast, checkpoint.RowCount+int64(len(batch.Rows)), rolling).Scan(&checkpoint.LastKey, &checkpoint.RowCount, &checkpoint.RollingSHA256, &checkpoint.UpdatedAt); err != nil {
		return MailCutoverCheckpoint{}, errors.New("mail cutover checkpoint cannot advance")
	}
	if err := tx.Commit(); err != nil {
		return MailCutoverCheckpoint{}, errors.New("mail cutover batch cannot commit")
	}
	return checkpoint, nil
}

func verifyStagedMailRows(ctx context.Context, tx *sql.Tx, batch MailCutoverBatch) error {
	for _, row := range batch.Rows {
		var exact bool
		if err := tx.QueryRowContext(ctx, `SELECT payload=$4::jsonb AND row_sha256=$5 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name=$2 AND row_key=$3`, batch.EpochID, batch.Table, row.Key, string(row.Payload), row.SHA256).Scan(&exact); err != nil || !exact {
			return ErrIdempotencyConflict
		}
	}
	return nil
}

// VerifyMailCutover streams and verifies every staged row against the durable
// source manifest, then materializes the PostgreSQL relay atomically while the
// application-role write fence remains closed.
func (a *Administration) VerifyMailCutover(ctx context.Context, actorPrincipalID, epochID, sourceFingerprint string) (MailCutoverEpoch, error) {
	if !validOpaqueID(actorPrincipalID) || uuid.Validate(epochID) != nil || !mailCutoverDigestPattern.MatchString(sourceFingerprint) {
		return MailCutoverEpoch{}, errors.New("invalid mail cutover verification")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover verification cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := guardMutation(ctx, tx); err != nil {
		return MailCutoverEpoch{}, err
	}
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return MailCutoverEpoch{}, errors.New("mail cutover verification is not authorized")
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, mailCutoverLockKey); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover verification cannot be serialized")
	}
	var epoch MailCutoverEpoch
	if err := scanMailCutover(tx.QueryRowContext(ctx, mailCutoverSelect+` WHERE epoch_id=$1 FOR UPDATE`, epochID), &epoch); err != nil || epoch.SourceFingerprint != sourceFingerprint {
		return MailCutoverEpoch{}, errors.New("mail cutover epoch is unavailable")
	}
	if epoch.Phase == MailCutoverVerified {
		if err := tx.Commit(); err != nil {
			return MailCutoverEpoch{}, errors.New("mail cutover verification retry cannot commit")
		}
		return epoch, nil
	}
	if epoch.Phase != MailCutoverImporting {
		return MailCutoverEpoch{}, errors.New("mail cutover is not importing")
	}
	var manifest relay.MigrationSourceManifest
	if err := json.Unmarshal(epoch.Manifest, &manifest); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover manifest is unavailable")
	}
	for _, table := range mailCutoverTables {
		expectedCount, expectedDigest := mailCutoverTableEvidence(manifest, table)
		var checkpointCount int64
		if err := tx.QueryRowContext(ctx, `SELECT row_count FROM relay.mail_cutover_checkpoints WHERE epoch_id=$1 AND table_name=$2`, epochID, table).Scan(&checkpointCount); err != nil || checkpointCount != expectedCount {
			return MailCutoverEpoch{}, errors.New("mail cutover checkpoint does not match the source manifest")
		}
		hasher, err := relay.NewMigrationTableHasher(table)
		if err != nil {
			return MailCutoverEpoch{}, errors.New("mail cutover table is unavailable")
		}
		rows, err := tx.QueryContext(ctx, `SELECT row_key,payload::text,row_sha256 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name=$2 ORDER BY row_key COLLATE "C"`, epochID, table)
		if err != nil {
			return MailCutoverEpoch{}, errors.New("mail cutover staging is unavailable")
		}
		for rows.Next() {
			var row relay.MigrationSourceRow
			var payload []byte
			row.Table = table
			if err := rows.Scan(&row.Key, &payload, &row.SHA256); err != nil {
				_ = rows.Close()
				return MailCutoverEpoch{}, errors.New("mail cutover staged row is malformed")
			}
			canonical, err := canonicalizeStagedPayload(payload)
			if err != nil {
				_ = rows.Close()
				return MailCutoverEpoch{}, err
			}
			row.Payload = canonical
			if err := hasher.Add(row); err != nil {
				_ = rows.Close()
				return MailCutoverEpoch{}, errors.New("mail cutover staged row is invalid")
			}
		}
		if err := rows.Close(); err != nil || rows.Err() != nil {
			return MailCutoverEpoch{}, errors.New("mail cutover staging cannot be read")
		}
		count, digest := hasher.Evidence()
		if count != expectedCount || digest != expectedDigest {
			return MailCutoverEpoch{}, errors.New("mail cutover staging does not match the source manifest")
		}
	}
	for _, statement := range mailCutoverMaterializationStatements {
		if _, err := tx.ExecContext(ctx, statement, epochID); err != nil {
			return MailCutoverEpoch{}, errors.New("mail cutover rows cannot be materialized")
		}
	}
	for _, table := range mailCutoverTables {
		expected, _ := mailCutoverTableEvidence(manifest, table)
		var actual int64
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM relay.`+table).Scan(&actual); err != nil || actual != expected { // #nosec G202 -- table comes only from mailCutoverTables.
			return MailCutoverEpoch{}, errors.New("mail cutover materialized count does not match")
		}
	}
	if err := scanMailCutover(tx.QueryRowContext(ctx, `UPDATE relay.mail_cutover_epochs SET phase='verified',updated_at=statement_timestamp(),verified_at=statement_timestamp() WHERE epoch_id=$1 AND phase='importing' RETURNING epoch_id::text,source_id::text,target_identity,source_fingerprint,source_manifest,manifest_sha256,phase,created_at,updated_at,verified_at,activated_at,aborted_at`, epochID), &epoch); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover cannot be verified")
	}
	if err := tx.Commit(); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover verification cannot commit")
	}
	return epoch, nil
}

func canonicalizeStagedPayload(payload []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("mail cutover staged payload is invalid")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("mail cutover staged payload is invalid")
	}
	return canonical, nil
}

func mailCutoverTableEvidence(manifest relay.MigrationSourceManifest, table string) (int64, string) {
	switch table {
	case "mail_endpoints":
		return manifest.Counts.Endpoints, manifest.TableSHA256.Endpoints
	case "mail_conversations":
		return manifest.Counts.Conversations, manifest.TableSHA256.Conversations
	case "mail_memberships":
		return manifest.Counts.Memberships, manifest.TableSHA256.Memberships
	case "mail_messages":
		return manifest.Counts.Messages, manifest.TableSHA256.Messages
	case "mail_deliveries":
		return manifest.Counts.Deliveries, manifest.TableSHA256.Deliveries
	case "mail_recipient_cursors":
		return manifest.Counts.RecipientCursors, manifest.TableSHA256.RecipientCursors
	case "mail_message_idempotency":
		return manifest.Counts.MessageIdempotency, manifest.TableSHA256.MessageIdempotency
	case "mail_conversation_idempotency":
		return manifest.Counts.ConversationIdempotency, manifest.TableSHA256.ConversationIdempotency
	case "mail_request_nonces":
		return manifest.Counts.RequestNonces, manifest.TableSHA256.RequestNonces
	default:
		return -1, ""
	}
}

var mailCutoverMaterializationStatements = []string{
	`INSERT INTO relay.mail_endpoints(endpoint,machine_id,lease_until,ownership_generation,consumer_id,consumer_generation,consumer_lease_until)
	 SELECT payload->>'endpoint',payload->>'machine_id',TIMESTAMPTZ 'epoch'+(payload->>'lease_until')::bigint*INTERVAL '1 millisecond',(payload->>'ownership_generation')::bigint,payload->>'consumer_id',(payload->>'consumer_generation')::bigint,
	 CASE WHEN payload->>'consumer_lease_until' IS NULL THEN NULL ELSE TIMESTAMPTZ 'epoch'+(payload->>'consumer_lease_until')::bigint*INTERVAL '1 millisecond' END
	 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name='mail_endpoints' ORDER BY row_key COLLATE "C"`,
	`INSERT INTO relay.mail_conversations(id,next_sequence,created_at)
	 SELECT (payload->>'id')::uuid,(payload->>'next_sequence')::bigint,TIMESTAMPTZ 'epoch'+(payload->>'created_at')::bigint*INTERVAL '1 millisecond'
	 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name='mail_conversations' ORDER BY row_key COLLATE "C"`,
	`INSERT INTO relay.mail_memberships(conversation_id,endpoint,capabilities)
	 SELECT (payload->>'conversation_id')::uuid,payload->>'endpoint',(payload->>'capabilities')::smallint
	 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name='mail_memberships' ORDER BY row_key COLLATE "C"`,
	`INSERT INTO relay.mail_messages(id,conversation_id,sequence,from_endpoint,body,created_at)
	 SELECT (payload->>'id')::uuid,(payload->>'conversation_id')::uuid,(payload->>'sequence')::bigint,payload->>'from_endpoint',payload->>'body',TIMESTAMPTZ 'epoch'+(payload->>'created_at')::bigint*INTERVAL '1 millisecond'
	 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name='mail_messages' ORDER BY row_key COLLATE "C"`,
	`INSERT INTO relay.mail_deliveries(id,message_id,recipient_endpoint,lease_machine_id,lease_token,lease_generation,ownership_generation,consumer_generation,lease_until,acked_at)
	 SELECT (payload->>'id')::uuid,(payload->>'message_id')::uuid,payload->>'recipient_endpoint',payload->>'lease_machine_id',(payload->>'lease_token')::uuid,(payload->>'lease_generation')::bigint,(payload->>'ownership_generation')::bigint,(payload->>'consumer_generation')::bigint,
	 CASE WHEN payload->>'lease_until' IS NULL THEN NULL ELSE TIMESTAMPTZ 'epoch'+(payload->>'lease_until')::bigint*INTERVAL '1 millisecond' END,
	 CASE WHEN payload->>'acked_at' IS NULL THEN NULL ELSE TIMESTAMPTZ 'epoch'+(payload->>'acked_at')::bigint*INTERVAL '1 millisecond' END
	 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name='mail_deliveries' ORDER BY row_key COLLATE "C"`,
	`INSERT INTO relay.mail_recipient_cursors(recipient_endpoint,conversation_id,sequence)
	 SELECT payload->>'recipient_endpoint',(payload->>'conversation_id')::uuid,(payload->>'sequence')::bigint
	 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name='mail_recipient_cursors' ORDER BY row_key COLLATE "C"`,
	`INSERT INTO relay.mail_message_idempotency(machine_id,key,request_hash,message_id,created_at)
	 SELECT payload->>'machine_id',payload->>'key',payload->>'request_hash',(payload->>'message_id')::uuid,TIMESTAMPTZ 'epoch'+(payload->>'created_at')::bigint*INTERVAL '1 millisecond'
	 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name='mail_message_idempotency' ORDER BY row_key COLLATE "C"`,
	`INSERT INTO relay.mail_conversation_idempotency(machine_id,key,request_hash,conversation_id,created_at)
	 SELECT payload->>'machine_id',payload->>'key',payload->>'request_hash',(payload->>'conversation_id')::uuid,TIMESTAMPTZ 'epoch'+(payload->>'created_at')::bigint*INTERVAL '1 millisecond'
	 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name='mail_conversation_idempotency' ORDER BY row_key COLLATE "C"`,
	`INSERT INTO relay.mail_request_nonces(machine_id,nonce,expires_at)
	 SELECT payload->>'machine_id',payload->>'nonce',TIMESTAMPTZ 'epoch'+(payload->>'expires_at')::bigint*INTERVAL '1 millisecond'
	 FROM relay.mail_cutover_staging WHERE epoch_id=$1 AND table_name='mail_request_nonces' ORDER BY row_key COLLATE "C"`,
}

// CheckMailCutoverActivationReadiness proves that the verified destination has
// no pending legacy identity, every migrated key remains enrolled, and any
// additionally enrolled key is a known retired identity whose source mail is
// being preserved before the host irreversibly retires SQLite.
// ActivateMailCutover repeats the pending-inventory proof while closing the
// legacy gate in the same transaction as PostgreSQL activation.
func (a *Administration) CheckMailCutoverActivationReadiness(ctx context.Context, actorPrincipalID, epochID, sourceFingerprint, enrollment string) error {
	if !validOpaqueID(actorPrincipalID) || uuid.Validate(epochID) != nil || !mailCutoverDigestPattern.MatchString(sourceFingerprint) || relay.ValidateMachineEnrollments(enrollment) != nil {
		return errors.New("invalid mail cutover activation readiness check")
	}
	machines, err := relay.ParseMachineEnrollments(enrollment)
	if err != nil {
		return errors.New("invalid mail cutover activation readiness check")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("mail cutover activation readiness cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := guardMutation(ctx, tx); err != nil {
		return err
	}
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return errors.New("mail cutover activation readiness is not authorized")
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, mailCutoverLockKey); err != nil {
		return errors.New("mail cutover activation readiness cannot be serialized")
	}
	if err := lockLegacyMutations(ctx, tx); err != nil {
		return err
	}
	var phase MailCutoverPhase
	if err := tx.QueryRowContext(ctx, `SELECT phase FROM relay.mail_cutover_epochs WHERE epoch_id=$1 AND source_fingerprint=$2 FOR UPDATE`, epochID, sourceFingerprint).Scan(&phase); err != nil || phase != MailCutoverVerified {
		return errors.New("mail cutover is not verified")
	}
	var pending, legacyStatePresent bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.legacy_machines WHERE state='pending'),EXISTS (SELECT 1 FROM auth.legacy_auth_state WHERE singleton)`).Scan(&pending, &legacyStatePresent); err != nil || !legacyStatePresent {
		return errors.New("legacy inventory is unavailable")
	}
	if pending {
		return errors.New("legacy authentication still has pending machines")
	}
	rows, err := tx.QueryContext(ctx, `SELECT public_key,state FROM auth.legacy_machines WHERE state<>'pending' ORDER BY public_key_digest`)
	if err != nil {
		return errors.New("legacy inventory is unavailable")
	}
	var legacyKeys []mailCutoverLegacyKey
	for rows.Next() {
		var publicKey []byte
		var state LegacyMachineState
		if err := rows.Scan(&publicKey, &state); err != nil {
			_ = rows.Close()
			return errors.New("legacy inventory is malformed")
		}
		legacyKeys = append(legacyKeys, mailCutoverLegacyKey{publicKey: publicKey, state: state})
	}
	if err := rows.Close(); err != nil || rows.Err() != nil {
		return errors.New("legacy inventory is unavailable")
	}
	if err := validateMailCutoverEnrollmentKeys(machines, legacyKeys); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New("mail cutover activation readiness cannot commit")
	}
	return nil
}

type mailCutoverLegacyKey struct {
	publicKey []byte
	state     LegacyMachineState
}

func validateMailCutoverEnrollmentKeys(machines []relay.Machine, legacyKeys []mailCutoverLegacyKey) error {
	configured := make(map[string]struct{}, len(machines))
	for _, machine := range machines {
		configured[string(machine.PublicKey)] = struct{}{}
	}
	known := make(map[string]LegacyMachineState, len(legacyKeys))
	for _, legacy := range legacyKeys {
		key := string(legacy.publicKey)
		known[key] = legacy.state
		if legacy.state == LegacyMigrated {
			if _, ok := configured[key]; !ok {
				return errors.New("static relay enrollment omits migrated legacy inventory")
			}
		}
	}
	for publicKey := range configured {
		if _, ok := known[publicKey]; !ok {
			return errors.New("static relay enrollment contains an unknown legacy key")
		}
	}
	return nil
}

// ActivateMailCutover crosses the PostgreSQL authority barrier only after the
// host-local executor presents the exact source manifest in its durable retired
// phase. Legacy authentication closure and PostgreSQL activation commit in the
// same owner transaction.
func (a *Administration) ActivateMailCutover(ctx context.Context, actorPrincipalID, epochID, sourceFingerprint string, retired relay.MigrationSourceManifest) (MailCutoverEpoch, error) {
	if !validOpaqueID(actorPrincipalID) || uuid.Validate(epochID) != nil || !mailCutoverDigestPattern.MatchString(sourceFingerprint) || retired.Phase != relay.MigrationSourceRetired || retired.EpochID != epochID || retired.Fingerprint != sourceFingerprint {
		return MailCutoverEpoch{}, errors.New("invalid mail cutover activation")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover activation cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	if err := guardMutation(ctx, tx); err != nil {
		return MailCutoverEpoch{}, err
	}
	if ok, err := lockInstallationOwner(ctx, tx, actorPrincipalID); err != nil || !ok {
		return MailCutoverEpoch{}, errors.New("mail cutover activation is not authorized")
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, mailCutoverLockKey); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover activation cannot be serialized")
	}
	if err := lockLegacyMutations(ctx, tx); err != nil {
		return MailCutoverEpoch{}, err
	}
	var epoch MailCutoverEpoch
	if err := scanMailCutover(tx.QueryRowContext(ctx, mailCutoverSelect+` WHERE epoch_id=$1 FOR UPDATE`, epochID), &epoch); err != nil || epoch.SourceFingerprint != sourceFingerprint {
		return MailCutoverEpoch{}, errors.New("mail cutover epoch is unavailable")
	}
	var prepared relay.MigrationSourceManifest
	if err := json.Unmarshal(epoch.Manifest, &prepared); err != nil || !sameMailCutoverSource(prepared, retired) {
		return MailCutoverEpoch{}, errors.New("retired mail source does not match the verified epoch")
	}
	if epoch.Phase == MailCutoverActive {
		if err := tx.Commit(); err != nil {
			return MailCutoverEpoch{}, errors.New("mail cutover activation retry cannot commit")
		}
		return epoch, nil
	}
	if epoch.Phase != MailCutoverVerified {
		return MailCutoverEpoch{}, errors.New("mail cutover is not verified")
	}
	var pending bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.legacy_machines WHERE state='pending')`).Scan(&pending); err != nil {
		return MailCutoverEpoch{}, errors.New("legacy inventory is unavailable")
	}
	if pending {
		return MailCutoverEpoch{}, errors.New("legacy authentication still has pending machines")
	}
	var legacyEnabled bool
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM auth.legacy_auth_state WHERE singleton FOR UPDATE`).Scan(&legacyEnabled); err != nil {
		return MailCutoverEpoch{}, errors.New("legacy authentication state is unavailable")
	}
	if legacyEnabled {
		if _, err := tx.ExecContext(ctx, `UPDATE auth.legacy_auth_state SET enabled=false,changed_at=statement_timestamp() WHERE singleton AND enabled`); err != nil {
			return MailCutoverEpoch{}, errors.New("legacy authentication cannot be closed")
		}
		control := &ControlTx{tx: tx}
		if err := control.AppendAudit(ctx, AuditEvent{PrincipalID: actorPrincipalID, Action: AuditLegacyDisable, Outcome: AuditSucceeded, TargetKind: AuditTargetLegacyMachine}); err != nil {
			return MailCutoverEpoch{}, err
		}
		if _, err := control.AdvanceChange(ctx); err != nil {
			return MailCutoverEpoch{}, err
		}
	}
	if err := scanMailCutover(tx.QueryRowContext(ctx, `UPDATE relay.mail_cutover_epochs SET phase='active',updated_at=statement_timestamp(),activated_at=statement_timestamp() WHERE epoch_id=$1 AND phase='verified' RETURNING epoch_id::text,source_id::text,target_identity,source_fingerprint,source_manifest,manifest_sha256,phase,created_at,updated_at,verified_at,activated_at,aborted_at`, epochID), &epoch); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover cannot activate")
	}
	if err := tx.Commit(); err != nil {
		return MailCutoverEpoch{}, errors.New("mail cutover activation cannot commit")
	}
	return epoch, nil
}

func sameMailCutoverSource(prepared, retired relay.MigrationSourceManifest) bool {
	return prepared.Version == retired.Version && prepared.SourceID == retired.SourceID && prepared.EpochID == retired.EpochID && prepared.TargetIdentity == retired.TargetIdentity && prepared.Fingerprint == retired.Fingerprint &&
		prepared.Counts == retired.Counts && prepared.TableSHA256 == retired.TableSHA256 && prepared.Phase == relay.MigrationSourcePrepared && retired.Phase == relay.MigrationSourceRetired
}
