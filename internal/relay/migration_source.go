package relay

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// MigrationSourcePhase is the durable SQLite authority boundary.
type MigrationSourcePhase string

const (
	// MigrationSourceActive permits ordinary SQLite relay writes.
	MigrationSourceActive MigrationSourcePhase = "active"
	// MigrationSourcePrepared is the abortable durable write barrier.
	MigrationSourcePrepared MigrationSourcePhase = "prepared"
	// MigrationSourceRetired is the irreversible forensic-only barrier.
	MigrationSourceRetired MigrationSourcePhase = "retired"
)

// MigrationSourceCounts are the exact logical row counts bound into a source
// manifest. Cutover metadata is intentionally excluded.
type MigrationSourceCounts struct {
	Endpoints               int64 `json:"endpoints"`
	Conversations           int64 `json:"conversations"`
	Memberships             int64 `json:"memberships"`
	Messages                int64 `json:"messages"`
	Deliveries              int64 `json:"deliveries"`
	RecipientCursors        int64 `json:"recipient_cursors"`
	MessageIdempotency      int64 `json:"message_idempotency"`
	ConversationIdempotency int64 `json:"conversation_idempotency"`
	RequestNonces           int64 `json:"request_nonces"`
}

// MigrationSourceHashes are per-table hashes over canonical ordered rows.
type MigrationSourceHashes struct {
	Endpoints               string `json:"endpoints"`
	Conversations           string `json:"conversations"`
	Memberships             string `json:"memberships"`
	Messages                string `json:"messages"`
	Deliveries              string `json:"deliveries"`
	RecipientCursors        string `json:"recipient_cursors"`
	MessageIdempotency      string `json:"message_idempotency"`
	ConversationIdempotency string `json:"conversation_idempotency"`
	RequestNonces           string `json:"request_nonces"`
}

// MigrationSourceManifest is a content-addressed logical view of one SQLite
// relay. It never includes file bytes, page order, WAL state, or secrets.
type MigrationSourceManifest struct {
	Version                 int                   `json:"version"`
	SourceID                string                `json:"source_id"`
	Phase                   MigrationSourcePhase  `json:"phase"`
	EpochID                 string                `json:"epoch_id,omitempty"`
	TargetIdentity          string                `json:"target_identity,omitempty"`
	Counts                  MigrationSourceCounts `json:"counts"`
	TableSHA256             MigrationSourceHashes `json:"table_sha256"`
	Fingerprint             string                `json:"fingerprint"`
	lastEpochID             string
	lastTargetIdentity      string
	lastExpectedFingerprint string
	lastResultFingerprint   string
	lastCutoff              int64
	lastTransition          string
}

type migrationTableSpec struct {
	name, columns, order string
}

var migrationTableSpecs = []migrationTableSpec{
	{"endpoints", "endpoint,machine_id,lease_until,ownership_generation,consumer_id,consumer_generation,consumer_lease_until", "endpoint"},
	{"conversations", "id,next_sequence,created_at", "id"},
	{"memberships", "conversation_id,endpoint,capabilities", "conversation_id,endpoint"},
	{"messages", "id,conversation_id,sequence,from_endpoint,body,created_at", "id"},
	{"deliveries", "id,message_id,recipient_endpoint,lease_machine_id,lease_token,lease_generation,ownership_generation,consumer_generation,lease_until,acked_at", "id"},
	{"recipient_cursors", "recipient_endpoint,conversation_id,sequence", "recipient_endpoint,conversation_id"},
	{"idempotency", "machine_id,key,request_hash,message_id,created_at", "machine_id,key"},
	{"conversation_idempotency", "machine_id,key,request_hash,conversation_id,created_at", "machine_id,key"},
	{"request_nonces", "machine_id,nonce,expires_at", "machine_id,nonce"},
}

const migrationSourceSchema = "punaro-relay-sqlite-v1:endpoints;conversations;memberships;messages;deliveries;recipient_cursors;idempotency;conversation_idempotency;request_nonces"

// InspectMigrationSource reads an existing source without creating, migrating,
// checkpointing, or changing its logical cutover state.
func InspectMigrationSource(ctx context.Context, path string) (MigrationSourceManifest, error) {
	db, err := openMigrationSourceDatabase(path, true)
	if err != nil {
		return MigrationSourceManifest{}, err
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return MigrationSourceManifest{}, errors.New("relay migration source snapshot cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	manifest, err := inspectMigrationSource(ctx, tx)
	if err != nil {
		return MigrationSourceManifest{}, err
	}
	if err := tx.Commit(); err != nil {
		return MigrationSourceManifest{}, errors.New("relay migration source snapshot cannot commit")
	}
	return manifest, nil
}

// PrepareMigrationSource fences every SQLite relay mutation, advances all
// carried lease fences, and records the exact post-fence logical fingerprint.
func PrepareMigrationSource(ctx context.Context, path, epochID, targetIdentity, expectedFingerprint string, now time.Time) (MigrationSourceManifest, error) {
	if uuid.Validate(epochID) != nil || !validMigrationDigest(targetIdentity) || !validMigrationDigest(expectedFingerprint) || now.IsZero() {
		return MigrationSourceManifest{}, errors.New("invalid relay migration preparation")
	}
	return mutateMigrationSource(ctx, path, func(conn *sql.Conn, current MigrationSourceManifest) (MigrationSourceManifest, error) {
		if current.Phase == MigrationSourcePrepared && current.EpochID == epochID && current.TargetIdentity == targetIdentity && current.lastEpochID == epochID && current.lastTargetIdentity == targetIdentity && current.lastExpectedFingerprint == expectedFingerprint && current.lastResultFingerprint == current.Fingerprint && current.lastCutoff == now.UTC().UnixMilli() && current.lastTransition == "prepared" {
			return current, nil
		}
		if current.Phase != MigrationSourceActive || current.Fingerprint != expectedFingerprint {
			return MigrationSourceManifest{}, errors.New("relay migration source changed before preparation")
		}
		if _, err := conn.ExecContext(ctx, `UPDATE endpoints SET lease_until=?,ownership_generation=ownership_generation+1,
			consumer_id=NULL,consumer_generation=consumer_generation+CASE WHEN consumer_id IS NULL THEN 0 ELSE 1 END,consumer_lease_until=NULL`, now.UTC().UnixMilli()); err != nil {
			return MigrationSourceManifest{}, errors.New("relay migration endpoint fencing failed")
		}
		if _, err := conn.ExecContext(ctx, `UPDATE deliveries SET lease_machine_id=NULL,lease_token=NULL,
			lease_generation=lease_generation+CASE WHEN lease_token IS NULL THEN 0 ELSE 1 END,
			ownership_generation=NULL,consumer_generation=NULL,lease_until=NULL`); err != nil {
			return MigrationSourceManifest{}, errors.New("relay migration delivery fencing failed")
		}
		prepared, err := inspectMigrationSource(ctx, conn)
		if err != nil {
			return MigrationSourceManifest{}, err
		}
		if _, err := conn.ExecContext(ctx, `UPDATE relay_migration_control SET phase='prepared',epoch_id=?,target_identity=?,fingerprint=?,last_epoch_id=?,last_target_identity=?,last_expected_fingerprint=?,last_result_fingerprint=?,last_cutoff=?,last_transition='prepared',changed_at=? WHERE singleton=1 AND phase='active'`, epochID, targetIdentity, prepared.Fingerprint, epochID, targetIdentity, expectedFingerprint, prepared.Fingerprint, now.UTC().UnixMilli(), now.UTC().UnixMilli()); err != nil {
			return MigrationSourceManifest{}, errors.New("relay migration source cannot be prepared")
		}
		prepared.Phase = MigrationSourcePrepared
		prepared.EpochID = epochID
		prepared.TargetIdentity = targetIdentity
		prepared.lastEpochID = epochID
		prepared.lastTargetIdentity = targetIdentity
		prepared.lastExpectedFingerprint = expectedFingerprint
		prepared.lastResultFingerprint = prepared.Fingerprint
		prepared.lastCutoff = now.UTC().UnixMilli()
		prepared.lastTransition = "prepared"
		return prepared, nil
	})
}

// AbortPreparedMigrationSource reopens SQLite only before the permanent retire
// boundary and only for the exact prepared epoch/source/target binding.
func AbortPreparedMigrationSource(ctx context.Context, path, epochID, targetIdentity, fingerprint string) (MigrationSourceManifest, error) {
	return transitionPreparedMigrationSource(ctx, path, epochID, targetIdentity, fingerprint, MigrationSourceActive)
}

// RetirePreparedMigrationSource permanently marks SQLite forensic-only.
func RetirePreparedMigrationSource(ctx context.Context, path, epochID, targetIdentity, fingerprint string) (MigrationSourceManifest, error) {
	return transitionPreparedMigrationSource(ctx, path, epochID, targetIdentity, fingerprint, MigrationSourceRetired)
}

func transitionPreparedMigrationSource(ctx context.Context, path, epochID, targetIdentity, fingerprint string, target MigrationSourcePhase) (MigrationSourceManifest, error) {
	if uuid.Validate(epochID) != nil || !validMigrationDigest(targetIdentity) || !validMigrationDigest(fingerprint) || target != MigrationSourceActive && target != MigrationSourceRetired {
		return MigrationSourceManifest{}, errors.New("invalid relay migration transition")
	}
	return mutateMigrationSource(ctx, path, func(conn *sql.Conn, current MigrationSourceManifest) (MigrationSourceManifest, error) {
		if current.Phase == MigrationSourceRetired {
			if target == MigrationSourceRetired && current.EpochID == epochID && current.TargetIdentity == targetIdentity && current.Fingerprint == fingerprint && current.lastEpochID == epochID && current.lastTargetIdentity == targetIdentity && current.lastResultFingerprint == fingerprint && current.lastTransition == "retired" {
				return current, nil
			}
			return MigrationSourceManifest{}, ErrMigrationSourceRetired
		}
		if current.Phase == MigrationSourceActive && target == MigrationSourceActive && current.Fingerprint == fingerprint && current.lastEpochID == epochID && current.lastTargetIdentity == targetIdentity && current.lastResultFingerprint == fingerprint && current.lastTransition == "aborted" {
			return current, nil
		}
		if current.Phase != MigrationSourcePrepared || current.EpochID != epochID || current.TargetIdentity != targetIdentity || current.Fingerprint != fingerprint {
			return MigrationSourceManifest{}, errors.New("relay migration source binding does not match")
		}
		if target == MigrationSourceActive {
			if _, err := conn.ExecContext(ctx, `UPDATE relay_migration_control SET phase='active',epoch_id=NULL,target_identity=NULL,fingerprint=NULL,last_transition='aborted',changed_at=? WHERE singleton=1 AND phase='prepared'`, time.Now().UTC().UnixMilli()); err != nil {
				return MigrationSourceManifest{}, errors.New("relay migration source cannot be reopened")
			}
			current.Phase, current.EpochID, current.TargetIdentity = MigrationSourceActive, "", ""
			current.lastTransition = "aborted"
			return current, nil
		}
		if _, err := conn.ExecContext(ctx, `UPDATE relay_migration_control SET phase='retired',last_transition='retired',changed_at=? WHERE singleton=1 AND phase='prepared'`, time.Now().UTC().UnixMilli()); err != nil {
			return MigrationSourceManifest{}, errors.New("relay migration source cannot be retired")
		}
		current.Phase = MigrationSourceRetired
		current.lastTransition = "retired"
		return current, nil
	})
}

func mutateMigrationSource(ctx context.Context, path string, mutation func(*sql.Conn, MigrationSourceManifest) (MigrationSourceManifest, error)) (MigrationSourceManifest, error) {
	db, err := openMigrationSourceDatabase(path, false)
	if err != nil {
		return MigrationSourceManifest{}, err
	}
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(ctx)
	if err != nil {
		return MigrationSourceManifest{}, errors.New("relay migration source connection is unavailable")
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		return MigrationSourceManifest{}, errors.New("relay migration source timeout cannot be configured")
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return MigrationSourceManifest{}, errors.New("relay migration source writer barrier is unavailable")
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	current, err := inspectMigrationSource(ctx, conn)
	if err != nil {
		return MigrationSourceManifest{}, err
	}
	result, err := mutation(conn, current)
	if err != nil {
		return MigrationSourceManifest{}, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return MigrationSourceManifest{}, errors.New("relay migration source transition cannot commit")
	}
	committed = true
	return result, nil
}

type migrationQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func inspectMigrationSource(ctx context.Context, q migrationQueryer) (MigrationSourceManifest, error) {
	manifest := MigrationSourceManifest{Version: 1}
	var storedFingerprint sql.NullString
	var controlRows int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM relay_migration_control`).Scan(&controlRows); err != nil || controlRows != 1 {
		return MigrationSourceManifest{}, errors.New("relay migration source control is unavailable")
	}
	if err := q.QueryRowContext(ctx, `SELECT source_id,phase,COALESCE(epoch_id,''),COALESCE(target_identity,''),fingerprint,COALESCE(last_epoch_id,''),COALESCE(last_target_identity,''),COALESCE(last_expected_fingerprint,''),COALESCE(last_result_fingerprint,''),COALESCE(last_cutoff,0),COALESCE(last_transition,'') FROM relay_migration_control WHERE singleton=1`).Scan(&manifest.SourceID, &manifest.Phase, &manifest.EpochID, &manifest.TargetIdentity, &storedFingerprint, &manifest.lastEpochID, &manifest.lastTargetIdentity, &manifest.lastExpectedFingerprint, &manifest.lastResultFingerprint, &manifest.lastCutoff, &manifest.lastTransition); err != nil || uuid.Validate(manifest.SourceID) != nil {
		return MigrationSourceManifest{}, errors.New("relay migration source control is unavailable")
	}
	if manifest.Phase != MigrationSourceActive && manifest.Phase != MigrationSourcePrepared && manifest.Phase != MigrationSourceRetired {
		return MigrationSourceManifest{}, errors.New("relay migration source phase is invalid")
	}
	if manifest.Phase == MigrationSourceActive {
		if manifest.EpochID != "" || manifest.TargetIdentity != "" || storedFingerprint.Valid {
			return MigrationSourceManifest{}, errors.New("relay migration active binding is invalid")
		}
	} else if uuid.Validate(manifest.EpochID) != nil || !validMigrationDigest(manifest.TargetIdentity) || !storedFingerprint.Valid || !validMigrationDigest(storedFingerprint.String) {
		return MigrationSourceManifest{}, errors.New("relay migration durable binding is invalid")
	}
	if manifest.lastTransition != "" && manifest.lastTransition != "prepared" && manifest.lastTransition != "aborted" && manifest.lastTransition != "retired" {
		return MigrationSourceManifest{}, errors.New("relay migration transition journal is invalid")
	}
	if err := verifyMigrationSourceSchema(ctx, q); err != nil {
		return MigrationSourceManifest{}, err
	}
	overall := sha256.New()
	if err := writeMigrationHashValue(overall, migrationSourceSchema); err != nil {
		return MigrationSourceManifest{}, err
	}
	if err := writeMigrationHashValue(overall, manifest.SourceID); err != nil {
		return MigrationSourceManifest{}, err
	}
	for _, spec := range migrationTableSpecs {
		tableHash := sha256.New()
		query := fmt.Sprintf("SELECT %s FROM %s ORDER BY %s", spec.columns, spec.name, spec.order)
		rows, err := q.QueryContext(ctx, query) // #nosec G202 -- query fragments come only from the fixed migrationTableSpecs allowlist.
		if err != nil {
			return MigrationSourceManifest{}, errors.New("relay migration source rows are unavailable")
		}
		columns, err := rows.Columns()
		if err != nil {
			_ = rows.Close()
			return MigrationSourceManifest{}, errors.New("relay migration source columns are unavailable")
		}
		var count int64
		for rows.Next() {
			values := make([]any, len(columns))
			destinations := make([]any, len(columns))
			for index := range values {
				destinations[index] = &values[index]
			}
			if err := rows.Scan(destinations...); err != nil {
				_ = rows.Close()
				return MigrationSourceManifest{}, errors.New("relay migration source row is malformed")
			}
			for _, value := range values {
				if err := writeMigrationHashValue(tableHash, value); err != nil {
					_ = rows.Close()
					return MigrationSourceManifest{}, err
				}
			}
			count++
		}
		if err := rows.Close(); err != nil {
			return MigrationSourceManifest{}, errors.New("relay migration source rows cannot close")
		}
		if err := rows.Err(); err != nil {
			return MigrationSourceManifest{}, errors.New("relay migration source rows are unavailable")
		}
		digest := hex.EncodeToString(tableHash.Sum(nil))
		setMigrationTableEvidence(&manifest, spec.name, count, digest)
		if err := writeMigrationHashValue(overall, spec.name); err != nil {
			return MigrationSourceManifest{}, err
		}
		if err := writeMigrationHashValue(overall, count); err != nil {
			return MigrationSourceManifest{}, err
		}
		if err := writeMigrationHashValue(overall, digest); err != nil {
			return MigrationSourceManifest{}, err
		}
	}
	manifest.Fingerprint = hex.EncodeToString(overall.Sum(nil))
	if manifest.Phase != MigrationSourceActive && (!storedFingerprint.Valid || storedFingerprint.String != manifest.Fingerprint) {
		return MigrationSourceManifest{}, errors.New("relay migration source fingerprint does not match its durable barrier")
	}
	return manifest, nil
}

func verifyMigrationSourceSchema(ctx context.Context, q migrationQueryer) error {
	rows, err := q.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return errors.New("relay migration source schema is unavailable")
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return errors.New("relay migration source schema is malformed")
		}
		names = append(names, name)
	}
	want := []string{"conversation_idempotency", "conversations", "deliveries", "endpoints", "idempotency", "memberships", "messages", "recipient_cursors", "relay_migration_control", "request_nonces"}
	if strings.Join(names, "\x00") != strings.Join(want, "\x00") {
		return errors.New("relay migration source has an unexpected schema")
	}
	expectedColumns := map[string][]string{
		"endpoints":                {"endpoint:TEXT:0:1:-", "machine_id:TEXT:1:0:-", "lease_until:INTEGER:1:0:-", "ownership_generation:INTEGER:1:0:1", "consumer_id:TEXT:0:0:-", "consumer_generation:INTEGER:1:0:0", "consumer_lease_until:INTEGER:0:0:-"},
		"conversations":            {"id:TEXT:0:1:-", "next_sequence:INTEGER:1:0:0", "created_at:INTEGER:1:0:-"},
		"memberships":              {"conversation_id:TEXT:1:1:-", "endpoint:TEXT:1:2:-", "capabilities:INTEGER:1:0:-"},
		"messages":                 {"id:TEXT:0:1:-", "conversation_id:TEXT:1:0:-", "sequence:INTEGER:1:0:-", "from_endpoint:TEXT:1:0:-", "body:TEXT:1:0:-", "created_at:INTEGER:1:0:-"},
		"deliveries":               {"id:TEXT:0:1:-", "message_id:TEXT:1:0:-", "recipient_endpoint:TEXT:1:0:-", "lease_machine_id:TEXT:0:0:-", "lease_token:TEXT:0:0:-", "lease_generation:INTEGER:1:0:0", "ownership_generation:INTEGER:0:0:-", "consumer_generation:INTEGER:0:0:-", "lease_until:INTEGER:0:0:-", "acked_at:INTEGER:0:0:-"},
		"recipient_cursors":        {"recipient_endpoint:TEXT:1:1:-", "conversation_id:TEXT:1:2:-", "sequence:INTEGER:1:0:0"},
		"idempotency":              {"machine_id:TEXT:1:1:-", "key:TEXT:1:2:-", "request_hash:TEXT:1:0:-", "message_id:TEXT:1:0:-", "created_at:INTEGER:1:0:-"},
		"conversation_idempotency": {"machine_id:TEXT:1:1:-", "key:TEXT:1:2:-", "request_hash:TEXT:1:0:-", "conversation_id:TEXT:1:0:-", "created_at:INTEGER:1:0:-"},
		"request_nonces":           {"machine_id:TEXT:1:1:-", "nonce:TEXT:1:2:-", "expires_at:INTEGER:1:0:-"},
		"relay_migration_control":  {"singleton:INTEGER:0:1:-", "source_id:TEXT:1:0:-", "phase:TEXT:1:0:'active'", "epoch_id:TEXT:0:0:-", "target_identity:TEXT:0:0:-", "fingerprint:TEXT:0:0:-", "last_epoch_id:TEXT:0:0:-", "last_target_identity:TEXT:0:0:-", "last_expected_fingerprint:TEXT:0:0:-", "last_result_fingerprint:TEXT:0:0:-", "last_cutoff:INTEGER:0:0:-", "last_transition:TEXT:0:0:-", "changed_at:INTEGER:1:0:-"},
	}
	for table, expected := range expectedColumns {
		columns, err := q.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table)) // #nosec G202 -- table comes only from the fixed expectedColumns allowlist.
		if err != nil {
			return errors.New("relay migration source columns are unavailable")
		}
		var actual []string
		for columns.Next() {
			var ordinal, notNull, primaryKey int
			var name, columnType string
			var defaultValue sql.NullString
			if err := columns.Scan(&ordinal, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				_ = columns.Close()
				return errors.New("relay migration source columns are malformed")
			}
			encodedDefault := "-"
			if defaultValue.Valid {
				encodedDefault = defaultValue.String
			}
			actual = append(actual, fmt.Sprintf("%s:%s:%d:%d:%s", name, strings.ToUpper(columnType), notNull, primaryKey, encodedDefault))
		}
		sort.Strings(actual)
		sort.Strings(expected)
		if err := columns.Close(); err != nil || columns.Err() != nil || strings.Join(actual, "\x00") != strings.Join(expected, "\x00") {
			return errors.New("relay migration source has unexpected columns")
		}
	}
	expectedForeignKeys := map[string][]string{
		"memberships":              {"conversations:conversation_id:id:NO ACTION:CASCADE:NONE"},
		"messages":                 {"conversations:conversation_id:id:NO ACTION:CASCADE:NONE"},
		"deliveries":               {"messages:message_id:id:NO ACTION:CASCADE:NONE"},
		"recipient_cursors":        {"conversations:conversation_id:id:NO ACTION:CASCADE:NONE"},
		"idempotency":              {"messages:message_id:id:NO ACTION:CASCADE:NONE"},
		"conversation_idempotency": {"conversations:conversation_id:id:NO ACTION:CASCADE:NONE"},
	}
	for table := range expectedColumns {
		foreignKeys, err := q.QueryContext(ctx, fmt.Sprintf("PRAGMA foreign_key_list(%s)", table)) // #nosec G202 -- table comes only from the fixed expectedColumns allowlist.
		if err != nil {
			return errors.New("relay migration source foreign key schema is unavailable")
		}
		var actual []string
		for foreignKeys.Next() {
			var id, sequence int
			var foreignTable, from, to, onUpdate, onDelete, match string
			if err := foreignKeys.Scan(&id, &sequence, &foreignTable, &from, &to, &onUpdate, &onDelete, &match); err != nil {
				_ = foreignKeys.Close()
				return errors.New("relay migration source foreign key schema is malformed")
			}
			actual = append(actual, strings.Join([]string{foreignTable, from, to, onUpdate, onDelete, match}, ":"))
		}
		expected := append([]string(nil), expectedForeignKeys[table]...)
		sort.Strings(actual)
		sort.Strings(expected)
		if err := foreignKeys.Close(); err != nil || foreignKeys.Err() != nil || strings.Join(actual, "\x00") != strings.Join(expected, "\x00") {
			return errors.New("relay migration source has unexpected foreign keys")
		}
	}
	expectedIndexes := []string{
		"endpoints:1:pk:0:endpoint",
		"conversations:1:pk:0:id",
		"memberships:1:pk:0:conversation_id,endpoint",
		"messages:1:pk:0:id", "messages:1:u:0:conversation_id,sequence",
		"deliveries:1:pk:0:id", "deliveries:1:u:0:message_id,recipient_endpoint", "deliveries:0:c:0:recipient_endpoint,acked_at,lease_until",
		"recipient_cursors:1:pk:0:recipient_endpoint,conversation_id",
		"idempotency:1:pk:0:machine_id,key",
		"conversation_idempotency:1:pk:0:machine_id,key",
		"request_nonces:1:pk:0:machine_id,nonce", "request_nonces:0:c:0:expires_at",
	}
	var actualIndexes []string
	for table := range expectedColumns {
		indexes, err := q.QueryContext(ctx, fmt.Sprintf("PRAGMA index_list(%s)", table)) // #nosec G202 -- table comes only from the fixed expectedColumns allowlist.
		if err != nil {
			return errors.New("relay migration source index schema is unavailable")
		}
		type indexMetadata struct {
			name, origin    string
			unique, partial int
		}
		var metadata []indexMetadata
		for indexes.Next() {
			var sequence, unique, partial int
			var name, origin string
			if err := indexes.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
				_ = indexes.Close()
				return errors.New("relay migration source index schema is malformed")
			}
			metadata = append(metadata, indexMetadata{name: name, origin: origin, unique: unique, partial: partial})
		}
		if err := indexes.Close(); err != nil || indexes.Err() != nil {
			return errors.New("relay migration source index schema is unavailable")
		}
		for _, index := range metadata {
			escapedName := strings.ReplaceAll(index.name, "'", "''")
			indexColumns, err := q.QueryContext(ctx, "PRAGMA index_info('"+escapedName+"')") // #nosec G202 -- SQLite quotes are escaped before inspecting an existing schema object.
			if err != nil {
				return errors.New("relay migration source index columns are unavailable")
			}
			var columns []string
			for indexColumns.Next() {
				var ordinal, columnID int
				var column string
				if err := indexColumns.Scan(&ordinal, &columnID, &column); err != nil {
					_ = indexColumns.Close()
					return errors.New("relay migration source index columns are malformed")
				}
				columns = append(columns, column)
			}
			if err := indexColumns.Close(); err != nil || indexColumns.Err() != nil {
				return errors.New("relay migration source index columns are unavailable")
			}
			actualIndexes = append(actualIndexes, fmt.Sprintf("%s:%d:%s:%d:%s", table, index.unique, index.origin, index.partial, strings.Join(columns, ",")))
		}
	}
	sort.Strings(expectedIndexes)
	sort.Strings(actualIndexes)
	if strings.Join(actualIndexes, "\x00") != strings.Join(expectedIndexes, "\x00") {
		return errors.New("relay migration source has unexpected indexes")
	}
	triggerRows, err := q.QueryContext(ctx, `SELECT name,tbl_name,sql FROM sqlite_master WHERE type='trigger' ORDER BY name`)
	if err != nil {
		return errors.New("relay migration source guards are unavailable")
	}
	seenTriggers := make(map[string]struct{}, 27)
	for triggerRows.Next() {
		var name, table, statement string
		if err := triggerRows.Scan(&name, &table, &statement); err != nil {
			_ = triggerRows.Close()
			return errors.New("relay migration source guard is malformed")
		}
		matched := false
		for _, operation := range []string{"insert", "update", "delete"} {
			expectedName := "relay_migration_guard_" + table + "_" + operation
			if name != expectedName {
				continue
			}
			normalized := strings.ToLower(strings.Join(strings.Fields(statement), " "))
			normalized = strings.Replace(normalized, "create trigger if not exists ", "create trigger ", 1)
			expectedStatement := fmt.Sprintf("create trigger %s before %s on %s when coalesce((select phase from relay_migration_control where singleton=1), 'missing') <> 'active' begin select raise(abort, 'relay migration source is not writable'); end", name, operation, table)
			if normalized != expectedStatement {
				_ = triggerRows.Close()
				return errors.New("relay migration source guard definition is unexpected")
			}
			matched = true
			seenTriggers[name] = struct{}{}
			break
		}
		if !matched {
			_ = triggerRows.Close()
			return errors.New("relay migration source has an unexpected trigger")
		}
	}
	if err := triggerRows.Close(); err != nil || triggerRows.Err() != nil || len(seenTriggers) != 27 {
		return errors.New("relay migration source guard inventory is incomplete")
	}
	var integrity string
	if err := q.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("relay migration source integrity check failed")
	}
	foreignKeyRows, err := q.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return errors.New("relay migration source foreign keys cannot be checked")
	}
	defer func() { _ = foreignKeyRows.Close() }()
	if foreignKeyRows.Next() || foreignKeyRows.Err() != nil {
		return errors.New("relay migration source foreign keys are invalid")
	}
	var invalidLogicalState bool
	if err := q.QueryRowContext(ctx, `WITH uuid_values(value) AS (
		SELECT id FROM conversations UNION ALL SELECT conversation_id FROM memberships
		UNION ALL SELECT id FROM messages UNION ALL SELECT conversation_id FROM messages
		UNION ALL SELECT id FROM deliveries UNION ALL SELECT message_id FROM deliveries
		UNION ALL SELECT conversation_id FROM recipient_cursors
		UNION ALL SELECT message_id FROM idempotency
		UNION ALL SELECT conversation_id FROM conversation_idempotency
	)
	SELECT
        EXISTS (SELECT 1 FROM endpoints WHERE ownership_generation<1 OR consumer_generation<0 OR (consumer_id IS NULL)<>(consumer_lease_until IS NULL))
        OR EXISTS (SELECT 1 FROM conversations WHERE next_sequence<0)
        OR EXISTS (SELECT 1 FROM memberships WHERE capabilities<1 OR capabilities>7)
        OR EXISTS (SELECT 1 FROM memberships AS membership LEFT JOIN endpoints AS endpoint ON endpoint.endpoint=membership.endpoint WHERE endpoint.endpoint IS NULL)
        OR EXISTS (SELECT 1 FROM messages WHERE sequence<1 OR length(CAST(body AS blob))>32768)
        OR EXISTS (SELECT 1 FROM messages AS message LEFT JOIN endpoints AS endpoint ON endpoint.endpoint=message.from_endpoint WHERE endpoint.endpoint IS NULL)
        OR EXISTS (SELECT 1 FROM messages AS message JOIN conversations AS conversation ON conversation.id=message.conversation_id WHERE message.sequence>conversation.next_sequence)
        OR EXISTS (SELECT 1 FROM deliveries WHERE lease_generation<0 OR (lease_token IS NOT NULL AND (ownership_generation<1 OR consumer_generation<0)) OR (acked_at IS NOT NULL AND lease_token IS NOT NULL) OR ((lease_machine_id IS NULL OR lease_token IS NULL OR ownership_generation IS NULL OR consumer_generation IS NULL OR lease_until IS NULL) AND NOT (lease_machine_id IS NULL AND lease_token IS NULL AND ownership_generation IS NULL AND consumer_generation IS NULL AND lease_until IS NULL)))
        OR EXISTS (SELECT 1 FROM deliveries AS delivery LEFT JOIN endpoints AS endpoint ON endpoint.endpoint=delivery.recipient_endpoint WHERE endpoint.endpoint IS NULL)
        OR EXISTS (SELECT 1 FROM recipient_cursors AS cursor JOIN conversations AS conversation ON conversation.id=cursor.conversation_id WHERE cursor.sequence<0 OR cursor.sequence>conversation.next_sequence)
        OR EXISTS (SELECT 1 FROM recipient_cursors AS cursor LEFT JOIN endpoints AS endpoint ON endpoint.endpoint=cursor.recipient_endpoint WHERE endpoint.endpoint IS NULL)
        OR EXISTS (SELECT 1 FROM idempotency WHERE length(request_hash)<>64 OR request_hash GLOB '*[^0-9a-f]*')
		OR EXISTS (SELECT 1 FROM idempotency GROUP BY message_id HAVING count(*)<>1)
        OR EXISTS (SELECT 1 FROM conversation_idempotency WHERE length(request_hash)<>64 OR request_hash GLOB '*[^0-9a-f]*')
		OR EXISTS (SELECT 1 FROM conversation_idempotency GROUP BY conversation_id HAVING count(*)<>1)
		OR EXISTS (SELECT 1 FROM uuid_values WHERE typeof(value)<>'text' OR length(value)<>36 OR substr(value,9,1)<>'-' OR substr(value,14,1)<>'-' OR substr(value,19,1)<>'-' OR substr(value,24,1)<>'-' OR lower(replace(value,'-','')) GLOB '*[^0-9a-f]*')
		OR EXISTS (SELECT 1 FROM endpoints WHERE typeof(endpoint)<>'text' OR typeof(machine_id)<>'text' OR typeof(lease_until)<>'integer' OR typeof(ownership_generation)<>'integer' OR (consumer_id IS NOT NULL AND typeof(consumer_id)<>'text') OR typeof(consumer_generation)<>'integer' OR (consumer_lease_until IS NOT NULL AND typeof(consumer_lease_until)<>'integer'))
		OR EXISTS (SELECT 1 FROM conversations WHERE typeof(next_sequence)<>'integer' OR typeof(created_at)<>'integer')
		OR EXISTS (SELECT 1 FROM memberships WHERE typeof(endpoint)<>'text' OR typeof(capabilities)<>'integer')
		OR EXISTS (SELECT 1 FROM messages WHERE typeof(sequence)<>'integer' OR typeof(from_endpoint)<>'text' OR typeof(body)<>'text' OR typeof(created_at)<>'integer')
		OR EXISTS (SELECT 1 FROM deliveries WHERE typeof(recipient_endpoint)<>'text' OR (lease_machine_id IS NOT NULL AND typeof(lease_machine_id)<>'text') OR typeof(lease_generation)<>'integer' OR (lease_token IS NOT NULL AND (typeof(lease_token)<>'text' OR length(lease_token)<>64 OR lease_token GLOB '*[^0-9a-f]*')) OR (ownership_generation IS NOT NULL AND typeof(ownership_generation)<>'integer') OR (consumer_generation IS NOT NULL AND typeof(consumer_generation)<>'integer') OR (lease_until IS NOT NULL AND typeof(lease_until)<>'integer') OR (acked_at IS NOT NULL AND typeof(acked_at)<>'integer'))
		OR EXISTS (SELECT 1 FROM recipient_cursors WHERE typeof(recipient_endpoint)<>'text' OR typeof(sequence)<>'integer')
		OR EXISTS (SELECT 1 FROM idempotency WHERE typeof(machine_id)<>'text' OR typeof(key)<>'text' OR typeof(request_hash)<>'text' OR typeof(created_at)<>'integer')
		OR EXISTS (SELECT 1 FROM conversation_idempotency WHERE typeof(machine_id)<>'text' OR typeof(key)<>'text' OR typeof(request_hash)<>'text' OR typeof(created_at)<>'integer')
		OR EXISTS (SELECT 1 FROM request_nonces WHERE typeof(machine_id)<>'text' OR typeof(nonce)<>'text' OR typeof(expires_at)<>'integer')
		OR EXISTS (SELECT 1 FROM relay_migration_control WHERE typeof(source_id)<>'text' OR typeof(phase)<>'text' OR (epoch_id IS NOT NULL AND typeof(epoch_id)<>'text') OR (target_identity IS NOT NULL AND typeof(target_identity)<>'text') OR (fingerprint IS NOT NULL AND typeof(fingerprint)<>'text') OR (last_epoch_id IS NOT NULL AND typeof(last_epoch_id)<>'text') OR (last_target_identity IS NOT NULL AND typeof(last_target_identity)<>'text') OR (last_expected_fingerprint IS NOT NULL AND typeof(last_expected_fingerprint)<>'text') OR (last_result_fingerprint IS NOT NULL AND typeof(last_result_fingerprint)<>'text') OR (last_cutoff IS NOT NULL AND typeof(last_cutoff)<>'integer') OR (last_transition IS NOT NULL AND typeof(last_transition)<>'text') OR typeof(changed_at)<>'integer')`).Scan(&invalidLogicalState); err != nil || invalidLogicalState {
		return errors.New("relay migration source logical constraints are invalid")
	}
	return nil
}

func writeMigrationHashValue(destination hash.Hash, value any) error {
	var kind byte
	var body []byte
	switch typed := value.(type) {
	case nil:
		kind = 0
	case int64:
		kind = 1
		body = make([]byte, 8)
		binary.BigEndian.PutUint64(body, uint64(typed)) // #nosec G115 -- two's-complement bits are the canonical signed-int encoding.
	case string:
		kind, body = 2, []byte(typed)
	case []byte:
		kind, body = 3, typed
	default:
		return errors.New("relay migration source contains an unsupported value")
	}
	_, _ = destination.Write([]byte{kind})
	length := make([]byte, 8)
	binary.BigEndian.PutUint64(length, uint64(len(body)))
	_, _ = destination.Write(length)
	_, _ = destination.Write(body)
	return nil
}

func setMigrationTableEvidence(manifest *MigrationSourceManifest, table string, count int64, digest string) {
	switch table {
	case "endpoints":
		manifest.Counts.Endpoints, manifest.TableSHA256.Endpoints = count, digest
	case "conversations":
		manifest.Counts.Conversations, manifest.TableSHA256.Conversations = count, digest
	case "memberships":
		manifest.Counts.Memberships, manifest.TableSHA256.Memberships = count, digest
	case "messages":
		manifest.Counts.Messages, manifest.TableSHA256.Messages = count, digest
	case "deliveries":
		manifest.Counts.Deliveries, manifest.TableSHA256.Deliveries = count, digest
	case "recipient_cursors":
		manifest.Counts.RecipientCursors, manifest.TableSHA256.RecipientCursors = count, digest
	case "idempotency":
		manifest.Counts.MessageIdempotency, manifest.TableSHA256.MessageIdempotency = count, digest
	case "conversation_idempotency":
		manifest.Counts.ConversationIdempotency, manifest.TableSHA256.ConversationIdempotency = count, digest
	case "request_nonces":
		manifest.Counts.RequestNonces, manifest.TableSHA256.RequestNonces = count, digest
	}
}

func openMigrationSourceDatabase(path string, readOnly bool) (*sql.DB, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("relay migration source path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("relay migration source must be an existing regular file")
	}
	directoryInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("relay migration source path must not traverse symlinks")
	}
	mode := "rw"
	if readOnly {
		mode = "ro"
	}
	sourceURL := &url.URL{Scheme: "file", Path: path, RawQuery: "mode=" + mode}
	dsn := sourceURL.String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errors.New("relay migration source cannot open")
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, errors.New("relay migration source is unavailable")
	}
	openedInfo, err := os.Stat(path)
	if err != nil || !os.SameFile(info, openedInfo) {
		_ = db.Close()
		return nil, errors.New("relay migration source changed while opening")
	}
	return db, nil
}

func validMigrationDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
