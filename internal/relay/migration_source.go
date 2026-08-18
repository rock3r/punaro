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
	"unicode/utf8"

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
	Roles                   int64 `json:"roles"`
	RoleMemberships         int64 `json:"role_memberships"`
	RoleBindings            int64 `json:"role_bindings"`
	Messages                int64 `json:"messages"`
	Deliveries              int64 `json:"deliveries"`
	RecipientCursors        int64 `json:"recipient_cursors"`
	MessageIdempotency      int64 `json:"message_idempotency"`
	ConversationIdempotency int64 `json:"conversation_idempotency"`
	ControlEvents           int64 `json:"control_events,omitempty"`
	ControlIdempotency      int64 `json:"control_idempotency,omitempty"`
	RoleProfiles            int64 `json:"role_profiles,omitempty"`
	RoleProfileIdempotency  int64 `json:"role_profile_idempotency,omitempty"`
	RequestNonces           int64 `json:"request_nonces"`
}

// MigrationSourceHashes are per-table hashes over canonical ordered rows.
type MigrationSourceHashes struct {
	Endpoints               string `json:"endpoints"`
	Conversations           string `json:"conversations"`
	Memberships             string `json:"memberships"`
	Roles                   string `json:"roles"`
	RoleMemberships         string `json:"role_memberships"`
	RoleBindings            string `json:"role_bindings"`
	Messages                string `json:"messages"`
	Deliveries              string `json:"deliveries"`
	RecipientCursors        string `json:"recipient_cursors"`
	MessageIdempotency      string `json:"message_idempotency"`
	ConversationIdempotency string `json:"conversation_idempotency"`
	ControlEvents           string `json:"control_events,omitempty"`
	ControlIdempotency      string `json:"control_idempotency,omitempty"`
	RoleProfiles            string `json:"role_profiles,omitempty"`
	RoleProfileIdempotency  string `json:"role_profile_idempotency,omitempty"`
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
	ExpectedFingerprint     string                `json:"-"`
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
	{"roles", "role,machine_id", "role"},
	{"role_memberships", "conversation_id,role,capabilities", "conversation_id,role"},
	{"role_bindings", "role,session_endpoint,machine_id,ownership_generation,lease_until", "role"},
	{"messages", "id,conversation_id,sequence,from_endpoint,body,created_at", "id"},
	{"deliveries", "id,message_id,recipient_endpoint,lease_machine_id,lease_token,lease_generation,ownership_generation,consumer_generation,lease_until,acked_at", "id"},
	{"recipient_cursors", "recipient_endpoint,conversation_id,sequence", "recipient_endpoint,conversation_id"},
	{"idempotency", "machine_id,key,request_hash,message_id,created_at", "machine_id,key"},
	{"conversation_idempotency", "machine_id,key,request_hash,conversation_id,created_at", "machine_id,key"},
	{"conversation_controls", "id,conversation_id,actor_endpoint,operation,member_endpoint,member_capabilities,created_at", "id"},
	{"conversation_control_idempotency", "machine_id,key,request_hash,control_id,created_at", "machine_id,key"},
	{"request_nonces", "machine_id,nonce,expires_at", "machine_id,nonce"},
	{"role_profiles", "role,display_name,direct_addressable,updated_at", "role"},
	{"role_profile_idempotency", "machine_id,key,request_hash,role,display_name,direct_addressable,updated_at,created_at", "machine_id,key"},
}

var v3MigrationTableSpecs = migrationTableSpecs[:14]

var roleMigrationTableSpecs = func() []migrationTableSpec {
	specs := append([]migrationTableSpec(nil), migrationTableSpecs[:11]...)
	return append(specs, migrationTableSpecs[13])
}()

var legacyMigrationTableSpecs = []migrationTableSpec{
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

const migrationSourceSchema = "punaro-relay-sqlite-v4:endpoints;conversations;memberships;roles;role_memberships;role_bindings;messages;deliveries;recipient_cursors;idempotency;conversation_idempotency;conversation_controls;conversation_control_idempotency;request_nonces;role_profiles;role_profile_idempotency"
const v3MigrationSourceSchema = "punaro-relay-sqlite-v3:endpoints;conversations;memberships;roles;role_memberships;role_bindings;messages;deliveries;recipient_cursors;idempotency;conversation_idempotency;conversation_controls;conversation_control_idempotency;request_nonces"
const roleMigrationSourceSchema = "punaro-relay-sqlite-v3:endpoints;conversations;memberships;roles;role_memberships;role_bindings;messages;deliveries;recipient_cursors;idempotency;conversation_idempotency;request_nonces"
const legacyMigrationSourceSchema = "punaro-relay-sqlite-v1:endpoints;conversations;memberships;messages;deliveries;recipient_cursors;idempotency;conversation_idempotency;request_nonces"

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

// CheckMigrationSourceEnrollmentCoverage proves every existing SQLite endpoint
// remains claimable by at least one machine in the static PostgreSQL runtime.
func CheckMigrationSourceEnrollmentCoverage(ctx context.Context, path, enrollment string) error {
	authenticator, _, err := machineEnrollmentAuthenticator(enrollment)
	if err != nil {
		return errors.New("relay migration enrollment is invalid")
	}
	db, err := openMigrationSourceDatabase(path, true)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return errors.New("relay migration enrollment snapshot cannot start")
	}
	defer func() { _ = tx.Rollback() }()
	manifest, err := inspectMigrationSource(ctx, tx)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT endpoint, machine_id FROM endpoints ORDER BY endpoint COLLATE BINARY`)
	if err != nil {
		return errors.New("relay migration endpoints are unavailable")
	}
	for rows.Next() {
		var endpoint, machineID string
		if err := rows.Scan(&endpoint, &machineID); err != nil || !authenticator.AllowsEndpoint(machineID, endpoint) {
			_ = rows.Close()
			return errors.New("relay migration enrollment does not cover every endpoint")
		}
	}
	if err := rows.Close(); err != nil || rows.Err() != nil {
		return errors.New("relay migration endpoints are unavailable")
	}
	if manifest.Version == 1 {
		if err := tx.Commit(); err != nil {
			return errors.New("relay migration enrollment snapshot cannot commit")
		}
		return nil
	}
	roleRows, err := tx.QueryContext(ctx, `SELECT DISTINCT machine_id FROM roles ORDER BY machine_id COLLATE BINARY`)
	if err != nil {
		return errors.New("relay migration roles are unavailable")
	}
	for roleRows.Next() {
		var machineID string
		if err := roleRows.Scan(&machineID); err != nil {
			_ = roleRows.Close()
			return errors.New("relay migration roles are unavailable")
		}
		if _, found := authenticator.machines[machineID]; !found {
			_ = roleRows.Close()
			return errors.New("relay migration enrollment does not cover every durable role")
		}
	}
	if err := roleRows.Close(); err != nil || roleRows.Err() != nil {
		return errors.New("relay migration roles are unavailable")
	}
	if err := tx.Commit(); err != nil {
		return errors.New("relay migration enrollment snapshot cannot commit")
	}
	return nil
}

// PrepareMigrationSource fences every SQLite relay mutation, advances all
// carried lease fences, and records the exact post-fence logical fingerprint.
func PrepareMigrationSource(ctx context.Context, path, epochID, targetIdentity, expectedFingerprint string, now time.Time) (MigrationSourceManifest, error) {
	if uuid.Validate(epochID) != nil || !validMigrationDigest(targetIdentity) || !validMigrationDigest(expectedFingerprint) || now.IsZero() {
		return MigrationSourceManifest{}, errors.New("invalid relay migration preparation")
	}
	return mutateMigrationSource(ctx, path, func(conn *sql.Conn, current MigrationSourceManifest) (MigrationSourceManifest, error) {
		cutoff := now.UTC().UnixMilli()
		if current.Version == 2 {
			// The transition journal predates the v2 schema. Its signed cutoff is
			// otherwise opaque bookkeeping, so retain v2 identity durably without
			// changing the parent schema's accepted transition vocabulary.
			cutoff = -cutoff
		}
		if current.Phase == MigrationSourcePrepared && current.EpochID == epochID && current.TargetIdentity == targetIdentity && current.lastEpochID == epochID && current.lastTargetIdentity == targetIdentity && current.lastExpectedFingerprint == expectedFingerprint && current.lastResultFingerprint == current.Fingerprint && current.lastCutoff == cutoff && current.lastTransition == "prepared" {
			return current, nil
		}
		if current.Phase != MigrationSourceActive || current.Fingerprint != expectedFingerprint {
			return MigrationSourceManifest{}, errors.New("relay migration source changed before preparation")
		}
		if _, err := conn.ExecContext(ctx, `UPDATE endpoints SET lease_until=?,ownership_generation=ownership_generation+1,
			consumer_id=NULL,consumer_generation=consumer_generation+CASE WHEN consumer_id IS NULL THEN 0 ELSE 1 END,consumer_lease_until=NULL`, now.UTC().UnixMilli()); err != nil {
			return MigrationSourceManifest{}, errors.New("relay migration endpoint fencing failed")
		}
		if current.Version >= 2 {
			if _, err := conn.ExecContext(ctx, `UPDATE role_bindings SET lease_until=?, ownership_generation=(
				SELECT ownership_generation FROM endpoints WHERE endpoint=role_bindings.session_endpoint
			)`, now.UTC().UnixMilli()); err != nil {
				return MigrationSourceManifest{}, errors.New("relay migration role binding fencing failed")
			}
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
		if _, err := conn.ExecContext(ctx, `UPDATE relay_migration_control SET phase='prepared',epoch_id=?,target_identity=?,fingerprint=?,last_epoch_id=?,last_target_identity=?,last_expected_fingerprint=?,last_result_fingerprint=?,last_cutoff=?,last_transition='prepared',changed_at=? WHERE singleton=1 AND phase='active'`, epochID, targetIdentity, prepared.Fingerprint, epochID, targetIdentity, expectedFingerprint, prepared.Fingerprint, cutoff, now.UTC().UnixMilli()); err != nil {
			return MigrationSourceManifest{}, errors.New("relay migration source cannot be prepared")
		}
		prepared.Phase = MigrationSourcePrepared
		prepared.EpochID = epochID
		prepared.TargetIdentity = targetIdentity
		prepared.lastEpochID = epochID
		prepared.lastTargetIdentity = targetIdentity
		prepared.lastExpectedFingerprint = expectedFingerprint
		prepared.ExpectedFingerprint = expectedFingerprint
		prepared.lastResultFingerprint = prepared.Fingerprint
		prepared.lastCutoff = cutoff
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
		if current.Phase == MigrationSourceActive && target == MigrationSourceActive && current.lastEpochID == epochID && current.lastTargetIdentity == targetIdentity && current.lastResultFingerprint == fingerprint && current.lastTransition == "aborted" {
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
			if current.Version == 3 && current.TableSHA256.ControlEvents == "" && current.TableSHA256.ControlIdempotency == "" {
				current.Version = 2
			}
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
	var roleTables int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('roles','role_memberships','role_bindings')`).Scan(&roleTables); err != nil || roleTables != 0 && roleTables != 3 {
		return MigrationSourceManifest{}, errors.New("relay migration source schema is unavailable")
	}
	var controlTables int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('conversation_controls','conversation_control_idempotency')`).Scan(&controlTables); err != nil || controlTables != 0 && controlTables != 2 {
		return MigrationSourceManifest{}, errors.New("relay migration source schema is unavailable")
	}
	var profileTables int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('role_profiles','role_profile_idempotency')`).Scan(&profileTables); err != nil || profileTables != 0 && profileTables != 2 {
		return MigrationSourceManifest{}, errors.New("relay migration source schema is unavailable")
	}
	if profileTables == 2 && controlTables != 2 {
		return MigrationSourceManifest{}, errors.New("relay migration source schema is unavailable")
	}
	manifest := MigrationSourceManifest{Version: 3}
	roleOnly := false
	tableSpecs, schema := v3MigrationTableSpecs, v3MigrationSourceSchema
	if roleTables == 0 {
		if controlTables != 0 || profileTables != 0 {
			return MigrationSourceManifest{}, errors.New("relay migration source schema is unavailable")
		}
		manifest.Version, tableSpecs, schema = 1, legacyMigrationTableSpecs, legacyMigrationSourceSchema
	} else if controlTables == 0 {
		roleOnly = true
		manifest.Version = 2
		tableSpecs, schema = roleMigrationTableSpecs, roleMigrationSourceSchema
	} else if profileTables == 2 {
		manifest.Version = 4
		tableSpecs, schema = migrationTableSpecs, migrationSourceSchema
	}
	var storedFingerprint sql.NullString
	var controlRows int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM relay_migration_control`).Scan(&controlRows); err != nil || controlRows != 1 {
		return MigrationSourceManifest{}, errors.New("relay migration source control is unavailable")
	}
	if err := q.QueryRowContext(ctx, `SELECT source_id,phase,COALESCE(epoch_id,''),COALESCE(target_identity,''),fingerprint,COALESCE(last_epoch_id,''),COALESCE(last_target_identity,''),COALESCE(last_expected_fingerprint,''),COALESCE(last_result_fingerprint,''),COALESCE(last_cutoff,0),COALESCE(last_transition,'') FROM relay_migration_control WHERE singleton=1`).Scan(&manifest.SourceID, &manifest.Phase, &manifest.EpochID, &manifest.TargetIdentity, &storedFingerprint, &manifest.lastEpochID, &manifest.lastTargetIdentity, &manifest.lastExpectedFingerprint, &manifest.lastResultFingerprint, &manifest.lastCutoff, &manifest.lastTransition); err != nil || uuid.Validate(manifest.SourceID) != nil {
		return MigrationSourceManifest{}, errors.New("relay migration source control is unavailable")
	}
	manifest.ExpectedFingerprint = manifest.lastExpectedFingerprint
	if manifest.Phase != MigrationSourceActive && manifest.Phase != MigrationSourcePrepared && manifest.Phase != MigrationSourceRetired {
		return MigrationSourceManifest{}, errors.New("relay migration source phase is invalid")
	}
	// Parent releases recorded role-only prepared manifests as v3. Retain that
	// durable identity until the existing epoch is retired or aborted; newly
	// active role-only sources use v2 so fresh cutovers name the absent controls.
	if roleOnly && manifest.Phase != MigrationSourceActive && manifest.lastCutoff >= 0 {
		manifest.Version = 3
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
	if err := verifyMigrationSourceSchemaVersion(ctx, q, manifest.Version, controlTables == 2, profileTables == 2); err != nil {
		return MigrationSourceManifest{}, err
	}
	overall := sha256.New()
	if err := writeMigrationHashValue(overall, schema); err != nil {
		return MigrationSourceManifest{}, err
	}
	if err := writeMigrationHashValue(overall, manifest.SourceID); err != nil {
		return MigrationSourceManifest{}, err
	}
	for _, spec := range tableSpecs {
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
			for index, value := range values {
				if err := validateMigrationSourceValue(spec.name, columns[index], value); err != nil {
					_ = rows.Close()
					return MigrationSourceManifest{}, err
				}
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

func verifyMigrationSourceSchemaVersion(ctx context.Context, q migrationQueryer, version int, controls, profiles bool) error {
	if version == 1 {
		return verifyLegacyMigrationSourceSchema(ctx, q)
	}
	return verifyMigrationSourceSchema(ctx, q, controls, profiles)
}

func verifyLegacyMigrationSourceSchema(ctx context.Context, q migrationQueryer) error {
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
	if err := rows.Err(); err != nil || strings.Join(names, "\x00") != strings.Join(want, "\x00") {
		return errors.New("relay migration source has an unexpected schema")
	}
	var integrity string
	if err := q.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("relay migration source integrity check failed")
	}
	foreignKeys, err := q.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil || foreignKeys.Next() || foreignKeys.Err() != nil {
		if foreignKeys != nil {
			_ = foreignKeys.Close()
		}
		return errors.New("relay migration source foreign keys are invalid")
	}
	return foreignKeys.Close()
}

func verifyMigrationSourceSchema(ctx context.Context, q migrationQueryer, controls, profiles bool) error {
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
	want := []string{"conversation_control_idempotency", "conversation_controls", "conversation_idempotency", "conversations", "deliveries", "endpoints", "idempotency", "memberships", "messages", "recipient_cursors", "relay_migration_control", "request_nonces", "role_bindings", "role_memberships", "roles"}
	if profiles {
		want = []string{"conversation_control_idempotency", "conversation_controls", "conversation_idempotency", "conversations", "deliveries", "endpoints", "idempotency", "memberships", "messages", "recipient_cursors", "relay_migration_control", "request_nonces", "role_bindings", "role_memberships", "role_profile_idempotency", "role_profiles", "roles"}
	} else if !controls {
		want = []string{"conversation_idempotency", "conversations", "deliveries", "endpoints", "idempotency", "memberships", "messages", "recipient_cursors", "relay_migration_control", "request_nonces", "role_bindings", "role_memberships", "roles"}
	}
	if strings.Join(names, "\x00") != strings.Join(want, "\x00") {
		return errors.New("relay migration source has an unexpected schema")
	}
	expectedColumns := map[string][]string{
		"endpoints":                        {"endpoint:TEXT:0:1:-", "machine_id:TEXT:1:0:-", "lease_until:INTEGER:1:0:-", "ownership_generation:INTEGER:1:0:1", "consumer_id:TEXT:0:0:-", "consumer_generation:INTEGER:1:0:0", "consumer_lease_until:INTEGER:0:0:-"},
		"conversations":                    {"id:TEXT:0:1:-", "next_sequence:INTEGER:1:0:0", "created_at:INTEGER:1:0:-"},
		"memberships":                      {"conversation_id:TEXT:1:1:-", "endpoint:TEXT:1:2:-", "capabilities:INTEGER:1:0:-"},
		"roles":                            {"role:TEXT:0:1:-", "machine_id:TEXT:1:0:-"},
		"role_memberships":                 {"conversation_id:TEXT:1:1:-", "role:TEXT:1:2:-", "capabilities:INTEGER:1:0:-"},
		"role_bindings":                    {"role:TEXT:0:1:-", "session_endpoint:TEXT:1:0:-", "machine_id:TEXT:1:0:-", "ownership_generation:INTEGER:1:0:-", "lease_until:INTEGER:1:0:-"},
		"messages":                         {"id:TEXT:0:1:-", "conversation_id:TEXT:1:0:-", "sequence:INTEGER:1:0:-", "from_endpoint:TEXT:1:0:-", "body:TEXT:1:0:-", "created_at:INTEGER:1:0:-"},
		"deliveries":                       {"id:TEXT:0:1:-", "message_id:TEXT:1:0:-", "recipient_endpoint:TEXT:1:0:-", "lease_machine_id:TEXT:0:0:-", "lease_token:TEXT:0:0:-", "lease_generation:INTEGER:1:0:0", "ownership_generation:INTEGER:0:0:-", "consumer_generation:INTEGER:0:0:-", "lease_until:INTEGER:0:0:-", "acked_at:INTEGER:0:0:-"},
		"recipient_cursors":                {"recipient_endpoint:TEXT:1:1:-", "conversation_id:TEXT:1:2:-", "sequence:INTEGER:1:0:0"},
		"idempotency":                      {"machine_id:TEXT:1:1:-", "key:TEXT:1:2:-", "request_hash:TEXT:1:0:-", "message_id:TEXT:1:0:-", "created_at:INTEGER:1:0:-"},
		"conversation_idempotency":         {"machine_id:TEXT:1:1:-", "key:TEXT:1:2:-", "request_hash:TEXT:1:0:-", "conversation_id:TEXT:1:0:-", "created_at:INTEGER:1:0:-"},
		"conversation_controls":            {"id:TEXT:0:1:-", "conversation_id:TEXT:1:0:-", "actor_endpoint:TEXT:1:0:-", "operation:TEXT:1:0:-", "member_endpoint:TEXT:1:0:-", "member_capabilities:INTEGER:1:0:-", "created_at:INTEGER:1:0:-"},
		"conversation_control_idempotency": {"machine_id:TEXT:1:1:-", "key:TEXT:1:2:-", "request_hash:TEXT:1:0:-", "control_id:TEXT:1:0:-", "created_at:INTEGER:1:0:-"},
		"request_nonces":                   {"machine_id:TEXT:1:1:-", "nonce:TEXT:1:2:-", "expires_at:INTEGER:1:0:-"},
		"relay_migration_control":          {"singleton:INTEGER:0:1:-", "source_id:TEXT:1:0:-", "phase:TEXT:1:0:'active'", "epoch_id:TEXT:0:0:-", "target_identity:TEXT:0:0:-", "fingerprint:TEXT:0:0:-", "last_epoch_id:TEXT:0:0:-", "last_target_identity:TEXT:0:0:-", "last_expected_fingerprint:TEXT:0:0:-", "last_result_fingerprint:TEXT:0:0:-", "last_cutoff:INTEGER:0:0:-", "last_transition:TEXT:0:0:-", "changed_at:INTEGER:1:0:-"},
		"role_profiles":                    {"role:TEXT:0:1:-", "display_name:TEXT:0:0:-", "direct_addressable:INTEGER:1:0:0", "updated_at:INTEGER:1:0:-"},
		"role_profile_idempotency":         {"machine_id:TEXT:1:1:-", "key:TEXT:1:2:-", "request_hash:TEXT:1:0:-", "role:TEXT:1:0:-", "display_name:TEXT:0:0:-", "direct_addressable:INTEGER:1:0:-", "updated_at:INTEGER:1:0:-", "created_at:INTEGER:1:0:-"},
	}
	if !controls {
		delete(expectedColumns, "conversation_controls")
		delete(expectedColumns, "conversation_control_idempotency")
	}
	if !profiles {
		delete(expectedColumns, "role_profiles")
		delete(expectedColumns, "role_profile_idempotency")
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
		"memberships":                      {"conversations:conversation_id:id:NO ACTION:CASCADE:NONE"},
		"role_memberships":                 {"conversations:conversation_id:id:NO ACTION:CASCADE:NONE", "roles:role:role:NO ACTION:RESTRICT:NONE"},
		"role_bindings":                    {"roles:role:role:NO ACTION:CASCADE:NONE"},
		"messages":                         {"conversations:conversation_id:id:NO ACTION:CASCADE:NONE"},
		"deliveries":                       {"messages:message_id:id:NO ACTION:CASCADE:NONE"},
		"recipient_cursors":                {"conversations:conversation_id:id:NO ACTION:CASCADE:NONE"},
		"idempotency":                      {"messages:message_id:id:NO ACTION:CASCADE:NONE"},
		"conversation_idempotency":         {"conversations:conversation_id:id:NO ACTION:CASCADE:NONE"},
		"conversation_controls":            {"conversations:conversation_id:id:NO ACTION:CASCADE:NONE"},
		"conversation_control_idempotency": {"conversation_controls:control_id:id:NO ACTION:CASCADE:NONE"},
		"role_profiles":                    {"roles:role:role:NO ACTION:CASCADE:NONE"},
		"role_profile_idempotency":         {"role_profiles:role:role:NO ACTION:CASCADE:NONE"},
	}
	if !controls {
		delete(expectedForeignKeys, "conversation_controls")
		delete(expectedForeignKeys, "conversation_control_idempotency")
	}
	if !profiles {
		delete(expectedForeignKeys, "role_profiles")
		delete(expectedForeignKeys, "role_profile_idempotency")
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
		"roles:1:pk:0:role",
		"role_memberships:1:pk:0:conversation_id,role",
		"role_bindings:1:pk:0:role", "role_bindings:0:c:0:machine_id,session_endpoint,ownership_generation,lease_until",
		"messages:1:pk:0:id", "messages:1:u:0:conversation_id,sequence",
		"deliveries:1:pk:0:id", "deliveries:1:u:0:message_id,recipient_endpoint", "deliveries:0:c:0:recipient_endpoint,acked_at,lease_until",
		"recipient_cursors:1:pk:0:recipient_endpoint,conversation_id",
		"idempotency:1:pk:0:machine_id,key",
		"conversation_idempotency:1:pk:0:machine_id,key",
		"conversation_controls:1:pk:0:id",
		"conversation_control_idempotency:1:pk:0:machine_id,key",
		"request_nonces:1:pk:0:machine_id,nonce", "request_nonces:0:c:0:expires_at",
		"role_profiles:1:pk:0:role",
		"role_profile_idempotency:1:pk:0:machine_id,key",
	}
	if !profiles {
		expectedIndexes = expectedIndexes[:len(expectedIndexes)-2]
	}
	if !controls {
		expectedIndexes = []string{
			"endpoints:1:pk:0:endpoint", "conversations:1:pk:0:id", "memberships:1:pk:0:conversation_id,endpoint", "roles:1:pk:0:role", "role_memberships:1:pk:0:conversation_id,role", "role_bindings:1:pk:0:role", "role_bindings:0:c:0:machine_id,session_endpoint,ownership_generation,lease_until", "messages:1:pk:0:id", "messages:1:u:0:conversation_id,sequence", "deliveries:1:pk:0:id", "deliveries:1:u:0:message_id,recipient_endpoint", "deliveries:0:c:0:recipient_endpoint,acked_at,lease_until", "recipient_cursors:1:pk:0:recipient_endpoint,conversation_id", "idempotency:1:pk:0:machine_id,key", "conversation_idempotency:1:pk:0:machine_id,key", "request_nonces:1:pk:0:machine_id,nonce", "request_nonces:0:c:0:expires_at",
		}
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
	seenTriggers := make(map[string]struct{}, 33)
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
	wantTriggers := 42
	if profiles {
		wantTriggers = 48
	} else if !controls {
		wantTriggers = 36
	}
	if err := triggerRows.Close(); err != nil || triggerRows.Err() != nil || len(seenTriggers) != wantTriggers {
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
	logicalStateQuery := `WITH uuid_values(value) AS (
		SELECT id FROM conversations UNION ALL SELECT conversation_id FROM memberships
		UNION ALL SELECT id FROM messages UNION ALL SELECT conversation_id FROM messages
		UNION ALL SELECT id FROM deliveries UNION ALL SELECT message_id FROM deliveries
		UNION ALL SELECT conversation_id FROM recipient_cursors
		UNION ALL SELECT message_id FROM idempotency
		UNION ALL SELECT conversation_id FROM conversation_idempotency
		UNION ALL SELECT id FROM conversation_controls UNION ALL SELECT conversation_id FROM conversation_controls
		UNION ALL SELECT control_id FROM conversation_control_idempotency
	)
	SELECT
        EXISTS (SELECT 1 FROM endpoints WHERE ownership_generation<1 OR consumer_generation<0 OR (consumer_id IS NULL)<>(consumer_lease_until IS NULL))
        OR EXISTS (SELECT 1 FROM conversations WHERE next_sequence<0)
		OR EXISTS (SELECT 1 FROM memberships WHERE capabilities<1 OR capabilities>15)
		OR EXISTS (SELECT 1 FROM role_memberships WHERE capabilities<1 OR capabilities>7)
        OR EXISTS (SELECT 1 FROM memberships AS membership LEFT JOIN endpoints AS endpoint ON endpoint.endpoint=membership.endpoint WHERE endpoint.endpoint IS NULL)
        OR EXISTS (SELECT 1 FROM messages WHERE sequence<1 OR length(CAST(body AS blob))>32768)
        OR EXISTS (SELECT 1 FROM messages AS message LEFT JOIN endpoints AS endpoint ON endpoint.endpoint=message.from_endpoint WHERE endpoint.endpoint IS NULL)
        OR EXISTS (SELECT 1 FROM messages AS message JOIN conversations AS conversation ON conversation.id=message.conversation_id WHERE message.sequence>conversation.next_sequence)
        OR EXISTS (SELECT 1 FROM deliveries WHERE lease_generation<0 OR (lease_token IS NOT NULL AND (ownership_generation<1 OR consumer_generation<0)) OR (acked_at IS NOT NULL AND lease_token IS NOT NULL) OR ((lease_machine_id IS NULL OR lease_token IS NULL OR ownership_generation IS NULL OR consumer_generation IS NULL OR lease_until IS NULL) AND NOT (lease_machine_id IS NULL AND lease_token IS NULL AND ownership_generation IS NULL AND consumer_generation IS NULL AND lease_until IS NULL)))
        OR EXISTS (SELECT 1 FROM deliveries AS delivery LEFT JOIN endpoints AS endpoint ON endpoint.endpoint=delivery.recipient_endpoint LEFT JOIN roles AS role ON substr(delivery.recipient_endpoint,7)=role.role WHERE (substr(delivery.recipient_endpoint,1,6)=char(30)||'role:' AND role.role IS NULL) OR (substr(delivery.recipient_endpoint,1,6)<>char(30)||'role:' AND endpoint.endpoint IS NULL))
        OR EXISTS (SELECT 1 FROM recipient_cursors AS cursor JOIN conversations AS conversation ON conversation.id=cursor.conversation_id WHERE cursor.sequence<0 OR cursor.sequence>conversation.next_sequence)
        OR EXISTS (SELECT 1 FROM recipient_cursors AS cursor LEFT JOIN endpoints AS endpoint ON endpoint.endpoint=cursor.recipient_endpoint LEFT JOIN roles AS role ON substr(cursor.recipient_endpoint,7)=role.role WHERE (substr(cursor.recipient_endpoint,1,6)=char(30)||'role:' AND role.role IS NULL) OR (substr(cursor.recipient_endpoint,1,6)<>char(30)||'role:' AND endpoint.endpoint IS NULL))
        OR EXISTS (SELECT 1 FROM idempotency WHERE length(request_hash)<>64 OR request_hash GLOB '*[^0-9a-f]*')
		OR EXISTS (SELECT 1 FROM idempotency GROUP BY message_id HAVING count(*)<>1)
        OR EXISTS (SELECT 1 FROM conversation_idempotency WHERE length(request_hash)<>64 OR request_hash GLOB '*[^0-9a-f]*')
		OR EXISTS (SELECT 1 FROM conversation_idempotency GROUP BY conversation_id HAVING count(*)<>1)
		OR EXISTS (SELECT 1 FROM conversation_controls WHERE operation NOT IN ('upsert_member','remove_member') OR member_capabilities<0 OR member_capabilities>15 OR (operation='upsert_member' AND member_capabilities=0) OR (operation='remove_member' AND member_capabilities<>0))
		OR EXISTS (SELECT 1 FROM conversation_controls AS control
			LEFT JOIN endpoints AS actor ON actor.endpoint=control.actor_endpoint
			LEFT JOIN endpoints AS member ON member.endpoint=control.member_endpoint
			WHERE actor.endpoint IS NULL OR member.endpoint IS NULL)
		OR EXISTS (SELECT 1 FROM conversation_control_idempotency WHERE length(request_hash)<>64 OR request_hash GLOB '*[^0-9a-f]*')
		OR EXISTS (SELECT 1 FROM conversation_controls AS control LEFT JOIN conversation_control_idempotency AS retry ON retry.control_id=control.id GROUP BY control.id HAVING count(retry.control_id)<>1)
		OR EXISTS (SELECT 1 FROM uuid_values WHERE typeof(value)<>'text' OR length(value)<>36 OR substr(value,9,1)<>'-' OR substr(value,14,1)<>'-' OR substr(value,19,1)<>'-' OR substr(value,24,1)<>'-' OR lower(replace(value,'-','')) GLOB '*[^0-9a-f]*')
		OR EXISTS (SELECT 1 FROM endpoints WHERE typeof(endpoint)<>'text' OR typeof(machine_id)<>'text' OR typeof(lease_until)<>'integer' OR typeof(ownership_generation)<>'integer' OR (consumer_id IS NOT NULL AND typeof(consumer_id)<>'text') OR typeof(consumer_generation)<>'integer' OR (consumer_lease_until IS NOT NULL AND typeof(consumer_lease_until)<>'integer'))
		OR EXISTS (SELECT 1 FROM conversations WHERE typeof(next_sequence)<>'integer' OR typeof(created_at)<>'integer')
		OR EXISTS (SELECT 1 FROM memberships WHERE typeof(endpoint)<>'text' OR typeof(capabilities)<>'integer')
		OR EXISTS (SELECT 1 FROM roles WHERE typeof(role)<>'text' OR typeof(machine_id)<>'text')
		OR EXISTS (SELECT 1 FROM role_memberships WHERE typeof(role)<>'text' OR typeof(capabilities)<>'integer')
		OR EXISTS (SELECT 1 FROM role_bindings AS binding
			LEFT JOIN roles AS role ON role.role=binding.role
			LEFT JOIN endpoints AS endpoint ON endpoint.endpoint=binding.session_endpoint
			WHERE role.role IS NULL OR endpoint.endpoint IS NULL
				OR typeof(binding.session_endpoint)<>'text' OR typeof(binding.machine_id)<>'text'
				OR typeof(binding.ownership_generation)<>'integer' OR binding.ownership_generation<1
				OR typeof(binding.lease_until)<>'integer' OR role.machine_id<>binding.machine_id
				OR endpoint.machine_id<>binding.machine_id OR endpoint.ownership_generation<>binding.ownership_generation)
		OR EXISTS (SELECT 1 FROM messages WHERE typeof(sequence)<>'integer' OR typeof(from_endpoint)<>'text' OR typeof(body)<>'text' OR typeof(created_at)<>'integer')
		OR EXISTS (SELECT 1 FROM deliveries WHERE typeof(recipient_endpoint)<>'text' OR (lease_machine_id IS NOT NULL AND typeof(lease_machine_id)<>'text') OR typeof(lease_generation)<>'integer' OR (lease_token IS NOT NULL AND (typeof(lease_token)<>'text' OR length(lease_token)<>64 OR lease_token GLOB '*[^0-9a-f]*')) OR (ownership_generation IS NOT NULL AND typeof(ownership_generation)<>'integer') OR (consumer_generation IS NOT NULL AND typeof(consumer_generation)<>'integer') OR (lease_until IS NOT NULL AND typeof(lease_until)<>'integer') OR (acked_at IS NOT NULL AND typeof(acked_at)<>'integer'))
		OR EXISTS (SELECT 1 FROM recipient_cursors WHERE typeof(recipient_endpoint)<>'text' OR typeof(sequence)<>'integer')
		OR EXISTS (SELECT 1 FROM idempotency WHERE typeof(machine_id)<>'text' OR typeof(key)<>'text' OR typeof(request_hash)<>'text' OR typeof(created_at)<>'integer')
		OR EXISTS (SELECT 1 FROM conversation_idempotency WHERE typeof(machine_id)<>'text' OR typeof(key)<>'text' OR typeof(request_hash)<>'text' OR typeof(created_at)<>'integer')
		OR EXISTS (SELECT 1 FROM conversation_controls WHERE typeof(actor_endpoint)<>'text' OR typeof(operation)<>'text' OR typeof(member_endpoint)<>'text' OR typeof(member_capabilities)<>'integer' OR typeof(created_at)<>'integer')
		OR EXISTS (SELECT 1 FROM conversation_control_idempotency WHERE typeof(machine_id)<>'text' OR typeof(key)<>'text' OR typeof(request_hash)<>'text' OR typeof(created_at)<>'integer')
		OR EXISTS (SELECT 1 FROM request_nonces WHERE typeof(machine_id)<>'text' OR typeof(nonce)<>'text' OR typeof(expires_at)<>'integer')
		OR EXISTS (SELECT 1 FROM relay_migration_control WHERE typeof(source_id)<>'text' OR typeof(phase)<>'text' OR (epoch_id IS NOT NULL AND typeof(epoch_id)<>'text') OR (target_identity IS NOT NULL AND typeof(target_identity)<>'text') OR (fingerprint IS NOT NULL AND typeof(fingerprint)<>'text') OR (last_epoch_id IS NOT NULL AND typeof(last_epoch_id)<>'text') OR (last_target_identity IS NOT NULL AND typeof(last_target_identity)<>'text') OR (last_expected_fingerprint IS NOT NULL AND typeof(last_expected_fingerprint)<>'text') OR (last_result_fingerprint IS NOT NULL AND typeof(last_result_fingerprint)<>'text') OR (last_cutoff IS NOT NULL AND typeof(last_cutoff)<>'integer') OR (last_transition IS NOT NULL AND typeof(last_transition)<>'text') OR typeof(changed_at)<>'integer')`
	if profiles {
		logicalStateQuery += `
		OR EXISTS (SELECT 1 FROM role_profiles WHERE direct_addressable NOT IN (0,1) OR typeof(role)<>'text' OR (display_name IS NOT NULL AND typeof(display_name)<>'text') OR typeof(direct_addressable)<>'integer' OR typeof(updated_at)<>'integer')
		OR EXISTS (SELECT 1 FROM role_profiles AS profile LEFT JOIN roles AS role ON role.role=profile.role WHERE role.role IS NULL)
		OR EXISTS (SELECT 1 FROM role_profile_idempotency WHERE length(request_hash)<>64 OR request_hash GLOB '*[^0-9a-f]*' OR direct_addressable NOT IN (0,1))
		OR EXISTS (SELECT 1 FROM role_profile_idempotency AS retry LEFT JOIN role_profiles AS profile ON profile.role=retry.role WHERE profile.role IS NULL
			OR typeof(retry.machine_id)<>'text' OR typeof(retry.key)<>'text' OR typeof(retry.request_hash)<>'text' OR typeof(retry.role)<>'text'
			OR (retry.display_name IS NOT NULL AND typeof(retry.display_name)<>'text') OR typeof(retry.direct_addressable)<>'integer' OR typeof(retry.updated_at)<>'integer' OR typeof(retry.created_at)<>'integer')`
	}
	if !controls {
		for _, clause := range []string{
			"\n\t\tUNION ALL SELECT id FROM conversation_controls UNION ALL SELECT conversation_id FROM conversation_controls\n\t\tUNION ALL SELECT control_id FROM conversation_control_idempotency",
			"\n\t\tOR EXISTS (SELECT 1 FROM conversation_controls WHERE operation NOT IN ('upsert_member','remove_member') OR member_capabilities<0 OR member_capabilities>15 OR (operation='upsert_member' AND member_capabilities=0) OR (operation='remove_member' AND member_capabilities<>0))",
			"\n\t\tOR EXISTS (SELECT 1 FROM conversation_controls AS control\n\t\t\tLEFT JOIN endpoints AS actor ON actor.endpoint=control.actor_endpoint\n\t\t\tLEFT JOIN endpoints AS member ON member.endpoint=control.member_endpoint\n\t\t\tWHERE actor.endpoint IS NULL OR member.endpoint IS NULL)",
			"\n\t\tOR EXISTS (SELECT 1 FROM conversation_control_idempotency WHERE length(request_hash)<>64 OR request_hash GLOB '*[^0-9a-f]*')",
			"\n\t\tOR EXISTS (SELECT 1 FROM conversation_controls AS control LEFT JOIN conversation_control_idempotency AS retry ON retry.control_id=control.id GROUP BY control.id HAVING count(retry.control_id)<>1)",
			"\n\t\tOR EXISTS (SELECT 1 FROM conversation_controls WHERE typeof(actor_endpoint)<>'text' OR typeof(operation)<>'text' OR typeof(member_endpoint)<>'text' OR typeof(member_capabilities)<>'integer' OR typeof(created_at)<>'integer')",
			"\n\t\tOR EXISTS (SELECT 1 FROM conversation_control_idempotency WHERE typeof(machine_id)<>'text' OR typeof(key)<>'text' OR typeof(request_hash)<>'text' OR typeof(created_at)<>'integer')",
		} {
			logicalStateQuery = strings.ReplaceAll(logicalStateQuery, clause, "")
		}
	}
	var invalidLogicalState bool
	if err := q.QueryRowContext(ctx, logicalStateQuery).Scan(&invalidLogicalState); err != nil || invalidLogicalState {
		return errors.New("relay migration source logical constraints are invalid")
	}
	if !controls {
		return nil
	}
	controlRows, err := q.QueryContext(ctx, `SELECT retry.request_hash,control.conversation_id,control.actor_endpoint,control.operation,control.member_endpoint,control.member_capabilities
		FROM conversation_control_idempotency AS retry
		JOIN conversation_controls AS control ON control.id=retry.control_id`)
	if err != nil {
		return errors.New("relay migration source control retry binding is unavailable")
	}
	defer func() { _ = controlRows.Close() }()
	for controlRows.Next() {
		var requestHash, conversationID, actorEndpoint, operation, memberEndpoint string
		var capabilities Capability
		if err := controlRows.Scan(&requestHash, &conversationID, &actorEndpoint, &operation, &memberEndpoint, &capabilities); err != nil || requestHash != ControlRequestHash(ControlInput{ConversationID: conversationID, ActorEndpoint: actorEndpoint, Operation: ControlOperation(operation), Member: Member{Endpoint: memberEndpoint, Capabilities: capabilities}}) {
			return errors.New("relay migration source control retry binding is invalid")
		}
	}
	if err := controlRows.Err(); err != nil {
		return errors.New("relay migration source control retry binding is unavailable")
	}
	return nil
}

func validateMigrationSourceValue(table, column string, value any) error {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	var valid bool
	switch table + "." + column {
	case "endpoints.endpoint", "memberships.endpoint", "messages.from_endpoint", "role_bindings.session_endpoint", "conversation_controls.actor_endpoint", "conversation_controls.member_endpoint":
		valid = ValidEndpoint(text)
	case "roles.role", "role_memberships.role", "role_bindings.role", "role_profiles.role", "role_profile_idempotency.role":
		valid = ValidRole(text)
	case "endpoints.machine_id", "roles.machine_id", "role_bindings.machine_id", "deliveries.lease_machine_id", "idempotency.machine_id", "conversation_idempotency.machine_id", "conversation_control_idempotency.machine_id", "role_profile_idempotency.machine_id", "request_nonces.machine_id":
		valid = ValidMachineID(text)
	case "deliveries.recipient_endpoint", "recipient_cursors.recipient_endpoint":
		_, roleRecipient := parseRoleRecipient(text)
		valid = roleRecipient || ValidEndpoint(text)
	case "endpoints.consumer_id", "idempotency.key", "conversation_idempotency.key", "conversation_control_idempotency.key", "role_profile_idempotency.key", "request_nonces.nonce":
		valid = ValidRequestToken(text)
	case "role_profiles.display_name", "role_profile_idempotency.display_name":
		_, valid = NormalizeRoleDisplayName(text)
	case "messages.body":
		valid = ValidMessageBody(text)
	case "conversations.id", "memberships.conversation_id", "messages.id", "messages.conversation_id", "deliveries.id", "deliveries.message_id", "recipient_cursors.conversation_id", "idempotency.message_id", "conversation_idempotency.conversation_id", "conversation_controls.id", "conversation_controls.conversation_id", "conversation_control_idempotency.control_id":
		valid = uuid.Validate(text) == nil
	default:
		return nil
	}
	if !valid {
		return errors.New("relay migration source contains invalid portable text")
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
		if !utf8.ValidString(typed) || strings.ContainsRune(typed, 0) {
			return errors.New("relay migration source contains non-portable text")
		}
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
	case "roles":
		manifest.Counts.Roles, manifest.TableSHA256.Roles = count, digest
	case "role_memberships":
		manifest.Counts.RoleMemberships, manifest.TableSHA256.RoleMemberships = count, digest
	case "role_bindings":
		manifest.Counts.RoleBindings, manifest.TableSHA256.RoleBindings = count, digest
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
	case "conversation_controls":
		manifest.Counts.ControlEvents, manifest.TableSHA256.ControlEvents = count, digest
	case "conversation_control_idempotency":
		manifest.Counts.ControlIdempotency, manifest.TableSHA256.ControlIdempotency = count, digest
	case "role_profiles":
		manifest.Counts.RoleProfiles, manifest.TableSHA256.RoleProfiles = count, digest
	case "role_profile_idempotency":
		manifest.Counts.RoleProfileIdempotency, manifest.TableSHA256.RoleProfileIdempotency = count, digest
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
		return nil, errors.New("relay migration source parent must be a real directory")
	}
	// The later host-local executor supplies this privileged path from Punaro's
	// private relay data directory; it is not a caller-selected confinement root.
	// Reject last-hop redirection while allowing platform aliases in ancestors.
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
