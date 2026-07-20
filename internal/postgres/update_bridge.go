package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
)

// V5UpdateBridge is the one-time transactional bridge from the last schema
// that predates the durable mutation fence. Its transaction retains exclusive
// locks on every v5 mutable relation until the caller has stopped all writers.
type V5UpdateBridge struct {
	mu          sync.Mutex
	database    *sql.DB
	connection  *sql.Conn
	transaction *sql.Tx
	update      UpdateTransaction
	closed      bool
}

func validateV5BridgeRequest(request UpdateRequest) error {
	if request.Validate() != nil || request.SourceSchema != 5 || request.TargetSchema != 6 {
		return errors.New("v5 update bridge requires the exact v5 to v6 boundary")
	}
	return nil
}

// BeginV5UpdateBridge drains v5 writes under ACCESS EXCLUSIVE locks, installs
// only the additive update-control migration, and stages the durable fence in
// the same uncommitted owner transaction. The caller must stop every writer and
// then call CommitWritersStopped; a crash or Abort rolls everything back.
func BeginV5UpdateBridge(ctx context.Context, cfg Config, request UpdateRequest) (*V5UpdateBridge, error) {
	if validateV5BridgeRequest(request) != nil {
		return nil, errors.New("invalid v5 update bridge request")
	}
	dsn, err := ReadDSNFile(cfg.DSNFile)
	if err != nil {
		return nil, err
	}
	database, err := open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	closeDatabase := true
	defer func() {
		if closeDatabase {
			_ = database.Close()
		}
	}()
	connection, err := database.Conn(ctx)
	if err != nil {
		return nil, errors.New("v5 update bridge connection is unavailable")
	}
	closeConnection := true
	defer func() {
		if closeConnection {
			_ = connection.Close()
		}
	}()
	if err := verifyMigrationRoles(ctx, connection); err != nil {
		return nil, err
	}
	snapshot, err := inspect(ctx, connection)
	if err != nil {
		return nil, err
	}
	state := Classify(snapshot, CurrentManifest())
	if state.Classification != UpgradeRequired || state.Version != 5 {
		return nil, errors.New("v5 update bridge requires an intact v5 schema")
	}
	var postgresMajor int
	if err := connection.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::integer / 10000`).Scan(&postgresMajor); err != nil || postgresMajor != request.PostgresMajor {
		return nil, errors.New("v5 update bridge PostgreSQL major does not match the target release")
	}
	existingControls, controlsErr := updateControlsAvailable(ctx, connection)
	if controlsErr != nil {
		return nil, controlsErr
	}
	tx, err := connection.BeginTx(ctx, nil)
	if err != nil {
		return nil, errors.New("v5 update bridge transaction cannot start")
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '30s'`); err != nil {
		return nil, errors.New("v5 update bridge lock timeout cannot be bounded")
	}
	if !existingControls {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(579001230607)`); err != nil {
			return nil, errors.New("v5 update bridge coordinator lock is unavailable")
		}
		if _, err := tx.ExecContext(ctx, `LOCK TABLE
jobs.schema_migrations, jobs.server_state,
auth.principals, relay.projects, auth.capability_grants,
relay.idempotency_records, audit.events, jobs.queue_capacity, jobs.outbox,
auth.installation_owner, auth.pending_enrollments, auth.pending_enrollment_grants,
auth.device_credentials, auth.legacy_auth_state, auth.legacy_machines,
auth.project_acl_state, relay.project_identities, relay.project_lookup_aliases,
relay.project_merge_previews, attachment.ready_blob_manifest
IN ACCESS EXCLUSIVE MODE`); err != nil {
			return nil, errors.New("v5 application mutations could not be drained")
		}
		migration := CurrentManifest().Migrations[5]
		if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
			return nil, errors.New("v5 update bridge controls could not be installed")
		}
	}
	update, err := scanUpdate(tx.QueryRowContext(ctx, `SELECT `+updateSelectColumns+` FROM jobs.begin_update($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, request.UpdateID, request.SourceRelease, request.TargetRelease, request.SourceImage, request.TargetImage, request.SourceSchema, request.TargetSchema, request.SchemaMin, request.SchemaMax, request.RollbackFloor, request.PostgresMajor, request.ReleaseSHA256, request.ComposeSHA256, request.MigrationManifestSHA256))
	if err != nil {
		return nil, errors.New("v5 update bridge fence could not be staged")
	}
	rollback = false
	closeConnection = false
	closeDatabase = false
	return &V5UpdateBridge{database: database, connection: connection, transaction: tx, update: update}, nil
}

// Update returns the immutable staged transaction identity.
func (bridge *V5UpdateBridge) Update() UpdateTransaction {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	return bridge.update
}

// CommitWritersStopped durably publishes both the fence and the proof that the
// old writer set was stopped while its relation locks were still held.
func (bridge *V5UpdateBridge) CommitWritersStopped(ctx context.Context) (UpdateTransaction, error) {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed || bridge.transaction == nil {
		return UpdateTransaction{}, errors.New("v5 update bridge is closed")
	}
	update, err := scanUpdate(bridge.transaction.QueryRowContext(ctx, `SELECT `+updateSelectColumns+` FROM jobs.advance_update($1::uuid,'fenced','writers_stopped',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`, bridge.update.UpdateID))
	if err != nil {
		return UpdateTransaction{}, errors.New("v5 update bridge writer stop could not be staged")
	}
	if err := bridge.transaction.Commit(); err != nil {
		bridge.close()
		return UpdateTransaction{}, errors.New("v5 update bridge outcome is uncertain; inspect the durable update transaction")
	}
	bridge.update = update
	bridge.close()
	return update, nil
}

// Abort rolls back the uncommitted bridge. It is safe only before the caller
// reports writer shutdown as complete.
func (bridge *V5UpdateBridge) Abort() error {
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.closed {
		return nil
	}
	err := bridge.transaction.Rollback()
	bridge.close()
	return err
}

func (bridge *V5UpdateBridge) close() {
	bridge.closed = true
	bridge.transaction = nil
	if bridge.connection != nil {
		_ = bridge.connection.Close()
		bridge.connection = nil
	}
	if bridge.database != nil {
		_ = bridge.database.Close()
		bridge.database = nil
	}
}
