package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	punarobackup "github.com/rock3r/punaro/internal/backup"
)

const backupFenceLifetime = 5 * time.Minute
const backupFenceSQLLifetime = "5 minutes"

// DumpSnapshot writes a PostgreSQL custom-format dump using the exact exported
// snapshot while the exporting transaction remains open.
type DumpSnapshot func(context.Context, string, string, string) error

// BackupSource opens exact, GC-fenced application-role backup snapshots.
type BackupSource struct {
	database         *Database
	dumpDSNFile      string
	dump             DumpSnapshot
	openFenceSession func(context.Context, string) (backupFenceSession, error)
}

type backupFenceSession interface {
	Release(context.Context, string, string, bool) (bool, error)
	Reconcile(context.Context, string, string, bool) (bool, error)
	Close() error
}

type postgresBackupFenceSession struct {
	administration *Administration
}

func (session *postgresBackupFenceSession) Release(ctx context.Context, token, snapshotID string, verified bool) (bool, error) {
	return releaseBackupGCFence(ctx, session.administration.db, token, snapshotID, verified)
}

func (session *postgresBackupFenceSession) Reconcile(ctx context.Context, token, snapshotID string, verified bool) (bool, error) {
	return reconcileBackupGCFence(ctx, session.administration.db, token, snapshotID, verified)
}

func (session *postgresBackupFenceSession) Close() error {
	return session.administration.Close()
}

type backupSnapshotFinisher struct {
	mu       sync.Mutex
	stopped  bool
	terminal bool
	stop     func() error
	finalize func(context.Context, bool) (bool, error)
	stopErr  error
	result   error
}

func (finisher *backupSnapshotFinisher) Finish(ctx context.Context, verified bool) error {
	finisher.mu.Lock()
	defer finisher.mu.Unlock()

	if finisher.terminal {
		return finisher.result
	}
	if !finisher.stopped {
		finisher.stopped = true
		finisher.stopErr = finisher.stop()
	}
	if finisher.stopErr != nil {
		verified = false
	}
	confirmed, err := finisher.finalize(ctx, verified)
	if !confirmed {
		return errors.New("PostgreSQL backup GC fence could not be released")
	}
	finisher.terminal = true
	if err != nil {
		finisher.result = errors.New("PostgreSQL backup authority could not close")
	} else {
		finisher.result = finisher.stopErr
	}
	return finisher.result
}

func openBackupFenceSession(ctx context.Context, dsnFile string) (backupFenceSession, error) {
	administration, err := OpenAdministration(ctx, Config{DSNFile: dsnFile})
	if err != nil {
		return nil, err
	}
	return &postgresBackupFenceSession{administration: administration}, nil
}

func finalizeBackupGCFence(ctx context.Context, openSession func(context.Context, string) (backupFenceSession, error), dsnFile, token, snapshotID string, verified bool) (bool, error) {
	attemptCtx := context.WithoutCancel(ctx)
	openCtx, cancelOpen := context.WithTimeout(attemptCtx, operationTimeout)
	session, err := openSession(openCtx, dsnFile)
	cancelOpen()
	if err != nil {
		return false, err
	}
	confirmed, finishErr := session.Release(attemptCtx, token, snapshotID, verified)
	if finishErr != nil {
		confirmed, finishErr = session.Reconcile(attemptCtx, token, snapshotID, verified)
	}
	closeErr := session.Close()
	if finishErr != nil || !confirmed {
		if finishErr == nil {
			finishErr = errors.New("PostgreSQL backup GC fence release was rejected")
		}
		return false, finishErr
	}
	return true, closeErr
}

func releaseBackupGCFence(ctx context.Context, db *sql.DB, token, snapshotID string, verified bool) (bool, error) {
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
	defer cancel()
	var released bool
	err := db.QueryRowContext(releaseCtx, `SELECT jobs.release_backup_gc_fence($1::uuid, $2, $3)`, token, snapshotID, verified).Scan(&released)
	return released, err
}

func reconcileBackupGCFence(ctx context.Context, db *sql.DB, token, snapshotID string, verified bool) (bool, error) {
	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
	defer cancel()
	var released bool
	var recorded sql.NullBool
	err := db.QueryRowContext(reconcileCtx, `SELECT released_at IS NOT NULL, verified FROM jobs.backup_gc_fences WHERE fence_id = $1::uuid AND snapshot_id = $2`, token, snapshotID).Scan(&released, &recorded)
	if errors.Is(err, sql.ErrNoRows) {
		if verified {
			return false, errors.New("PostgreSQL backup GC fence could not be released")
		}
		return true, nil
	}
	if err != nil || !released || (verified && (!recorded.Valid || !recorded.Bool)) {
		return false, errors.New("PostgreSQL backup GC fence release could not be confirmed")
	}
	return true, nil
}

// NewBackupSource binds an application database to a password-safe pg_dump
// adapter. The adapter receives the protected DSN file path, not its contents.
func NewBackupSource(database *Database, dumpDSNFile string, dump DumpSnapshot) (*BackupSource, error) {
	if database == nil || database.db == nil || dumpDSNFile == "" || dump == nil {
		return nil, errors.New("PostgreSQL backup source is unavailable")
	}
	return &BackupSource{
		database:         database,
		dumpDSNFile:      dumpDSNFile,
		dump:             dump,
		openFenceSession: openBackupFenceSession,
	}, nil
}

// Begin acquires and commits a GC fence before exporting one repeatable-read
// snapshot. READY blob metadata and server coordinates come from that snapshot.
func (source *BackupSource) Begin(ctx context.Context) (*punarobackup.Snapshot, error) {
	administration, err := OpenAdministration(ctx, Config{DSNFile: source.dumpDSNFile})
	if err != nil {
		return nil, errors.New("PostgreSQL backup authority is unavailable")
	}
	administrationOwned := true
	defer func() {
		if administrationOwned {
			_ = administration.Close()
		}
	}()
	var token string
	if err := administration.db.QueryRowContext(ctx, `SELECT jobs.acquire_backup_gc_fence($1::interval)::text`, backupFenceSQLLifetime).Scan(&token); err != nil {
		return nil, errors.New("PostgreSQL backup GC fence could not be acquired")
	}
	var snapshotID string
	bound := false
	sessionReady := false
	defer func() {
		if !sessionReady {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
			defer cancel()
			if bound {
				_, _ = administration.db.ExecContext(cleanupCtx, `SELECT jobs.release_backup_gc_fence($1::uuid, $2, false)`, token, snapshotID)
			} else {
				_, _ = administration.db.ExecContext(cleanupCtx, `SELECT jobs.cancel_unbound_backup_gc_fence($1::uuid)`, token)
			}
		}
	}()
	tx, err := source.database.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, errors.New("PostgreSQL backup snapshot could not start")
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	manifest := CurrentManifest()
	catalog, err := inspect(ctx, tx)
	if err != nil {
		return nil, errors.New("PostgreSQL backup schema cannot be inspected")
	}
	schemaState := Classify(catalog, manifest)
	if schemaState.Classification != Compatible || schemaState.Version != manifest.MaxSupported {
		return nil, errors.New("PostgreSQL backup requires the exact current schema")
	}
	var state punarobackup.State
	if err := tx.QueryRowContext(ctx, `SELECT pg_export_snapshot(), state.installation_id::text, state.timeline_id::text, state.change_sequence
FROM jobs.server_state AS state WHERE state.singleton`).Scan(&snapshotID, &state.InstallationID, &state.TimelineID, &state.ChangeSequence); err != nil {
		return nil, errors.New("PostgreSQL backup snapshot metadata is unavailable")
	}
	var didBind bool
	if err := administration.db.QueryRowContext(ctx, `SELECT jobs.bind_backup_snapshot($1::uuid, $2)`, token, snapshotID).Scan(&didBind); err != nil || !didBind {
		return nil, errors.New("PostgreSQL backup snapshot could not be fenced")
	}
	bound = true
	rows, err := tx.QueryContext(ctx, `SELECT storage_path, size_bytes, sha256 FROM attachment.ready_blob_manifest ORDER BY storage_path`)
	if err != nil {
		return nil, errors.New("PostgreSQL READY blob manifest is unavailable")
	}
	blobs := make([]punarobackup.Blob, 0)
	for rows.Next() {
		var blob punarobackup.Blob
		if err := rows.Scan(&blob.StoragePath, &blob.Size, &blob.SHA256); err != nil {
			_ = rows.Close()
			return nil, errors.New("PostgreSQL READY blob manifest is malformed")
		}
		blobs = append(blobs, blob)
	}
	if err := rows.Close(); err != nil || rows.Err() != nil {
		return nil, errors.New("PostgreSQL READY blob manifest is unavailable")
	}
	rollback = false
	stopRenewal := make(chan struct{})
	renewalDone := make(chan struct{})
	var renewalMu sync.Mutex
	var renewalErr error
	go func() {
		defer close(renewalDone)
		ticker := time.NewTicker(backupFenceLifetime / 3)
		defer ticker.Stop()
		for {
			select {
			case <-stopRenewal:
				return
			case <-ticker.C:
				renewCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
				var renewed bool
				renewErr := administration.db.QueryRowContext(renewCtx, `SELECT jobs.renew_backup_gc_fence($1::uuid, $2, $3::interval)`, token, snapshotID, backupFenceSQLLifetime).Scan(&renewed)
				cancel()
				if renewErr != nil || !renewed {
					renewalMu.Lock()
					renewalErr = errors.New("PostgreSQL backup GC fence renewal failed")
					renewalMu.Unlock()
					return
				}
			}
		}
	}()
	finisher := &backupSnapshotFinisher{
		stop: func() error {
			close(stopRenewal)
			<-renewalDone
			var finishErr error
			renewalMu.Lock()
			if renewalErr != nil {
				finishErr = renewalErr
			}
			renewalMu.Unlock()
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) && finishErr == nil {
				finishErr = errors.New("PostgreSQL backup snapshot could not close")
			}
			if err := administration.Close(); err != nil && finishErr == nil {
				finishErr = errors.New("PostgreSQL backup authority could not close")
			}
			return finishErr
		},
		finalize: func(finishCtx context.Context, verified bool) (bool, error) {
			return finalizeBackupGCFence(finishCtx, source.openFenceSession, source.dumpDSNFile, token, snapshotID, verified)
		},
	}
	sessionReady = true
	administrationOwned = false
	return &punarobackup.Snapshot{
		ID:            snapshotID,
		SchemaVersion: schemaState.Version,
		State:         state,
		ReadyBlobs:    blobs,
		Dump: func(dumpCtx context.Context, destination string) error {
			return source.dump(dumpCtx, source.dumpDSNFile, snapshotID, destination)
		},
		Finish: finisher.Finish,
	}, nil
}

// RotateRestoredTimeline makes later cursors from the abandoned timeline
// distinguishable immediately after a verified clean-stack restore.
func (a *Administration) RotateRestoredTimeline(ctx context.Context, backupID string, expected InstallationState) (InstallationState, error) {
	var state InstallationState
	err := a.db.QueryRowContext(ctx, `SELECT installation_id::text, timeline_id::text, change_sequence
FROM jobs.rotate_restored_timeline($1::uuid, $2::uuid, $3::uuid, $4)`, backupID, expected.InstallationID, expected.TimelineID, expected.ChangeSequence).Scan(&state.InstallationID, &state.TimelineID, &state.ChangeSequence)
	if err != nil || state.InstallationID != expected.InstallationID || state.TimelineID == expected.TimelineID || state.ChangeSequence != expected.ChangeSequence {
		return InstallationState{}, errors.New("restored PostgreSQL timeline could not be rotated")
	}
	return state, nil
}

var (
	// ErrCursorTimelineChanged requires authoritative re-enumeration.
	ErrCursorTimelineChanged = errors.New("cursor timeline changed")
	// ErrCursorFromFuture rejects coordinates beyond the current restore point.
	ErrCursorFromFuture = errors.New("cursor is from the future")
)

// ValidateCursor rejects other installations, abandoned timelines, and future
// coordinates instead of silently accepting stale pre-restore caches.
func ValidateCursor(current, cursor InstallationState) error {
	if current.InstallationID == "" || cursor.InstallationID != current.InstallationID || cursor.TimelineID != current.TimelineID {
		return ErrCursorTimelineChanged
	}
	if cursor.ChangeSequence < 0 || cursor.ChangeSequence > current.ChangeSequence {
		return ErrCursorFromFuture
	}
	return nil
}
