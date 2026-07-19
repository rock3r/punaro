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
	database    *Database
	dumpDSNFile string
	dump        DumpSnapshot
}

// NewBackupSource binds an application database to a password-safe pg_dump
// adapter. The adapter receives the protected DSN file path, not its contents.
func NewBackupSource(database *Database, dumpDSNFile string, dump DumpSnapshot) (*BackupSource, error) {
	if database == nil || database.db == nil || dumpDSNFile == "" || dump == nil {
		return nil, errors.New("PostgreSQL backup source is unavailable")
	}
	return &BackupSource{database: database, dumpDSNFile: dumpDSNFile, dump: dump}, nil
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
	var finishOnce sync.Once
	var finishErr error
	finish := func(_ context.Context, verified bool) error {
		finishOnce.Do(func() {
			close(stopRenewal)
			<-renewalDone
			renewalMu.Lock()
			if renewalErr != nil {
				verified = false
				finishErr = renewalErr
			}
			renewalMu.Unlock()
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) && finishErr == nil {
				verified = false
				finishErr = errors.New("PostgreSQL backup snapshot could not close")
			}
			releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), operationTimeout)
			defer cancel()
			var released bool
			if err := administration.db.QueryRowContext(releaseCtx, `SELECT jobs.release_backup_gc_fence($1::uuid, $2, $3)`, token, snapshotID, verified).Scan(&released); err != nil || !released {
				finishErr = errors.New("PostgreSQL backup GC fence could not be released")
			}
			if err := administration.Close(); err != nil && finishErr == nil {
				finishErr = errors.New("PostgreSQL backup authority could not close")
			}
		})
		return finishErr
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
		Finish: finish,
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
