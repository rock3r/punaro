package v2

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// sqlite provides the durable local anti-rollback checkpoint database.
	_ "modernc.org/sqlite"
)

// SQLiteCheckpointStore is the durable, local anti-rollback and equivocation
// store for one attachment verifier. Its database must be private to the
// adapter or relay service account.
type SQLiteCheckpointStore struct{ db *sql.DB }

// OpenSQLiteCheckpointStore opens a private SQLite checkpoint store in WAL
// mode. It creates the parent directory with service-private permissions.
func OpenSQLiteCheckpointStore(path string) (*SQLiteCheckpointStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("directory checkpoint path is required")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create directory checkpoint directory: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !isPrivateStateParent(parentInfo) {
		return nil, errors.New("directory checkpoint parent must be private and non-symlinked")
	}
	if info, err := os.Lstat(path); err == nil {
		if !isPrivateStateFile(info) {
			return nil, errors.New("directory checkpoint database must be private and non-symlinked")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect directory checkpoint database: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open directory checkpoint store: %w", err)
	}
	for _, statement := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		`CREATE TABLE IF NOT EXISTS directory_checkpoints (
			audience BLOB PRIMARY KEY, sequence BLOB NOT NULL, tree_size BLOB NOT NULL,
			tree_root BLOB NOT NULL, revocation_epoch BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS directory_freezes (
			audience BLOB PRIMARY KEY, evidence BLOB NOT NULL
		)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize directory checkpoint store: %w", err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("secure directory checkpoint database: %w", err)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Lstat(sidecar); err == nil {
			if err := os.Chmod(sidecar, 0o600); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("secure directory checkpoint sidecar: %w", err)
			}
		}
	}
	return &SQLiteCheckpointStore{db: db}, nil
}

// Close closes the local checkpoint database.
func (s *SQLiteCheckpointStore) Close() error { return s.db.Close() }

// Advance serializes all checkpoint comparisons, proof validation, updates,
// and equivocation freezes in one SQLite IMMEDIATE transaction. A caller can
// never observe a successful advance that is subsequently overwritten by an
// older concurrent advance.
func (s *SQLiteCheckpointStore) Advance(audience [32]byte, next DirectoryCheckpoint, evidence []byte, proof *FullConsistencyProof) error {
	if next.Sequence == 0 || next.TreeSize == 0 || isZero32(next.TreeRoot) || len(evidence) == 0 || len(evidence) > maxDirectoryHead {
		return errors.New("invalid directory checkpoint advance")
	}
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin directory checkpoint advance: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()
	var frozen int
	err = conn.QueryRowContext(ctx, "SELECT 1 FROM directory_freezes WHERE audience = ?", audience[:]).Scan(&frozen)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	previous, found, err := loadCheckpoint(ctx, conn, audience)
	if err != nil {
		return err
	}
	save, freeze, result := advanceCheckpoint(previous, found, err == nil && frozen == 1, next, proof)
	if freeze {
		if _, err := conn.ExecContext(ctx, "INSERT INTO directory_freezes(audience, evidence) VALUES (?, ?) ON CONFLICT(audience) DO NOTHING", audience[:], evidence); err != nil {
			return fmt.Errorf("freeze directory equivocation: %w", err)
		}
	}
	if save {
		if _, err := conn.ExecContext(ctx, `INSERT INTO directory_checkpoints(audience, sequence, tree_size, tree_root, revocation_epoch)
			VALUES (?, ?, ?, ?, ?) ON CONFLICT(audience) DO UPDATE SET sequence = excluded.sequence, tree_size = excluded.tree_size, tree_root = excluded.tree_root, revocation_epoch = excluded.revocation_epoch`, audience[:], uint64Bytes(next.Sequence), uint64Bytes(next.TreeSize), next.TreeRoot[:], uint64Bytes(next.RevocationEpoch)); err != nil {
			return fmt.Errorf("save directory checkpoint: %w", err)
		}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit directory checkpoint advance: %w", err)
	}
	committed = true
	return result
}

// LoadCheckpoint returns the last accepted directory checkpoint for audience.
func (s *SQLiteCheckpointStore) LoadCheckpoint(audience [32]byte) (DirectoryCheckpoint, bool, error) {
	return loadCheckpoint(context.Background(), s.db, audience)
}

type checkpointQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadCheckpoint(ctx context.Context, queryer checkpointQueryer, audience [32]byte) (DirectoryCheckpoint, bool, error) {
	var sequence, size, root, epoch []byte
	err := queryer.QueryRowContext(ctx, "SELECT sequence, tree_size, tree_root, revocation_epoch FROM directory_checkpoints WHERE audience = ?", audience[:]).Scan(&sequence, &size, &root, &epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return DirectoryCheckpoint{}, false, nil
	}
	if err != nil {
		return DirectoryCheckpoint{}, false, err
	}
	if len(root) != 32 {
		return DirectoryCheckpoint{}, false, errors.New("invalid stored directory checkpoint")
	}
	checkpoint := DirectoryCheckpoint{Sequence: uint64FromBytes(sequence), TreeSize: uint64FromBytes(size), RevocationEpoch: uint64FromBytes(epoch)}
	copy(checkpoint.TreeRoot[:], root)
	if len(sequence) != 8 || len(size) != 8 || len(epoch) != 8 || checkpoint.Sequence == 0 || checkpoint.TreeSize == 0 || isZero32(checkpoint.TreeRoot) {
		return DirectoryCheckpoint{}, false, errors.New("invalid stored directory checkpoint")
	}
	return checkpoint, true, nil
}

// SaveCheckpoint atomically records the latest verified directory state.
func (s *SQLiteCheckpointStore) SaveCheckpoint(audience [32]byte, checkpoint DirectoryCheckpoint) error {
	if checkpoint.Sequence == 0 || checkpoint.TreeSize == 0 || isZero32(checkpoint.TreeRoot) {
		return errors.New("invalid directory checkpoint")
	}
	_, err := s.db.ExecContext(context.Background(), `INSERT INTO directory_checkpoints(audience, sequence, tree_size, tree_root, revocation_epoch)
		VALUES (?, ?, ?, ?, ?) ON CONFLICT(audience) DO UPDATE SET sequence = excluded.sequence, tree_size = excluded.tree_size, tree_root = excluded.tree_root, revocation_epoch = excluded.revocation_epoch`, audience[:], uint64Bytes(checkpoint.Sequence), uint64Bytes(checkpoint.TreeSize), checkpoint.TreeRoot[:], uint64Bytes(checkpoint.RevocationEpoch))
	return err
}

// FreezeAudience durably prevents further attachment authority use after an
// equivocation observation while retaining bounded evidence for recovery.
func (s *SQLiteCheckpointStore) FreezeAudience(audience [32]byte, evidence []byte) error {
	if len(evidence) == 0 || len(evidence) > maxDirectoryHead {
		return errors.New("invalid directory equivocation evidence")
	}
	_, err := s.db.ExecContext(context.Background(), "INSERT INTO directory_freezes(audience, evidence) VALUES (?, ?) ON CONFLICT(audience) DO NOTHING", audience[:], evidence)
	return err
}

// AudienceFrozen reports whether this verifier observed an unrecovered
// equivocation for audience.
func (s *SQLiteCheckpointStore) AudienceFrozen(audience [32]byte) (bool, error) {
	var found int
	err := s.db.QueryRowContext(context.Background(), "SELECT 1 FROM directory_freezes WHERE audience = ?", audience[:]).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func uint64Bytes(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	return result
}

func uint64FromBytes(raw []byte) uint64 {
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}
