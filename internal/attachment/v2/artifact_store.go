package v2

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// sqlite provides durable source-artifact uniqueness reservations.
	_ "modernc.org/sqlite"
)

// SQLiteSourceReservationStore durably prevents file-key, content-salt, and
// nonce-tuple reuse. Its database must be on local persistent storage owned by
// the adapter service account; a lost database is a security incident, not a
// recoverable cache miss.
type SQLiteSourceReservationStore struct{ db *sql.DB }

// OpenSQLiteSourceReservationStore opens a service-private reservation store.
func OpenSQLiteSourceReservationStore(path string) (*SQLiteSourceReservationStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("source reservation path is required")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create source reservation directory: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("source reservation parent must be private and non-symlinked")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("source reservation database must be private and non-symlinked")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect source reservation database: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open source reservation store: %w", err)
	}
	for _, statement := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		`CREATE TABLE IF NOT EXISTS source_file_keys (commitment BLOB PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS source_content_salts (commitment BLOB PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS source_nonce_tuples (
			transfer_id BLOB NOT NULL, manifest_commitment BLOB NOT NULL,
			chunk_index BLOB NOT NULL,
			PRIMARY KEY(transfer_id, manifest_commitment, chunk_index)
		)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize source reservation store: %w", err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("secure source reservation database: %w", err)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Lstat(sidecar); err == nil {
			if err := os.Chmod(sidecar, 0o600); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("secure source reservation sidecar: %w", err)
			}
		}
	}
	return &SQLiteSourceReservationStore{db: db}, nil
}

// Close closes the durable reservation database.
func (s *SQLiteSourceReservationStore) Close() error { return s.db.Close() }

// Reserve atomically persists all uniqueness commitments before encryption.
func (s *SQLiteSourceReservationStore) Reserve(fileKey, contentSalt [32]byte, nonces []NonceReservation) error {
	if s == nil || isZero32(fileKey) || isZero32(contentSalt) || len(nonces) == 0 || len(nonces) > 4096 {
		return errors.New("invalid source reservation")
	}
	seen := make(map[NonceReservation]struct{}, len(nonces))
	for _, nonce := range nonces {
		if isZero16(nonce.TransferID) || isZero32(nonce.ManifestCommitment) {
			return errors.New("invalid source nonce reservation")
		}
		if _, exists := seen[nonce]; exists {
			return errors.New("duplicate source nonce reservation")
		}
		seen[nonce] = struct{}{}
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin source reservation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO source_file_keys(commitment) VALUES (?)", fileKey[:]); err != nil {
		return errors.New("source file-key commitment is already reserved")
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO source_content_salts(commitment) VALUES (?)", contentSalt[:]); err != nil {
		return errors.New("source content-salt commitment is already reserved")
	}
	for _, nonce := range nonces {
		if _, err := tx.ExecContext(context.Background(), "INSERT INTO source_nonce_tuples(transfer_id, manifest_commitment, chunk_index) VALUES (?, ?, ?)", nonce.TransferID[:], nonce.ManifestCommitment[:], uint64Bytes(nonce.ChunkIndex)); err != nil {
			return errors.New("source nonce tuple is already reserved")
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit source reservation: %w", err)
	}
	return nil
}

var _ SourceReservationStore = (*SQLiteSourceReservationStore)(nil)
