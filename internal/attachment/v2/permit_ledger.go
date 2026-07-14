package v2

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxOperationResultBytes = 4 << 10

// PermitMutation applies the concrete attachment state transition in the same
// transaction as operation redemption. It must not perform external I/O.
type PermitMutation func(context.Context, *sql.Tx) ([]byte, error)

// SQLitePermitLedger stores issued permits and exact operation results.
type SQLitePermitLedger struct{ db *sql.DB }

// OpenSQLitePermitLedger opens a private, durable permit ledger.
func OpenSQLitePermitLedger(path string) (*SQLitePermitLedger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("permit ledger path is required")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create permit ledger directory: %w", err)
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("permit ledger parent must be private and non-symlinked")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("permit ledger database must be private and non-symlinked")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	for _, statement := range []string{
		"PRAGMA journal_mode = WAL", "PRAGMA busy_timeout = 5000",
		`CREATE TABLE IF NOT EXISTS issued_permits (serial BLOB PRIMARY KEY, permit BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS redeemed_operations (
			permit_serial BLOB NOT NULL, operation_id BLOB NOT NULL, operation BLOB NOT NULL,
			path_commitment BLOB NOT NULL, target_commitment BLOB NOT NULL, body_commitment BLOB NOT NULL,
			idempotency_key BLOB NOT NULL, result BLOB NOT NULL,
			PRIMARY KEY(permit_serial, operation_id)
		)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize permit ledger: %w", err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLitePermitLedger{db: db}, nil
}

// Close closes the permit ledger.
func (s *SQLitePermitLedger) Close() error { return s.db.Close() }

// Issue verifies and persists a permit serial exactly once.
func (s *SQLitePermitLedger) Issue(permit Permit, issuers PermitIssuerResolver, now time.Time) error {
	if s == nil {
		return errors.New("nil permit ledger")
	}
	if err := VerifyPermit(permit, issuers, now); err != nil {
		return err
	}
	raw, err := EncodePermit(permit)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(context.Background(), "INSERT INTO issued_permits(serial, permit) VALUES (?, ?)", permit.Serial[:], raw); err != nil {
		return errors.New("permit serial already issued")
	}
	return nil
}

// Redeem verifies an exact signed operation, applies its state mutation in the
// same SQLite transaction, and returns a durable result on identical retry.
func (s *SQLitePermitLedger) Redeem(ctx context.Context, permit Permit, operation OperationRecord, issuers PermitIssuerResolver, holders OperationHolderResolver, now time.Time, mutation PermitMutation) ([]byte, bool, error) {
	if s == nil || mutation == nil {
		return nil, false, errors.New("invalid permit redemption")
	}
	if err := VerifyPermit(permit, issuers, now); err != nil {
		return nil, false, err
	}
	if err := VerifyOperation(operation, permit, holders, now); err != nil {
		return nil, false, err
	}
	rawPermit, err := EncodePermit(permit)
	if err != nil {
		return nil, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var storedPermit []byte
	if err := tx.QueryRowContext(ctx, "SELECT permit FROM issued_permits WHERE serial = ?", permit.Serial[:]).Scan(&storedPermit); err != nil || !bytes.Equal(storedPermit, rawPermit) {
		return nil, false, errors.New("unknown or mismatched issued permit")
	}
	var existingOperation, path, target, body, idempotency, result []byte
	err = tx.QueryRowContext(ctx, "SELECT operation, path_commitment, target_commitment, body_commitment, idempotency_key, result FROM redeemed_operations WHERE permit_serial = ? AND operation_id = ?", permit.Serial[:], operation.OperationID[:]).Scan(&existingOperation, &path, &target, &body, &idempotency, &result)
	if err == nil {
		if len(existingOperation) != 8 || uint64FromBytes(existingOperation) != operation.Operation || !bytes.Equal(path, operation.PathCommitment[:]) || !bytes.Equal(target, operation.TargetCommitment[:]) || !bytes.Equal(body, operation.BodyCommitment[:]) || !bytes.Equal(idempotency, operation.IdempotencyKey[:]) {
			return nil, false, errors.New("changed operation replay")
		}
		return append([]byte(nil), result...), true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	var used uint64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM redeemed_operations WHERE permit_serial = ?", permit.Serial[:]).Scan(&used); err != nil || used >= permit.MaxOperations {
		return nil, false, errors.New("permit operation quota exhausted")
	}
	result, err = mutation(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	if len(result) > maxOperationResultBytes {
		return nil, false, errors.New("operation result exceeds bound")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO redeemed_operations(permit_serial, operation_id, operation, path_commitment, target_commitment, body_commitment, idempotency_key, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", permit.Serial[:], operation.OperationID[:], uint64Bytes(operation.Operation), operation.PathCommitment[:], operation.TargetCommitment[:], operation.BodyCommitment[:], operation.IdempotencyKey[:], result); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return append([]byte(nil), result...), false, nil
}
