// Package v3 implements the private pre-offer source staging primitive for
// Attachment v3. It is not an HTTP runtime and cannot expose attachments.
package v3

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zeebo/blake3"
	_ "modernc.org/sqlite"
)

const (
	maxCiphertextFrame        = 256<<10 + 16
	defaultTombstoneRetention = 24 * time.Hour
)

type quotaLimit struct {
	CiphertextBytes    uint64
	Chunks             uint64
	Transfers          uint64
	DurableSources     uint64
	CryptoReservations uint64
}

type sourceLimits struct {
	Sender, Recipient, Conversation, Relay quotaLimit
	TombstoneRetention                     time.Duration
}

func (l sourceLimits) valid() bool {
	for _, limit := range []quotaLimit{l.Sender, l.Recipient, l.Conversation, l.Relay} {
		if limit.CiphertextBytes == 0 || limit.CiphertextBytes > 1<<40 || limit.Chunks == 0 || limit.Chunks > 1<<20 || limit.Transfers == 0 || limit.Transfers > 1<<20 || limit.DurableSources == 0 || limit.DurableSources > 1<<30 || limit.CryptoReservations == 0 || limit.CryptoReservations > 1<<32 {
			return false
		}
	}
	return l.TombstoneRetention > 0 && l.TombstoneRetention <= 30*24*time.Hour
}

func defaultSourceLimits() sourceLimits {
	// 65 MiB accommodates the 64 MiB plaintext ceiling plus one 16-byte AEAD
	// tag per permitted chunk, while leaving a small implementation margin.
	limit := quotaLimit{CiphertextBytes: 65 << 20, Chunks: 4096, Transfers: 64, DurableSources: 1 << 20, CryptoReservations: 1 << 20}
	return sourceLimits{Sender: limit, Recipient: limit, Conversation: limit, Relay: limit, TombstoneRetention: defaultTombstoneRetention}
}

type sourceSpec struct {
	TransferID         [16]byte
	ManifestCommitment [32]byte
	Manifest           []byte
	ChunkSize          uint64
	ChunkCount         uint64
	PlaintextSize      uint64
	ExpiresAt          int64
}

type sourceScope uint8

const (
	sourceScopeSender sourceScope = iota + 1
	sourceScopeRecipient
	sourceScopeConversation
	sourceScopeRelay
)

type quotaKey struct {
	scope sourceScope
	id    [32]byte
}

// sourceStore is an internal v3 staging primitive. It is deliberately not an
// HTTP authorization API: a future v3 handler owns permit/operation admission.
type sourceStore struct {
	db     *sql.DB
	limits sourceLimits
}

func openSourceStore(path string, limits sourceLimits) (*sourceStore, error) {
	if !limits.valid() {
		return nil, errors.New("invalid source limits")
	}
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("source store path is required")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("source store parent must be private and non-symlinked")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("source store database must be private and non-symlinked")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Lstat(sidecar); err == nil {
			return nil, errors.New("unexpected SQLite sidecar")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	// A rollback journal is evidence of an interrupted transaction. SQLite is
	// responsible for recovering it, but never follow a link or accept a
	// non-private file before letting SQLite open the database.
	if info, err := os.Lstat(path + "-journal"); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("unsafe SQLite rollback journal")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA journal_mode = DELETE", "PRAGMA busy_timeout = 5000", "PRAGMA foreign_keys = ON",
		`CREATE TABLE IF NOT EXISTS v3_source_specs (
			transfer_id BLOB PRIMARY KEY, manifest_commitment BLOB NOT NULL UNIQUE, manifest BLOB NOT NULL,
			chunk_size INTEGER NOT NULL, chunk_count INTEGER NOT NULL,
			plaintext_size INTEGER NOT NULL, expires_at INTEGER NOT NULL,
			ready INTEGER NOT NULL CHECK(ready IN (0,1))
		)`,
		`CREATE TABLE IF NOT EXISTS v3_transfers (
			transfer_id BLOB PRIMARY KEY, manifest_commitment BLOB NOT NULL UNIQUE,
			status INTEGER NOT NULL, attempt_generation INTEGER NOT NULL, expires_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS v3_source_chunks (
			transfer_id BLOB NOT NULL, chunk_index INTEGER NOT NULL,
			ciphertext BLOB NOT NULL, ciphertext_commitment BLOB NOT NULL,
			PRIMARY KEY(transfer_id, chunk_index),
			FOREIGN KEY(transfer_id) REFERENCES v3_source_specs(transfer_id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS v3_source_quota (
			scope INTEGER NOT NULL, scope_id BLOB NOT NULL,
			ciphertext_bytes INTEGER NOT NULL, chunks INTEGER NOT NULL, transfers INTEGER NOT NULL,
			PRIMARY KEY(scope, scope_id)
		)`,
		`CREATE TABLE IF NOT EXISTS v3_source_tombstones (
			transfer_id BLOB PRIMARY KEY, manifest_commitment BLOB NOT NULL UNIQUE, retain_until INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS v3_source_uniqueness (
			transfer_id BLOB PRIMARY KEY, manifest_commitment BLOB NOT NULL UNIQUE
		)`,
		`CREATE TABLE IF NOT EXISTS v3_source_admission (
			scope INTEGER NOT NULL, scope_id BLOB NOT NULL, durable_sources INTEGER NOT NULL,
			PRIMARY KEY(scope, scope_id)
		)`,
		`CREATE TABLE IF NOT EXISTS v3_source_file_keys (commitment BLOB PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS v3_source_content_salts (commitment BLOB PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS v3_source_nonce_tuples (
			transfer_id BLOB NOT NULL, manifest_commitment BLOB NOT NULL, chunk_index INTEGER NOT NULL,
			PRIMARY KEY(transfer_id, manifest_commitment, chunk_index)
		)`,
		`CREATE TABLE IF NOT EXISTS v3_source_crypto_admission (
			scope INTEGER NOT NULL, scope_id BLOB NOT NULL, reservations INTEGER NOT NULL,
			PRIMARY KEY(scope, scope_id)
		)`,
		`CREATE TABLE IF NOT EXISTS v3_issued_permits (
			serial BLOB PRIMARY KEY, permit BLOB NOT NULL UNIQUE, transfer_id BLOB NOT NULL,
			manifest_commitment BLOB NOT NULL, expires_at INTEGER NOT NULL, retain_until INTEGER NOT NULL
		)`,
		// Permit issuance is deliberately journaled beside source admission. That
		// makes a holder's retry stable across daemon restarts without allowing a
		// second database to mint an unregistered source-init capability.
		`CREATE TABLE IF NOT EXISTS v3_permit_requests (
			request_id BLOB PRIMARY KEY, request BLOB NOT NULL, permit BLOB NOT NULL,
			permit_serial BLOB NOT NULL UNIQUE, holder_device_id BLOB NOT NULL,
			expires_at INTEGER NOT NULL, retain_until INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS v3_permit_requests_retain_until ON v3_permit_requests(retain_until)`,
		`CREATE TABLE IF NOT EXISTS v3_redeemed_operations (
			permit_serial BLOB NOT NULL, operation_id BLOB NOT NULL, operation INTEGER NOT NULL,
			method INTEGER NOT NULL, path_commitment BLOB NOT NULL, target_commitment BLOB NOT NULL,
			body_commitment BLOB NOT NULL, idempotency_key BLOB NOT NULL,
			ciphertext_bytes INTEGER NOT NULL, ciphertext_chunks INTEGER NOT NULL, result BLOB NOT NULL,
			PRIMARY KEY(permit_serial, operation_id), UNIQUE(permit_serial, idempotency_key)
		)`,
		`CREATE TABLE IF NOT EXISTS v3_ledger_admission (
			transfer_id BLOB PRIMARY KEY, manifest_commitment BLOB NOT NULL,
			operations INTEGER NOT NULL, result_bytes INTEGER NOT NULL, retain_until INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS v3_offers (
			transfer_id BLOB PRIMARY KEY, manifest BLOB NOT NULL, envelope BLOB NOT NULL,
			acceptance_nonce BLOB NOT NULL, acceptance_consumed INTEGER NOT NULL CHECK(acceptance_consumed IN (0,1))
		)`,
		`CREATE TABLE IF NOT EXISTS v3_receipt_chunks (
			transfer_id BLOB NOT NULL, attempt_generation INTEGER NOT NULL, chunk_index INTEGER NOT NULL,
			ciphertext_commitment BLOB NOT NULL, PRIMARY KEY(transfer_id, attempt_generation, chunk_index)
		)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize source store: %w", err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := verifySourceStoreSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := verifyTrackedSources(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := reconcileLedgerAdmission(db, limits); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &sourceStore{db: db, limits: limits}, nil
}

// reconcileLedgerAdmission fails closed when a database created before the
// aggregate ledger budget contains durable operation results. It can only
// backfill rows whose active source still supplies a trustworthy chunk bound.
func reconcileLedgerAdmission(db *sql.DB, limits sourceLimits) error {
	rows, err := db.QueryContext(context.Background(), `SELECT i.transfer_id, i.manifest_commitment, COUNT(o.operation_id), MAX(i.retain_until) FROM v3_issued_permits i JOIN v3_redeemed_operations o ON o.permit_serial = i.serial GROUP BY i.transfer_id, i.manifest_commitment`)
	if err != nil {
		return err
	}
	type row struct {
		transferRaw, commitmentRaw []byte
		operations                 uint64
		retainUntil                int64
	}
	var recovered []row
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.transferRaw, &item.commitmentRaw, &item.operations, &item.retainUntil); err != nil || len(item.transferRaw) != 16 || len(item.commitmentRaw) != 32 {
			_ = rows.Close()
			return errors.New("unreconcilable v3 ledger state")
		}
		item.transferRaw, item.commitmentRaw = append([]byte(nil), item.transferRaw...), append([]byte(nil), item.commitmentRaw...)
		recovered = append(recovered, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var existingCount uint64
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM v3_ledger_admission`).Scan(&existingCount); err != nil {
		return err
	}
	if existingCount != 0 {
		if existingCount != uint64(len(recovered)) {
			return errors.New("incomplete v3 ledger admission state")
		}
		for _, item := range recovered {
			var commitmentRaw []byte
			var operations, resultBytes uint64
			var retainUntil int64
			if err := db.QueryRowContext(context.Background(), `SELECT manifest_commitment, operations, result_bytes, retain_until FROM v3_ledger_admission WHERE transfer_id = ?`, item.transferRaw).Scan(&commitmentRaw, &operations, &resultBytes, &retainUntil); err != nil || !bytes.Equal(commitmentRaw, item.commitmentRaw) || operations != item.operations || resultBytes != item.operations*uint64(maxOperationResultBytes) || retainUntil < item.retainUntil {
				return errors.New("incomplete v3 ledger admission state")
			}
			var chunks uint64
			err := db.QueryRowContext(context.Background(), `SELECT chunk_count FROM v3_source_specs WHERE transfer_id = ? AND manifest_commitment = ?`, item.transferRaw, item.commitmentRaw).Scan(&chunks)
			if err == nil && (chunks > 4096 || operations > chunks+16) {
				return errors.New("invalid v3 ledger admission state")
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		return nil
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, item := range recovered {
		transferRaw, commitmentRaw, operations, retainUntil := item.transferRaw, item.commitmentRaw, item.operations, item.retainUntil
		var id [16]byte
		var commitment [32]byte
		copy(id[:], transferRaw)
		copy(commitment[:], commitmentRaw)
		spec, found, err := loadSpecTx(context.Background(), tx, id)
		if err != nil || !found || spec.ManifestCommitment != commitment || operations > spec.ChunkCount+16 {
			return errors.New("unreconcilable v3 ledger state")
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO v3_ledger_admission(transfer_id, manifest_commitment, operations, result_bytes, retain_until) VALUES (?, ?, ?, ?, ?)`, id[:], commitment[:], operations, operations*uint64(maxOperationResultBytes), retainUntil); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *sourceStore) close() error { return s.db.Close() }

// Initialize records a source only after DecodeAndVerifySourceInit has derived
// its immutable values from a canonical, signed v3 manifest.
func (s *sourceStore) initialize(ctx context.Context, source VerifiedSource, now time.Time) error {
	if s == nil || s.db == nil {
		return errors.New("invalid source specification")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := s.initializeTx(ctx, tx, source, now); err != nil {
		return err
	}
	return tx.Commit()
}

// initializeTx is shared by ordinary pre-authorized staging and the atomic
// source-init redemption path. Callers own commit/rollback.
func (s *sourceStore) initializeTx(ctx context.Context, tx *sql.Tx, source VerifiedSource, now time.Time) (bool, error) {
	if s == nil || tx == nil || !source.valid(now) {
		return false, errors.New("invalid source specification")
	}
	spec, err := source.sourceSpec()
	if err != nil {
		return false, err
	}
	current, found, err := loadSpecTx(ctx, tx, spec.TransferID)
	if found && err == nil {
		if !sameSpec(current, spec) {
			return false, errors.New("source specification replacement is forbidden")
		}
		if err := verifyTrackedSourceTx(ctx, tx, current); err != nil {
			return false, err
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := s.reserveSourceTx(ctx, tx, spec); err != nil {
		return false, err
	}
	if err := s.admitDurableSourceTx(ctx, tx, spec); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_source_uniqueness(transfer_id, manifest_commitment) VALUES (?, ?)`, spec.TransferID[:], spec.ManifestCommitment[:]); err != nil {
		return false, errors.New("source transfer identity is not reusable")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v3_source_specs(transfer_id, manifest_commitment, manifest, chunk_size, chunk_count, plaintext_size, expires_at, ready) VALUES (?, ?, ?, ?, ?, ?, ?, 0)`, spec.TransferID[:], spec.ManifestCommitment[:], spec.Manifest, spec.ChunkSize, spec.ChunkCount, spec.PlaintextSize, spec.ExpiresAt)
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_transfers(transfer_id, manifest_commitment, status, attempt_generation, expires_at) VALUES (?, ?, ?, 0, ?)`, spec.TransferID[:], spec.ManifestCommitment[:], transferSourceUploading, spec.ExpiresAt); err != nil {
		return false, err
	}
	return true, nil
}

// Cancel is deliberately internal staging cleanup only. An HTTP route must
// redeem a sender-only cancel operation before invoking it.
func (s *sourceStore) cancel(ctx context.Context, transferID [16]byte, now time.Time) error {
	if s == nil || s.db == nil || transferID == [16]byte{} || now.UTC().Unix() < 0 {
		return errors.New("invalid source cancellation")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	spec, found, err := loadSpecTx(ctx, tx, transferID)
	if err != nil {
		return err
	}
	if !found {
		var retained int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM v3_source_tombstones WHERE transfer_id = ?`, transferID[:]).Scan(&retained)
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("unknown staged source")
		}
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := s.terminalizeSourceTx(ctx, tx, spec, now); err != nil {
		return err
	}
	return tx.Commit()
}

// ReapExpired bounds one recovery pass and releases capacity only while
// preserving the uniqueness reservation for every terminal source.
func (s *sourceStore) reapExpired(ctx context.Context, now time.Time, limit uint64) (uint64, error) {
	if s == nil || s.db == nil || now.UTC().Unix() < 0 || limit == 0 || limit > 1024 {
		return 0, errors.New("invalid source reaper request")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT transfer_id FROM v3_source_specs WHERE expires_at <= ? ORDER BY expires_at, transfer_id LIMIT ?`, now.UTC().Unix(), limit)
	if err != nil {
		return 0, err
	}
	var ids [][16]byte
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil || len(raw) != 16 {
			_ = rows.Close()
			return 0, errors.New("invalid stored source transfer")
		}
		var id [16]byte
		copy(id[:], raw)
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		spec, found, err := loadSpecTx(ctx, tx, id)
		if err != nil {
			return 0, err
		}
		if found {
			if err := s.terminalizeSourceTx(ctx, tx, spec, now); err != nil {
				return 0, err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_source_tombstones WHERE retain_until <= ?`, now.UTC().Unix()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_redeemed_operations WHERE permit_serial IN (SELECT serial FROM v3_issued_permits WHERE retain_until <= ?)`, now.UTC().Unix()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_issued_permits WHERE retain_until <= ?`, now.UTC().Unix()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_ledger_admission WHERE retain_until <= ?`, now.UTC().Unix()); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_permit_requests WHERE retain_until <= ?`, now.UTC().Unix()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return uint64(len(ids)), nil
}

func (s *sourceStore) upload(ctx context.Context, transferID [16]byte, index uint64, ciphertext []byte, now time.Time) error {
	if s == nil || s.db == nil || transferID == [16]byte{} || len(ciphertext) == 0 || len(ciphertext) > maxCiphertextFrame {
		return errors.New("invalid staged chunk")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.uploadTx(ctx, tx, transferID, index, ciphertext, now); err != nil {
		return err
	}
	return tx.Commit()
}

// uploadTx is the one transactional source-chunk mutation. Permit redemption
// calls it directly so a chunk, source-ready transition, operation result, and
// quota charge cannot cross a crash boundary.
func (s *sourceStore) uploadTx(ctx context.Context, tx *sql.Tx, transferID [16]byte, index uint64, ciphertext []byte, now time.Time) error {
	if s == nil || tx == nil || transferID == [16]byte{} || len(ciphertext) == 0 || len(ciphertext) > maxCiphertextFrame {
		return errors.New("invalid staged chunk")
	}
	spec, found, err := loadSpecTx(ctx, tx, transferID)
	if err != nil || !found {
		return errors.New("unknown staged source")
	}
	if now.UTC().Unix() >= spec.ExpiresAt || index >= spec.ChunkCount || uint64(len(ciphertext)) != expectedCiphertextLength(spec, index) {
		return errors.New("invalid staged chunk")
	}
	commitment := ciphertextCommitment(ciphertext)
	var existing, existingCommitment []byte
	err = tx.QueryRowContext(ctx, `SELECT ciphertext, ciphertext_commitment FROM v3_source_chunks WHERE transfer_id = ? AND chunk_index = ?`, transferID[:], index).Scan(&existing, &existingCommitment)
	switch {
	case err == nil:
		if !bytes.Equal(existing, ciphertext) || !bytes.Equal(existingCommitment, commitment[:]) {
			return errors.New("staged chunk replacement is forbidden")
		}
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_source_chunks(transfer_id, chunk_index, ciphertext, ciphertext_commitment) VALUES (?, ?, ?, ?)`, transferID[:], index, ciphertext, commitment[:]); err != nil {
			return err
		}
	default:
		return err
	}
	var stored uint64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM v3_source_chunks WHERE transfer_id = ?`, transferID[:]).Scan(&stored); err != nil {
		return err
	}
	if stored == spec.ChunkCount {
		result, err := tx.ExecContext(ctx, `UPDATE v3_source_specs SET ready = 1 WHERE transfer_id = ? AND ready = 0`, transferID[:])
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed > 1 {
			return errors.New("source-ready fencing failed")
		}
		if changed == 1 {
			transition, err := tx.ExecContext(ctx, `UPDATE v3_transfers SET status = ? WHERE transfer_id = ? AND manifest_commitment = ? AND status = ? AND attempt_generation = 0 AND expires_at = ?`, transferSourceReady, transferID[:], spec.ManifestCommitment[:], transferSourceUploading, spec.ExpiresAt)
			if err != nil {
				return err
			}
			if changed, err := transition.RowsAffected(); err != nil || changed != 1 {
				return errors.New("source-ready lifecycle transition failed")
			}
		} else if err := verifyTrackedSourceTx(ctx, tx, spec); err != nil {
			return err
		} else {
			var status transferStatus
			if err := tx.QueryRowContext(ctx, `SELECT status FROM v3_transfers WHERE transfer_id = ?`, transferID[:]).Scan(&status); err != nil || status != transferSourceReady {
				return errors.New("invalid ready source lifecycle state")
			}
		}
	}
	return nil
}

func (s *sourceStore) readyAt(transferID [16]byte, now time.Time) (bool, error) {
	if s == nil || s.db == nil || transferID == [16]byte{} {
		return false, errors.New("invalid source lookup")
	}
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	spec, found, err := loadSpecTx(context.Background(), tx, transferID)
	if err != nil || !found {
		return false, err
	}
	if err := verifyTrackedSourceTx(context.Background(), tx, spec); err != nil {
		return false, err
	}
	if now.UTC().Unix() >= spec.ExpiresAt {
		return false, nil
	}
	var ready int
	err = tx.QueryRowContext(context.Background(), `SELECT ready FROM v3_source_specs WHERE transfer_id = ?`, transferID[:]).Scan(&ready)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil || (ready != 0 && ready != 1) {
		return false, errors.New("invalid source state")
	}
	if ready == 0 {
		return false, nil
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT chunk_index, ciphertext, ciphertext_commitment FROM v3_source_chunks WHERE transfer_id = ? ORDER BY chunk_index`, transferID[:])
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	index := uint64(0)
	for rows.Next() {
		var storedIndex int64
		var ciphertext, commitment []byte
		if err := rows.Scan(&storedIndex, &ciphertext, &commitment); err != nil || storedIndex < 0 || uint64(storedIndex) != index || len(commitment) != 32 || uint64(len(ciphertext)) != expectedCiphertextLength(spec, index) {
			return false, errors.New("invalid stored staged chunk")
		}
		expected := ciphertextCommitment(ciphertext)
		if !bytes.Equal(commitment, expected[:]) {
			return false, errors.New("invalid stored staged chunk")
		}
		index++
	}
	if err := rows.Err(); err != nil || index != spec.ChunkCount {
		return false, errors.New("incomplete staged source")
	}
	return true, tx.Commit()
}

func (v VerifiedSource) sourceSpec() (sourceSpec, error) {
	expiresAt, err := unixSeconds(v.manifest.ExpiresAt)
	if err != nil {
		return sourceSpec{}, err
	}
	return sourceSpec{TransferID: v.manifest.TransferID, ManifestCommitment: v.commitment,
		Manifest: append([]byte(nil), v.raw...), ChunkSize: v.manifest.ChunkSize,
		ChunkCount: v.manifest.ChunkCount, PlaintextSize: v.manifest.PlaintextSize,
		ExpiresAt: expiresAt}, nil
}

func expectedCiphertextLength(spec sourceSpec, index uint64) uint64 {
	plain := spec.ChunkSize
	if index == spec.ChunkCount-1 {
		plain = spec.PlaintextSize - spec.ChunkSize*(spec.ChunkCount-1)
	}
	return plain + 16
}

func ciphertextCommitment(ciphertext []byte) [32]byte {
	return blake3.Sum256(append([]byte("punaro/attachment/ciphertext/v3\x00"), ciphertext...))
}

func sameSpec(left, right sourceSpec) bool {
	return left.TransferID == right.TransferID && left.ManifestCommitment == right.ManifestCommitment && bytes.Equal(left.Manifest, right.Manifest) && left.ChunkSize == right.ChunkSize && left.ChunkCount == right.ChunkCount && left.PlaintextSize == right.PlaintextSize && left.ExpiresAt == right.ExpiresAt
}

func loadSpecTx(ctx context.Context, tx *sql.Tx, transferID [16]byte) (sourceSpec, bool, error) {
	var transferRaw, commitmentRaw []byte
	var spec sourceSpec
	err := tx.QueryRowContext(ctx, `SELECT transfer_id, manifest_commitment, manifest, chunk_size, chunk_count, plaintext_size, expires_at FROM v3_source_specs WHERE transfer_id = ?`, transferID[:]).Scan(&transferRaw, &commitmentRaw, &spec.Manifest, &spec.ChunkSize, &spec.ChunkCount, &spec.PlaintextSize, &spec.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return sourceSpec{}, false, nil
	}
	if err != nil || len(transferRaw) != len(spec.TransferID) || len(commitmentRaw) != len(spec.ManifestCommitment) {
		return sourceSpec{}, false, errors.New("invalid stored source specification")
	}
	copy(spec.TransferID[:], transferRaw)
	copy(spec.ManifestCommitment[:], commitmentRaw)
	spec.Manifest = append([]byte(nil), spec.Manifest...)
	if !consistentStoredSpec(spec) {
		return sourceSpec{}, false, errors.New("invalid stored source specification")
	}
	return spec, true, nil
}

func consistentStoredSpec(spec sourceSpec) bool {
	manifest, err := DecodeManifest(spec.Manifest)
	if err != nil || spec.ManifestCommitment != blake3.Sum256(spec.Manifest) || manifest.ExpiresAt > math.MaxInt64 {
		return false
	}
	return manifest.TransferID == spec.TransferID && manifest.ChunkSize == spec.ChunkSize &&
		manifest.ChunkCount == spec.ChunkCount && manifest.PlaintextSize == spec.PlaintextSize &&
		int64(manifest.ExpiresAt) == spec.ExpiresAt
}

func verifySourceStoreSchema(db *sql.DB) error {
	expected := map[string][]string{
		"v3_source_specs":            {"transfer_id", "manifest_commitment", "manifest", "chunk_size", "chunk_count", "plaintext_size", "expires_at", "ready"},
		"v3_transfers":               {"transfer_id", "manifest_commitment", "status", "attempt_generation", "expires_at"},
		"v3_source_chunks":           {"transfer_id", "chunk_index", "ciphertext", "ciphertext_commitment"},
		"v3_source_quota":            {"scope", "scope_id", "ciphertext_bytes", "chunks", "transfers"},
		"v3_source_tombstones":       {"transfer_id", "manifest_commitment", "retain_until"},
		"v3_source_uniqueness":       {"transfer_id", "manifest_commitment"},
		"v3_source_admission":        {"scope", "scope_id", "durable_sources"},
		"v3_source_file_keys":        {"commitment"},
		"v3_source_content_salts":    {"commitment"},
		"v3_source_nonce_tuples":     {"transfer_id", "manifest_commitment", "chunk_index"},
		"v3_source_crypto_admission": {"scope", "scope_id", "reservations"},
		"v3_issued_permits":          {"serial", "permit", "transfer_id", "manifest_commitment", "expires_at", "retain_until"},
		"v3_permit_requests":         {"request_id", "request", "permit", "permit_serial", "holder_device_id", "expires_at", "retain_until"},
		"v3_redeemed_operations":     {"permit_serial", "operation_id", "operation", "method", "path_commitment", "target_commitment", "body_commitment", "idempotency_key", "ciphertext_bytes", "ciphertext_chunks", "result"},
		"v3_ledger_admission":        {"transfer_id", "manifest_commitment", "operations", "result_bytes", "retain_until"},
		"v3_offers":                  {"transfer_id", "manifest", "envelope", "acceptance_nonce", "acceptance_consumed"},
		"v3_receipt_chunks":          {"transfer_id", "attempt_generation", "chunk_index", "ciphertext_commitment"},
	}
	for table, columns := range expected {
		rows, err := db.QueryContext(context.Background(), "PRAGMA table_info("+table+")") // #nosec G202 -- table names are fixed constants.
		if err != nil {
			return err
		}
		seen := make(map[string]bool, len(columns))
		for rows.Next() {
			var cid int
			var name, kind string
			var notNull, primaryKey int
			var defaultValue any
			if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
				_ = rows.Close()
				return err
			}
			seen[name] = true
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, column := range columns {
			if !seen[column] {
				return errors.New("obsolete source store schema")
			}
		}
	}
	requiredDefinitions := map[string][]string{
		"v3_source_specs":            {"transfer_idblobprimarykey", "manifest_commitmentblobnotnullunique", "readyintegernotnullcheck(readyin(0,1))"},
		"v3_transfers":               {"transfer_idblobprimarykey", "manifest_commitmentblobnotnullunique"},
		"v3_source_chunks":           {"primarykey(transfer_id,chunk_index)", "foreignkey(transfer_id)referencesv3_source_specs(transfer_id)ondeletecascade"},
		"v3_source_quota":            {"primarykey(scope,scope_id)"},
		"v3_source_tombstones":       {"transfer_idblobprimarykey", "manifest_commitmentblobnotnullunique"},
		"v3_source_uniqueness":       {"transfer_idblobprimarykey", "manifest_commitmentblobnotnullunique"},
		"v3_source_admission":        {"primarykey(scope,scope_id)"},
		"v3_source_file_keys":        {"commitmentblobprimarykey"},
		"v3_source_content_salts":    {"commitmentblobprimarykey"},
		"v3_source_nonce_tuples":     {"primarykey(transfer_id,manifest_commitment,chunk_index)"},
		"v3_source_crypto_admission": {"primarykey(scope,scope_id)"},
		"v3_issued_permits":          {"serialblobprimarykey", "permitblobnotnullunique", "retain_untilintegernotnull"},
		"v3_permit_requests":         {"request_idblobprimarykey", "permitblobnotnull", "permit_serialblobnotnullunique", "holder_device_idblobnotnull", "expires_atintegernotnull", "retain_untilintegernotnull"},
		"v3_redeemed_operations":     {"primarykey(permit_serial,operation_id)", "unique(permit_serial,idempotency_key)"},
		"v3_ledger_admission":        {"transfer_idblobprimarykey", "manifest_commitmentblobnotnull", "retain_untilintegernotnull"},
		"v3_offers":                  {"transfer_idblobprimarykey", "acceptance_consumedintegernotnullcheck(acceptance_consumedin(0,1))"},
		"v3_receipt_chunks":          {"primarykey(transfer_id,attempt_generation,chunk_index)"},
	}
	for table, required := range requiredDefinitions {
		var definition string
		if err := db.QueryRowContext(context.Background(), `SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?`, table).Scan(&definition); err != nil {
			return errors.New("obsolete source store schema")
		}
		normalized := strings.ToLower(strings.Join(strings.Fields(definition), ""))
		for _, fragment := range required {
			if !strings.Contains(normalized, fragment) {
				return errors.New("obsolete source store schema")
			}
		}
	}
	return nil
}

func verifyTrackedSources(db *sql.DB) error {
	var missing int
	err := db.QueryRowContext(context.Background(), `SELECT 1 FROM v3_source_specs s LEFT JOIN v3_transfers t ON s.transfer_id = t.transfer_id AND s.manifest_commitment = t.manifest_commitment WHERE t.transfer_id IS NULL OR t.expires_at != s.expires_at OR (s.ready = 0 AND (t.status != ? OR t.attempt_generation != 0)) OR (s.ready = 1 AND NOT ((t.status IN (?, ?, ?) AND t.attempt_generation = 0) OR (t.status IN (?, ?) AND t.attempt_generation = 1))) LIMIT 1`, transferSourceUploading, transferSourceReady, transferOffered, transferAccepted, transferTransferring, transferCompleted).Scan(&missing)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("untracked source staging state requires operator recovery")
}

func verifyTrackedSourceTx(ctx context.Context, tx *sql.Tx, spec sourceSpec) error {
	var status transferStatus
	var attempts uint64
	var expires int64
	var ready int
	err := tx.QueryRowContext(ctx, `SELECT s.ready, t.status, t.attempt_generation, t.expires_at FROM v3_source_specs s JOIN v3_transfers t ON s.transfer_id = t.transfer_id AND s.manifest_commitment = t.manifest_commitment WHERE s.transfer_id = ? AND s.manifest_commitment = ?`, spec.TransferID[:], spec.ManifestCommitment[:]).Scan(&ready, &status, &attempts, &expires)
	valid := (ready == 0 && status == transferSourceUploading && attempts == 0) || (ready == 1 && (((status == transferSourceReady || status == transferOffered || status == transferAccepted) && attempts == 0) || ((status == transferTransferring || status == transferCompleted) && attempts == 1)))
	if err != nil || expires != spec.ExpiresAt || !valid || (ready != 0 && ready != 1) {
		return errors.New("invalid tracked source lifecycle state")
	}
	return nil
}

func sourceQuotaKeys(spec sourceSpec) ([]quotaKey, error) {
	manifest, err := DecodeManifest(spec.Manifest)
	if err != nil {
		return nil, err
	}
	key := func(scope sourceScope, values ...[]byte) quotaKey {
		hasher := blake3.New()
		_, _ = hasher.Write([]byte("punaro/attachment/source-quota/v3\x00"))
		_, _ = hasher.Write([]byte{byte(scope)})
		for _, value := range values {
			_, _ = hasher.Write(value)
		}
		var id [32]byte
		copy(id[:], hasher.Sum(nil))
		return quotaKey{scope: scope, id: id}
	}
	var senderGeneration, recipientGeneration [8]byte
	binary.BigEndian.PutUint64(senderGeneration[:], manifest.SenderGeneration)
	binary.BigEndian.PutUint64(recipientGeneration[:], manifest.RecipientGeneration)
	return []quotaKey{
		key(sourceScopeSender, manifest.Audience[:], manifest.SenderDeviceID[:], senderGeneration[:]),
		key(sourceScopeRecipient, manifest.Audience[:], manifest.RecipientDeviceID[:], recipientGeneration[:]),
		key(sourceScopeConversation, manifest.Audience[:], manifest.ConversationID[:]),
		key(sourceScopeRelay, []byte("all")),
	}, nil
}

func (s *sourceStore) scopeLimit(scope sourceScope) quotaLimit {
	switch scope {
	case sourceScopeSender:
		return s.limits.Sender
	case sourceScopeRecipient:
		return s.limits.Recipient
	case sourceScopeConversation:
		return s.limits.Conversation
	default:
		return s.limits.Relay
	}
}

func sourceUsage(spec sourceSpec) (uint64, uint64, error) {
	if spec.ChunkCount > (math.MaxUint64-spec.PlaintextSize)/16 {
		return 0, 0, errors.New("source ciphertext arithmetic overflow")
	}
	bytes := spec.PlaintextSize + 16*spec.ChunkCount
	if bytes > math.MaxInt64 {
		return 0, 0, errors.New("source ciphertext exceeds SQLite range")
	}
	return bytes, spec.ChunkCount, nil
}

func (s *sourceStore) reserveSourceTx(ctx context.Context, tx *sql.Tx, spec sourceSpec) error {
	bytes, chunks, err := sourceUsage(spec)
	if err != nil {
		return err
	}
	keys, err := sourceQuotaKeys(spec)
	if err != nil {
		return err
	}
	for _, key := range keys {
		var currentBytes, currentChunks, currentTransfers uint64
		err := tx.QueryRowContext(ctx, `SELECT ciphertext_bytes, chunks, transfers FROM v3_source_quota WHERE scope = ? AND scope_id = ?`, key.scope, key.id[:]).Scan(&currentBytes, &currentChunks, &currentTransfers)
		if errors.Is(err, sql.ErrNoRows) {
			currentBytes, currentChunks, currentTransfers = 0, 0, 0
		} else if err != nil {
			return err
		}
		limit := s.scopeLimit(key.scope)
		if bytes > limit.CiphertextBytes || chunks > limit.Chunks || currentBytes > limit.CiphertextBytes-bytes || currentChunks > limit.Chunks-chunks || currentTransfers >= limit.Transfers {
			return errors.New("source quota exceeded")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_source_quota(scope, scope_id, ciphertext_bytes, chunks, transfers) VALUES (?, ?, ?, ?, 1) ON CONFLICT(scope, scope_id) DO UPDATE SET ciphertext_bytes = excluded.ciphertext_bytes, chunks = excluded.chunks, transfers = v3_source_quota.transfers + 1`, key.scope, key.id[:], currentBytes+bytes, currentChunks+chunks); err != nil {
			return err
		}
	}
	return nil
}

func (s *sourceStore) admitDurableSourceTx(ctx context.Context, tx *sql.Tx, spec sourceSpec) error {
	keys, err := sourceQuotaKeys(spec)
	if err != nil {
		return err
	}
	for _, key := range keys {
		var current uint64
		err := tx.QueryRowContext(ctx, `SELECT durable_sources FROM v3_source_admission WHERE scope = ? AND scope_id = ?`, key.scope, key.id[:]).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			current = 0
		} else if err != nil {
			return err
		}
		if current >= s.scopeLimit(key.scope).DurableSources {
			return errors.New("source durable admission budget exhausted")
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO v3_source_admission(scope, scope_id, durable_sources) VALUES (?, ?, 1) ON CONFLICT(scope, scope_id) DO UPDATE SET durable_sources = v3_source_admission.durable_sources + 1`, key.scope, key.id[:]); err != nil {
			return err
		}
	}
	return nil
}

func (s *sourceStore) admitCryptoTx(tx *sql.Tx, spec sourceSpec, units uint64) error {
	keys, err := sourceQuotaKeys(spec)
	if err != nil || units < 2 || units > 4098 {
		return errors.New("invalid crypto admission")
	}
	for _, key := range keys {
		var current uint64
		err := tx.QueryRow(`SELECT reservations FROM v3_source_crypto_admission WHERE scope = ? AND scope_id = ?`, key.scope, key.id[:]).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			current = 0
		} else if err != nil {
			return err
		}
		limit := s.scopeLimit(key.scope).CryptoReservations
		if units > limit || current > limit-units {
			return errors.New("crypto reservation budget exhausted")
		}
		if _, err := tx.Exec(`INSERT INTO v3_source_crypto_admission(scope, scope_id, reservations) VALUES (?, ?, ?) ON CONFLICT(scope, scope_id) DO UPDATE SET reservations = v3_source_crypto_admission.reservations + excluded.reservations`, key.scope, key.id[:], units); err != nil {
			return err
		}
	}
	return nil
}

func (s *sourceStore) terminalizeSourceTx(ctx context.Context, tx *sql.Tx, spec sourceSpec, now time.Time) error {
	var status transferStatus
	var attempt uint64
	if err := tx.QueryRowContext(ctx, `SELECT status, attempt_generation FROM v3_transfers WHERE transfer_id = ? AND manifest_commitment = ? AND expires_at = ?`, spec.TransferID[:], spec.ManifestCommitment[:], spec.ExpiresAt).Scan(&status, &attempt); err != nil {
		return errors.New("invalid source terminal transition")
	}
	// A completed transfer is already terminal. Older stores may still retain
	// its staging rows, so expiry recovery releases those rows without ever
	// rewriting the durable completed status.
	if status == transferCompleted && attempt == 1 {
		return s.releaseTerminalSourceTx(ctx, tx, spec, now)
	}
	if status.terminal() {
		return errors.New("invalid source terminal transition")
	}
	terminal := transferCancelled
	if now.UTC().Unix() >= spec.ExpiresAt {
		terminal = transferExpired
	}
	result, err := tx.ExecContext(ctx, `UPDATE v3_transfers SET status = ? WHERE transfer_id = ? AND manifest_commitment = ? AND status IN (?, ?, ?, ?, ?) AND expires_at = ?`, terminal, spec.TransferID[:], spec.ManifestCommitment[:], transferSourceUploading, transferSourceReady, transferOffered, transferAccepted, transferTransferring, spec.ExpiresAt)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return errors.New("invalid source terminal transition")
	}
	return s.releaseTerminalSourceTx(ctx, tx, spec, now)
}

// releaseTerminalSourceTx drops every capacity-consuming artifact after the
// caller has recorded a terminal transfer state. It never changes that state:
// completed, cancelled, and expired remain durable audit/replay outcomes.
func (s *sourceStore) releaseTerminalSourceTx(ctx context.Context, tx *sql.Tx, spec sourceSpec, now time.Time) error {
	bytes, chunks, err := sourceUsage(spec)
	if err != nil {
		return err
	}
	keys, err := sourceQuotaKeys(spec)
	if err != nil {
		return err
	}
	for _, key := range keys {
		result, err := tx.ExecContext(ctx, `UPDATE v3_source_quota SET ciphertext_bytes = ciphertext_bytes - ?, chunks = chunks - ?, transfers = transfers - 1 WHERE scope = ? AND scope_id = ? AND ciphertext_bytes >= ? AND chunks >= ? AND transfers >= 1`, bytes, chunks, key.scope, key.id[:], bytes, chunks)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return errors.New("invalid source quota release")
		}
	}
	retainUntil := now.UTC().Add(s.limits.TombstoneRetention).Unix()
	if retainUntil < spec.ExpiresAt {
		retainUntil = spec.ExpiresAt
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_source_tombstones(transfer_id, manifest_commitment, retain_until) VALUES (?, ?, ?) ON CONFLICT(transfer_id) DO NOTHING`, spec.TransferID[:], spec.ManifestCommitment[:], retainUntil); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v3_issued_permits SET retain_until = MAX(retain_until, ?) WHERE transfer_id = ? AND manifest_commitment = ?`, retainUntil, spec.TransferID[:], spec.ManifestCommitment[:]); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE v3_ledger_admission SET retain_until = MAX(retain_until, ?) WHERE transfer_id = ? AND manifest_commitment = ?`, retainUntil, spec.TransferID[:], spec.ManifestCommitment[:]); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_offers WHERE transfer_id = ?`, spec.TransferID[:]); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_receipt_chunks WHERE transfer_id = ?`, spec.TransferID[:]); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM v3_source_specs WHERE transfer_id = ?`, spec.TransferID[:]); err != nil {
		return err
	}
	return nil
}
