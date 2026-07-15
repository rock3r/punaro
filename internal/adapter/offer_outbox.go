package adapter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/relay"
	// sqlite is the local durable adapter outbox driver.
	_ "modernc.org/sqlite"
)

// OfferNoticeSender is the narrow network boundary used by the durable offer
// outbox. HTTPRelayClient implements it; tests and local recovery tooling need
// not receive an adapter private key merely to exercise persistence.
type OfferNoticeSender interface {
	Send(context.Context, string, string, string, string) (relay.Message, error)
}

// OfferNoticeOutbox persists a completed-offer notification before attempting
// the normal relay append. A crash after an accepted append but before delete
// is safe: retrying the exact idempotency key returns the same relay message.
// It intentionally stores ciphertext metadata only, never plaintext or an
// HPKE private key.
type OfferNoticeOutbox struct{ db *sql.DB }

const (
	maxOfferNoticeOutboxRows        = 64
	maxOfferNoticeOutboxBytes       = maxOfferNoticeOutboxRows * (32 << 10)
	maxOfferNoticeConversationBytes = 128
	maxOfferNoticeEndpointBytes     = 256
	maxOfferNoticeIdempotencyBytes  = 256
)

// OpenOfferNoticeOutbox creates a private local SQLite outbox. It is separate
// from the inbound journal because a recipient delivery must never control a
// sender's retry state.
func OpenOfferNoticeOutbox(database string) (*OfferNoticeOutbox, error) {
	if strings.TrimSpace(database) == "" || !filepath.IsAbs(database) {
		return nil, errors.New("absolute offer notice outbox path is required")
	}
	if err := validateOfferNoticeOutboxPath(database); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", database)
	if err != nil {
		return nil, fmt.Errorf("open offer notice outbox: %w", err)
	}
	closeDB := true
	defer func() {
		if closeDB {
			_ = db.Close()
		}
	}()
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA journal_mode = DELETE",
		"PRAGMA busy_timeout = 5000",
		`CREATE TABLE IF NOT EXISTS v3_offer_notice_outbox (
			idempotency_key TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			from_endpoint TEXT NOT NULL,
			body TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			return nil, fmt.Errorf("initialize offer notice outbox: %w", err)
		}
	}
	if err := os.Chmod(database, 0o600); err != nil {
		return nil, fmt.Errorf("set offer notice outbox permissions: %w", err)
	}
	if err := validateOfferNoticeOutboxPath(database); err != nil {
		return nil, err
	}
	closeDB = false
	return &OfferNoticeOutbox{db: db}, nil
}

// Close releases the local offer-notice journal.
func (o *OfferNoticeOutbox) Close() error {
	if o == nil || o.db == nil {
		return nil
	}
	return o.db.Close()
}

// EnqueueV3OfferNotice durably records exactly one canonical offer notice.
// Call this immediately after the attachment offer operation succeeds, before
// treating recipient discovery as complete. The idempotency key may be retried
// only with byte-identical routing and offer content.
func (o *OfferNoticeOutbox) EnqueueV3OfferNotice(ctx context.Context, conversationID, fromEndpoint string, rawOffer []byte, idempotencyKey string) error {
	if o == nil || o.db == nil || strings.TrimSpace(conversationID) == "" || strings.TrimSpace(fromEndpoint) == "" || strings.TrimSpace(idempotencyKey) == "" || len(conversationID) > maxOfferNoticeConversationBytes || len(fromEndpoint) > maxOfferNoticeEndpointBytes || len(idempotencyKey) > maxOfferNoticeIdempotencyBytes {
		return errors.New("offer notice routing and outbox are required")
	}
	body, err := attachmentv3.EncodeOfferNotice(rawOffer)
	if err != nil {
		return fmt.Errorf("encode v3 attachment offer notice: %w", err)
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var previousConversation, previousEndpoint, previousBody string
	err = tx.QueryRowContext(ctx, `SELECT conversation_id, from_endpoint, body FROM v3_offer_notice_outbox WHERE idempotency_key = ?`, idempotencyKey).Scan(&previousConversation, &previousEndpoint, &previousBody)
	if err == nil {
		if previousConversation != conversationID || previousEndpoint != fromEndpoint || previousBody != body {
			return errors.New("changed v3 offer notice idempotency key")
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var pendingCount, pendingBytes int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(length(CAST(idempotency_key AS BLOB)) + length(CAST(conversation_id AS BLOB)) + length(CAST(from_endpoint AS BLOB)) + length(CAST(body AS BLOB))), 0) FROM v3_offer_notice_outbox`).Scan(&pendingCount, &pendingBytes); err != nil {
		return err
	}
	rowBytes := len(idempotencyKey) + len(conversationID) + len(fromEndpoint) + len(body)
	if pendingCount >= maxOfferNoticeOutboxRows || pendingBytes > int64(maxOfferNoticeOutboxBytes-rowBytes) {
		return errors.New("v3 offer notice outbox capacity exhausted")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO v3_offer_notice_outbox(idempotency_key, conversation_id, from_endpoint, body, created_at) VALUES (?, ?, ?, ?, ?)`, idempotencyKey, conversationID, fromEndpoint, body, time.Now().UTC().UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

func validateOfferNoticeOutboxPath(database string) error {
	parent := filepath.Dir(database)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create offer notice outbox directory: %w", err)
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("offer notice outbox parent must be private and non-symlinked")
	}
	if info, err := os.Lstat(database); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("offer notice outbox database must be private and non-symlinked")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, sidecar := range []string{database + "-wal", database + "-shm"} {
		if _, err := os.Lstat(sidecar); err == nil {
			return errors.New("unexpected offer notice SQLite sidecar")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if info, err := os.Lstat(database + "-journal"); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.New("unsafe offer notice SQLite rollback journal")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Flush sends every pending offer notice in stable creation order. A failure
// leaves the current and later rows intact for a subsequent adapter cycle; a
// successful relay response is deleted only when the exact persisted row still
// matches, preserving at-least-once handoff across a local crash.
func (o *OfferNoticeOutbox) Flush(ctx context.Context, sender OfferNoticeSender) error {
	if o == nil || o.db == nil || sender == nil {
		return errors.New("offer notice outbox and sender are required")
	}
	rows, err := o.db.QueryContext(ctx, `SELECT idempotency_key, conversation_id, from_endpoint, body FROM v3_offer_notice_outbox ORDER BY created_at, idempotency_key`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	type pending struct{ key, conversation, endpoint, body string }
	var notices []pending
	for rows.Next() {
		var notice pending
		if err := rows.Scan(&notice.key, &notice.conversation, &notice.endpoint, &notice.body); err != nil {
			return err
		}
		notices = append(notices, notice)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, notice := range notices {
		if _, err := sender.Send(ctx, notice.conversation, notice.endpoint, notice.body, notice.key); err != nil {
			return fmt.Errorf("deliver v3 offer notice: %w", err)
		}
		result, err := o.db.ExecContext(ctx, `DELETE FROM v3_offer_notice_outbox WHERE idempotency_key = ? AND conversation_id = ? AND from_endpoint = ? AND body = ?`, notice.key, notice.conversation, notice.endpoint, notice.body)
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			return errors.New("offer notice outbox changed during delivery")
		}
	}
	return nil
}
