package controller

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	_ "modernc.org/sqlite"
)

// Journal is the controller's private, single-writer durable state. It holds
// only immutable policy and discovery records at this layer; device keys and
// plaintext are intentionally not stored here.
type Journal struct {
	db        *sql.DB
	recipient RecipientIdentity
	acceptMu  sync.Mutex
	receiptMu sync.Mutex
	senderMu  sync.Mutex
}

// RecipientIdentity pins this controller to its own enrolled attachment
// device. It is local configuration, never selected from a relay message.
type RecipientIdentity struct {
	DeviceID   [16]byte
	Generation uint64
}

func (r RecipientIdentity) valid() bool { return r.DeviceID != [16]byte{} && r.Generation != 0 }

const (
	maxPendingOffers       = 64
	maxPendingOfferBytes   = 2 << 20
	maxPendingSenderStages = 64
)

// OpenJournal opens a private non-symlinked SQLite database. The parent is
// created only with owner permissions and an existing weaker parent is
// rejected rather than repaired implicitly.
func OpenJournal(path string) (*Journal, error) {
	return openJournal(path, RecipientIdentity{})
}

// OpenJournalForRecipient creates a controller journal bound to exactly one
// local recipient device generation.
func OpenJournalForRecipient(path string, recipient RecipientIdentity) (*Journal, error) {
	if !recipient.valid() {
		return nil, errors.New("invalid controller recipient identity")
	}
	return openJournal(path, recipient)
}

func openJournal(path string, recipient RecipientIdentity) (*Journal, error) {
	if !filepath.IsAbs(path) || strings.TrimSpace(path) == "" {
		return nil, errors.New("controller journal path must be absolute")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create controller journal parent: %w", err)
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("controller journal parent must be private and non-symlinked")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("controller journal database must be private and non-symlinked")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// SQLite may recover a private rollback journal under DELETE mode, but WAL
	// artifacts would let stale, separately mutable state affect the database.
	// Validate any rollback journal before SQLite sees it and fail closed on WAL
	// sidecars, which this controller never uses.
	if info, err := os.Lstat(path + "-journal"); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("controller journal rollback journal must be private and non-symlinked")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Lstat(sidecar); err == nil {
			return nil, errors.New("controller journal has unexpected SQLite sidecar")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA journal_mode = DELETE", "PRAGMA busy_timeout = 5000", "PRAGMA foreign_keys = ON",
		`CREATE TABLE IF NOT EXISTS controller_mappings (
			relay_conversation_id TEXT PRIMARY KEY, conversation_id BLOB NOT NULL,
			sender_device_id BLOB NOT NULL, sender_generation INTEGER NOT NULL,
			recipient_device_id BLOB NOT NULL, recipient_generation INTEGER NOT NULL,
			membership_commitment BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS controller_recipient_identity (
			singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
			device_id BLOB NOT NULL, generation INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS controller_inbound_offers (
			punaro_message_id TEXT PRIMARY KEY, relay_conversation_id TEXT NOT NULL,
			offer BLOB NOT NULL, transfer_id BLOB NOT NULL,
			expires_at INTEGER NOT NULL DEFAULT 9223372036854775807,
			FOREIGN KEY(relay_conversation_id) REFERENCES controller_mappings(relay_conversation_id)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS controller_offer_transfer_identity
			ON controller_inbound_offers(relay_conversation_id, transfer_id)`,
		`CREATE TABLE IF NOT EXISTS controller_receipt_approvals (
			punaro_message_id TEXT PRIMARY KEY, offer_commitment BLOB NOT NULL,
			approved_at INTEGER NOT NULL,
			FOREIGN KEY(punaro_message_id) REFERENCES controller_inbound_offers(punaro_message_id)
		)`,
		`CREATE TABLE IF NOT EXISTS controller_receipt_acceptances (
			punaro_message_id TEXT PRIMARY KEY, transfer_id BLOB NOT NULL,
			manifest_commitment BLOB NOT NULL, acceptance_nonce BLOB NOT NULL, permit_request BLOB NOT NULL,
			operation_id BLOB NOT NULL, idempotency_key BLOB NOT NULL,
			permit BLOB, operation BLOB, result BLOB,
			FOREIGN KEY(punaro_message_id) REFERENCES controller_inbound_offers(punaro_message_id)
		)`,
		`CREATE TABLE IF NOT EXISTS controller_receipt_reconciliation (
			punaro_message_id TEXT PRIMARY KEY, state TEXT NOT NULL,
			uncertain_at INTEGER NOT NULL, terminal_at INTEGER,
			outcome_request BLOB, outcome_operation_id BLOB, outcome_idempotency_key BLOB,
			outcome_permit BLOB, outcome_operation BLOB, outcome_result BLOB,
			FOREIGN KEY(punaro_message_id) REFERENCES controller_receipt_acceptances(punaro_message_id)
		)`,
		// Outcome permits are deliberately append-only attempts. A lookup request
		// can be accepted remotely just before a client crash; after its permit
		// expires the controller must mint a fresh lookup capability rather than
		// reusing an expired one or treating a transient failure as terminal.
		`CREATE TABLE IF NOT EXISTS controller_receipt_outcome_attempts (
			punaro_message_id TEXT NOT NULL, attempt_index INTEGER NOT NULL,
			permit_request BLOB NOT NULL, operation_id BLOB NOT NULL, idempotency_key BLOB NOT NULL,
			permit BLOB, operation BLOB, result BLOB,
			PRIMARY KEY(punaro_message_id, attempt_index),
			FOREIGN KEY(punaro_message_id) REFERENCES controller_receipt_reconciliation(punaro_message_id)
		)`,
		// The recipient keeps only opaque relay ciphertext and exact signed
		// operation records. Its HPKE-unwrapped file key is intentionally never
		// journalled: after restart it is re-opened from the immutable offer using
		// the local recipient key.
		`CREATE TABLE IF NOT EXISTS controller_receipt_downloads (
			punaro_message_id TEXT PRIMARY KEY, transfer_id BLOB NOT NULL,
			manifest BLOB NOT NULL, envelope BLOB NOT NULL, output_path TEXT NOT NULL,
			manifest_commitment BLOB NOT NULL, state TEXT NOT NULL,
			FOREIGN KEY(punaro_message_id) REFERENCES controller_receipt_acceptances(punaro_message_id)
		)`,
		`CREATE TABLE IF NOT EXISTS controller_receipt_download_chunks (
			punaro_message_id TEXT NOT NULL, chunk_index INTEGER NOT NULL,
			ciphertext BLOB NOT NULL, ciphertext_commitment BLOB NOT NULL,
			PRIMARY KEY(punaro_message_id, chunk_index),
			FOREIGN KEY(punaro_message_id) REFERENCES controller_receipt_downloads(punaro_message_id)
		)`,
		`CREATE TABLE IF NOT EXISTS controller_receipt_download_operations (
			punaro_message_id TEXT NOT NULL, phase TEXT NOT NULL, chunk_index INTEGER NOT NULL,
			permit_request BLOB NOT NULL, operation_id BLOB NOT NULL, idempotency_key BLOB NOT NULL,
			permit BLOB, operation BLOB, result BLOB,
			PRIMARY KEY(punaro_message_id, phase, chunk_index),
			FOREIGN KEY(punaro_message_id) REFERENCES controller_receipt_downloads(punaro_message_id)
		)`,
		`CREATE TABLE IF NOT EXISTS controller_sender_transfers (
			transfer_id BLOB PRIMARY KEY, relay_conversation_id TEXT NOT NULL,
			manifest BLOB NOT NULL, manifest_commitment BLOB NOT NULL,
			wrapped_file_key BLOB NOT NULL, envelope BLOB, offer BLOB, offer_nonce BLOB,
			FOREIGN KEY(relay_conversation_id) REFERENCES controller_mappings(relay_conversation_id)
		)`,
		`CREATE TABLE IF NOT EXISTS controller_sender_stage_intents (
			stage_id BLOB PRIMARY KEY, transfer_id BLOB NOT NULL UNIQUE,
			relay_conversation_id TEXT NOT NULL, manifest BLOB NOT NULL,
			manifest_commitment BLOB NOT NULL, wrapped_file_key BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(relay_conversation_id) REFERENCES controller_mappings(relay_conversation_id)
		)`,
		`CREATE TABLE IF NOT EXISTS controller_sender_chunks (
			transfer_id BLOB NOT NULL, chunk_index INTEGER NOT NULL,
			ciphertext BLOB NOT NULL, ciphertext_commitment BLOB NOT NULL,
			PRIMARY KEY(transfer_id, chunk_index),
			FOREIGN KEY(transfer_id) REFERENCES controller_sender_transfers(transfer_id)
		)`,
		`CREATE TABLE IF NOT EXISTS controller_sender_operations (
			transfer_id BLOB NOT NULL, phase TEXT NOT NULL, chunk_index INTEGER NOT NULL,
			permit_request BLOB NOT NULL, operation_id BLOB NOT NULL, idempotency_key BLOB NOT NULL,
			permit BLOB, operation BLOB, result BLOB,
			PRIMARY KEY(transfer_id, phase, chunk_index),
			FOREIGN KEY(transfer_id) REFERENCES controller_sender_transfers(transfer_id)
		)`,
		// Outcome attempts are separate from the operation they reconcile. A
		// response can be lost too, so each expired attempt receives a new,
		// durably retained outcome capability without rewriting the original.
		`CREATE TABLE IF NOT EXISTS controller_sender_outcome_attempts (
			transfer_id BLOB NOT NULL, phase TEXT NOT NULL, chunk_index INTEGER NOT NULL,
			attempt_index INTEGER NOT NULL, permit_request BLOB NOT NULL,
			operation_id BLOB NOT NULL, idempotency_key BLOB NOT NULL,
			permit BLOB, operation BLOB, result BLOB,
			PRIMARY KEY(transfer_id, phase, chunk_index, attempt_index),
			FOREIGN KEY(transfer_id, phase, chunk_index) REFERENCES controller_sender_operations(transfer_id, phase, chunk_index)
		)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize controller journal: %w", err)
		}
	}
	if err := ensureInboundOfferExpiryColumn(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate controller journal: %w", err)
	}
	if err := ensureReceiptAcceptanceNonceColumn(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate controller journal: %w", err)
	}
	if err := ensureSenderTransferKeySchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate sender key journal: %w", err)
	}
	if err := bindJournalRecipient(db, recipient); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("bind controller recipient: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Journal{db: db, recipient: recipient}, nil
}

// ensureSenderTransferKeySchema fails closed on an old journal which may
// contain raw file keys. Empty pre-release tables are safe to replace; a row
// requires an explicit operator purge rather than a best-effort migration
// which could preserve secret material under a misleading new column name.
func ensureSenderTransferKeySchema(db *sql.DB) error {
	if db == nil {
		return errors.New("missing controller journal")
	}
	rows, err := db.QueryContext(context.Background(), `PRAGMA table_info(controller_sender_transfers)`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var hasRaw, hasWrapped bool
	for rows.Next() {
		var cid, notNull, primary int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primary); err != nil {
			return err
		}
		hasRaw = hasRaw || name == "file_key"
		hasWrapped = hasWrapped || name == "wrapped_file_key"
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if hasWrapped && !hasRaw {
		return nil
	}
	if !hasRaw || hasWrapped {
		return errors.New("invalid sender key journal schema")
	}
	var transfers, chunks, operations int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM controller_sender_transfers`).Scan(&transfers); err != nil {
		return err
	}
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM controller_sender_chunks`).Scan(&chunks); err != nil {
		return err
	}
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM controller_sender_operations`).Scan(&operations); err != nil {
		return err
	}
	if transfers != 0 || chunks != 0 || operations != 0 {
		return errors.New("legacy journal contains unsafe raw sender key material")
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range []string{
		`DROP TABLE controller_sender_operations`,
		`DROP TABLE controller_sender_chunks`,
		`DROP TABLE controller_sender_transfers`,
		`CREATE TABLE controller_sender_transfers (
			transfer_id BLOB PRIMARY KEY, relay_conversation_id TEXT NOT NULL,
			manifest BLOB NOT NULL, manifest_commitment BLOB NOT NULL,
			wrapped_file_key BLOB NOT NULL, envelope BLOB, offer BLOB, offer_nonce BLOB,
			FOREIGN KEY(relay_conversation_id) REFERENCES controller_mappings(relay_conversation_id)
		)`,
		`CREATE TABLE controller_sender_chunks (
			transfer_id BLOB NOT NULL, chunk_index INTEGER NOT NULL,
			ciphertext BLOB NOT NULL, ciphertext_commitment BLOB NOT NULL,
			PRIMARY KEY(transfer_id, chunk_index),
			FOREIGN KEY(transfer_id) REFERENCES controller_sender_transfers(transfer_id)
		)`,
		`CREATE TABLE controller_sender_operations (
			transfer_id BLOB NOT NULL, phase TEXT NOT NULL, chunk_index INTEGER NOT NULL,
			permit_request BLOB NOT NULL, operation_id BLOB NOT NULL, idempotency_key BLOB NOT NULL,
			permit BLOB, operation BLOB, result BLOB,
			PRIMARY KEY(transfer_id, phase, chunk_index),
			FOREIGN KEY(transfer_id) REFERENCES controller_sender_transfers(transfer_id)
		)`,
	} {
		if _, err := tx.ExecContext(context.Background(), statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// bindJournalRecipient makes the local recipient pin durable. A process
// cannot reopen an existing controller journal under another device identity
// merely by changing its local configuration.
func bindJournalRecipient(db *sql.DB, recipient RecipientIdentity) error {
	var device []byte
	var generation uint64
	err := db.QueryRowContext(context.Background(), `SELECT device_id, generation FROM controller_recipient_identity WHERE singleton = 1`).Scan(&device, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		if !recipient.valid() {
			return nil
		}
		if _, err := db.ExecContext(context.Background(), `INSERT INTO controller_recipient_identity(singleton, device_id, generation) VALUES (1, ?, ?) ON CONFLICT(singleton) DO NOTHING`, recipient.DeviceID[:], recipient.Generation); err != nil {
			return err
		}
		err = db.QueryRowContext(context.Background(), `SELECT device_id, generation FROM controller_recipient_identity WHERE singleton = 1`).Scan(&device, &generation)
	}
	if err != nil || len(device) != len(recipient.DeviceID) || generation == 0 {
		return errors.New("invalid durable controller recipient identity")
	}
	if !recipient.valid() || !bytes.Equal(device, recipient.DeviceID[:]) || generation != recipient.Generation {
		return errors.New("controller journal recipient identity mismatch")
	}
	return nil
}

func (j *Journal) Close() error {
	if j == nil || j.db == nil {
		return nil
	}
	return j.db.Close()
}

// AddMapping stores a local operator-approved mapping exactly once. Repeating
// identical bytes is safe; changing any identity or membership is rejected.
func (j *Journal) AddMapping(mapping Mapping) error {
	if j == nil || j.db == nil || !mapping.valid() {
		return errors.New("invalid controller mapping")
	}
	if j.recipient.valid() && (mapping.RecipientDeviceID != j.recipient.DeviceID || mapping.RecipientGeneration != j.recipient.Generation) {
		return errors.New("controller mapping recipient is not local")
	}
	result, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_mappings(
		relay_conversation_id, conversation_id, sender_device_id, sender_generation,
		recipient_device_id, recipient_generation, membership_commitment
	) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(relay_conversation_id) DO NOTHING`, mapping.RelayConversationID, mapping.ConversationID[:], mapping.SenderDeviceID[:], mapping.SenderGeneration, mapping.RecipientDeviceID[:], mapping.RecipientGeneration, mapping.MembershipCommitment[:])
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 1 {
		return nil
	}
	existing, found, err := j.mapping(mapping.RelayConversationID)
	if err != nil {
		return err
	}
	if !found || existing != mapping {
		return errors.New("controller mapping is immutable")
	}
	return nil
}

// RecordInboundOffer validates an inert relay delivery against its stored
// mapping, then durably records the exact canonical offer before returning it.
// A duplicate message is accepted only when it is byte-for-byte identical.
func (j *Journal) RecordInboundOffer(inbound InboundOffer) (attachmentv3.OfferNotice, bool, error) {
	if j == nil || j.db == nil {
		return attachmentv3.OfferNotice{}, false, errors.New("controller journal is unavailable")
	}
	mapping, found, err := j.mapping(inbound.RelayConversationID)
	if err != nil || !found {
		return attachmentv3.OfferNotice{}, false, errors.New("unmapped v3 offer delivery")
	}
	notice, err := ValidateInboundOffer(inbound, mapping)
	if err != nil {
		return attachmentv3.OfferNotice{}, false, err
	}
	var transferOffer []byte
	err = j.db.QueryRowContext(context.Background(), `SELECT offer FROM controller_inbound_offers WHERE relay_conversation_id = ? AND transfer_id = ?`, inbound.RelayConversationID, notice.Manifest.TransferID[:]).Scan(&transferOffer)
	if err == nil {
		if bytes.Equal(transferOffer, notice.Raw) {
			return notice, false, nil
		}
		return attachmentv3.OfferNotice{}, false, errors.New("conflicting v3 offer transfer")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return attachmentv3.OfferNotice{}, false, err
	}
	result, err := j.db.ExecContext(context.Background(), `INSERT INTO controller_inbound_offers(punaro_message_id, relay_conversation_id, offer, transfer_id, expires_at)
		SELECT ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM controller_inbound_offers) < ?
		AND (SELECT COALESCE(SUM(length(offer)), 0) FROM controller_inbound_offers) + ? <= ?
		ON CONFLICT DO NOTHING`, inbound.PunaroMessageID, inbound.RelayConversationID, notice.Raw, notice.Manifest.TransferID[:], int64(notice.Manifest.ExpiresAt), maxPendingOffers, len(notice.Raw), maxPendingOfferBytes)
	if err != nil {
		return attachmentv3.OfferNotice{}, false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return attachmentv3.OfferNotice{}, false, err
	}
	if inserted == 1 {
		return notice, true, nil
	}
	var storedOffer []byte
	var storedConversation string
	err = j.db.QueryRowContext(context.Background(), `SELECT offer, relay_conversation_id FROM controller_inbound_offers WHERE punaro_message_id = ?`, inbound.PunaroMessageID).Scan(&storedOffer, &storedConversation)
	if err == nil {
		if storedConversation == inbound.RelayConversationID && bytes.Equal(storedOffer, notice.Raw) {
			return notice, false, nil
		}
		return attachmentv3.OfferNotice{}, false, errors.New("changed v3 offer retry")
	}
	err = j.db.QueryRowContext(context.Background(), `SELECT offer FROM controller_inbound_offers WHERE relay_conversation_id = ? AND transfer_id = ?`, inbound.RelayConversationID, notice.Manifest.TransferID[:]).Scan(&transferOffer)
	if err == nil {
		if bytes.Equal(transferOffer, notice.Raw) {
			return notice, false, nil
		}
		return attachmentv3.OfferNotice{}, false, errors.New("conflicting v3 offer transfer")
	}
	if errors.Is(err, sql.ErrNoRows) {
		return attachmentv3.OfferNotice{}, false, errors.New("v3 offer discovery capacity exhausted")
	}
	return attachmentv3.OfferNotice{}, false, err
}

// ReapExpiredUnapprovedOffers releases bounded discovery capacity without
// revoking an explicit local decision or an in-progress durable acceptance.
// It is intentionally invoked by a privileged maintenance loop rather than
// on inbound delivery, so wall-clock drift cannot cause a delivery to erase a
// just-recorded offer behind the caller's back.
func (j *Journal) ReapExpiredUnapprovedOffers(now time.Time, limit int) (int, error) {
	if j == nil || j.db == nil || now.UTC().Unix() < 0 || limit < 1 || limit > maxPendingOffers {
		return 0, errors.New("invalid expired v3 offer reap")
	}
	result, err := j.db.ExecContext(context.Background(), `DELETE FROM controller_inbound_offers
		WHERE punaro_message_id IN (
			SELECT inbound.punaro_message_id FROM controller_inbound_offers AS inbound
			WHERE inbound.expires_at <= ?
				AND NOT EXISTS (SELECT 1 FROM controller_receipt_approvals AS approval WHERE approval.punaro_message_id = inbound.punaro_message_id)
				AND NOT EXISTS (SELECT 1 FROM controller_receipt_acceptances AS acceptance WHERE acceptance.punaro_message_id = inbound.punaro_message_id)
			ORDER BY inbound.expires_at, inbound.punaro_message_id
			LIMIT ?
		)`, now.UTC().Unix(), limit)
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(deleted), nil
}

func ensureInboundOfferExpiryColumn(db *sql.DB) error {
	rows, err := db.QueryContext(context.Background(), `PRAGMA table_info(controller_inbound_offers)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue sql.NullString
		var primaryKey int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		if name == "expires_at" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// Legacy records were written before an expiry was persisted. Retaining
	// them is safer than guessing their expiry from untrusted relay material.
	_, err = db.ExecContext(context.Background(), `ALTER TABLE controller_inbound_offers ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 9223372036854775807`)
	return err
}

// The acceptance table is introduced alongside this controller. The nullable
// legacy migration is intentional: an old in-progress row lacks its exact
// nonce and is rejected by receiptAcceptance rather than being reconstructed
// from a changed relay delivery.
func ensureReceiptAcceptanceNonceColumn(db *sql.DB) error {
	rows, err := db.QueryContext(context.Background(), `PRAGMA table_info(controller_receipt_acceptances)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue sql.NullString
		var primaryKey int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return err
		}
		if name == "acceptance_nonce" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.ExecContext(context.Background(), `ALTER TABLE controller_receipt_acceptances ADD COLUMN acceptance_nonce BLOB`)
	return err
}

func (j *Journal) mapping(relayConversationID string) (Mapping, bool, error) {
	if strings.TrimSpace(relayConversationID) == "" {
		return Mapping{}, false, nil
	}
	var mapping Mapping
	var conversation, sender, recipient, membership []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT conversation_id, sender_device_id, sender_generation, recipient_device_id, recipient_generation, membership_commitment FROM controller_mappings WHERE relay_conversation_id = ?`, relayConversationID).Scan(&conversation, &sender, &mapping.SenderGeneration, &recipient, &mapping.RecipientGeneration, &membership)
	if errors.Is(err, sql.ErrNoRows) {
		return Mapping{}, false, nil
	}
	if err != nil || len(conversation) != 16 || len(sender) != 16 || len(recipient) != 16 || len(membership) != 32 {
		return Mapping{}, false, errors.New("invalid controller mapping record")
	}
	mapping.RelayConversationID = relayConversationID
	copy(mapping.ConversationID[:], conversation)
	copy(mapping.SenderDeviceID[:], sender)
	copy(mapping.RecipientDeviceID[:], recipient)
	copy(mapping.MembershipCommitment[:], membership)
	if !mapping.valid() {
		return Mapping{}, false, errors.New("invalid controller mapping record")
	}
	return mapping, true, nil
}
