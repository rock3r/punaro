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

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	_ "modernc.org/sqlite"
)

// Journal is the controller's private, single-writer durable state. It holds
// only immutable policy and discovery records at this layer; device keys and
// plaintext are intentionally not stored here.
type Journal struct{ db *sql.DB }

// OpenJournal opens a private non-symlinked SQLite database. The parent is
// created only with owner permissions and an existing weaker parent is
// rejected rather than repaired implicitly.
func OpenJournal(path string) (*Journal, error) {
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
		`CREATE TABLE IF NOT EXISTS controller_inbound_offers (
			punaro_message_id TEXT PRIMARY KEY, relay_conversation_id TEXT NOT NULL,
			offer BLOB NOT NULL, transfer_id BLOB NOT NULL,
			FOREIGN KEY(relay_conversation_id) REFERENCES controller_mappings(relay_conversation_id)
		)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize controller journal: %w", err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Journal{db: db}, nil
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
	existing, found, err := j.mapping(mapping.RelayConversationID)
	if err != nil {
		return err
	}
	if found {
		if existing != mapping {
			return errors.New("controller mapping is immutable")
		}
		return nil
	}
	_, err = j.db.ExecContext(context.Background(), `INSERT INTO controller_mappings(
		relay_conversation_id, conversation_id, sender_device_id, sender_generation,
		recipient_device_id, recipient_generation, membership_commitment
	) VALUES (?, ?, ?, ?, ?, ?, ?)`, mapping.RelayConversationID, mapping.ConversationID[:], mapping.SenderDeviceID[:], mapping.SenderGeneration, mapping.RecipientDeviceID[:], mapping.RecipientGeneration, mapping.MembershipCommitment[:])
	return err
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
	var storedOffer, storedConversation []byte
	err = j.db.QueryRowContext(context.Background(), `SELECT offer, relay_conversation_id FROM controller_inbound_offers WHERE punaro_message_id = ?`, inbound.PunaroMessageID).Scan(&storedOffer, &storedConversation)
	if err == nil {
		if string(storedConversation) != inbound.RelayConversationID || !bytes.Equal(storedOffer, notice.Raw) {
			return attachmentv3.OfferNotice{}, false, errors.New("changed v3 offer retry")
		}
		return notice, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return attachmentv3.OfferNotice{}, false, err
	}
	_, err = j.db.ExecContext(context.Background(), `INSERT INTO controller_inbound_offers(punaro_message_id, relay_conversation_id, offer, transfer_id) VALUES (?, ?, ?, ?)`, inbound.PunaroMessageID, inbound.RelayConversationID, notice.Raw, notice.Manifest.TransferID[:])
	if err != nil {
		return attachmentv3.OfferNotice{}, false, err
	}
	return notice, true, nil
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
