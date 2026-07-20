// Package relay provides the durable, authorization-aware core of the Punaro
// message relay. HTTP adapters authenticate callers before invoking this
// package; this package still verifies machine-to-endpoint ownership for every
// state transition so that a mistaken handler cannot grant cross-machine
// access.
package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	// sqlite is the durable embedded relay store driver.
	_ "modernc.org/sqlite"
)

const maxMessageBodyBytes = 32 << 10

var (
	// ErrForbidden intentionally does not disclose whether a referenced object
	// exists. Handlers map it to one stable client error.
	ErrForbidden = errors.New("relay authorization denied")
	// ErrConflict denotes a valid request that conflicts with durable state,
	// such as reusing an idempotency key with another request body.
	ErrConflict = errors.New("relay state conflict")
	// ErrMaintenance is a retryable, payload-free refusal while the durable
	// update fence owns application mutations.
	ErrMaintenance = errors.New("relay maintenance in progress")
)

// Capability controls an endpoint's membership in a conversation.
type Capability uint8

const (
	// CapSend permits an endpoint to append messages to the conversation.
	CapSend Capability = 1 << iota
	// CapReceive permits an endpoint to receive durable deliveries.
	CapReceive
	// CapAdmin reserves room-administration authority for a live endpoint.
	CapAdmin
)

// Member is an explicitly authorized conversation endpoint.
type Member struct {
	Endpoint     string
	Capabilities Capability
}

// Conversation is an immutable identifier returned when a room is created.
type Conversation struct {
	ID string `json:"id"`
}

// Message is immutable accepted message data. Bodies must be treated as
// untrusted opaque text by every adapter and gateway.
type Message struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversation_id"`
	Sequence       int64     `json:"sequence"`
	FromEndpoint   string    `json:"from_endpoint"`
	Body           string    `json:"body"`
	CreatedAt      time.Time `json:"created_at"`
}

// Delivery is a recipient-specific lease for one immutable message.
type Delivery struct {
	ID                string    `json:"id"`
	RecipientEndpoint string    `json:"recipient_endpoint"`
	Message           Message   `json:"message"`
	LeaseToken        string    `json:"lease_token"`
	LeaseGeneration   int64     `json:"lease_generation"`
	LeaseUntil        time.Time `json:"lease_until"`
}

// AppendInput contains one client retry domain. IdempotencyKey is scoped to
// SenderMachineID and may only be reused with identical message data.
type AppendInput struct {
	ConversationID  string
	SenderMachineID string
	FromEndpoint    string
	Body            string
	IdempotencyKey  string
	Now             time.Time
}

// CreateConversationInput identifies one create retry domain. IdempotencyKey
// is scoped to MachineID and is bound to the creator plus normalized members.
type CreateConversationInput struct {
	MachineID       string
	IdempotencyKey  string
	CreatorEndpoint string
	Members         []Member
	Now             time.Time
}

// Store owns SQLite-backed relay state.
type Store struct {
	db *sql.DB
}

// Open creates or opens a SQLite WAL database with the full durable delivery
// schema. The database directory is private to the service account.
func Open(database string) (*Store, error) {
	if strings.TrimSpace(database) == "" {
		return nil, fmt.Errorf("relay database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(database), 0o700); err != nil {
		return nil, fmt.Errorf("create relay data directory: %w", err)
	}
	db, err := sql.Open("sqlite", database)
	if err != nil {
		return nil, fmt.Errorf("open relay database: %w", err)
	}
	// SQLite has one writer. Keeping one pooled connection makes that boundary
	// explicit and prevents connection-local PRAGMAs or concurrent BEGIN calls
	// from surfacing SQLITE_BUSY instead of orderly transactional serialization.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the durable state database.
func (s *Store) Close() error { return s.db.Close() }

// ConsumeRequestNonce atomically prunes expired replay records and records one
// signed request nonce. A duplicate is intentionally indistinguishable from
// another authentication failure.
func (s *Store) ConsumeRequestNonce(machineID, nonce string, now, expiresAt time.Time) error {
	if !ValidMachineID(machineID) || !ValidRequestToken(nonce) || !expiresAt.After(now) {
		return ErrForbidden
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if _, err := tx.ExecContext(context.Background(), "DELETE FROM request_nonces WHERE expires_at <= ?", now.UnixMilli()); err != nil {
		return fmt.Errorf("prune request nonces: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO request_nonces(machine_id, nonce, expires_at) VALUES (?, ?, ?)", machineID, nonce, expiresAt.UnixMilli()); err != nil {
		return ErrForbidden
	}
	return tx.Commit()
}

func (s *Store) migrate(ctx context.Context) error {
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		`CREATE TABLE IF NOT EXISTS endpoints (
			endpoint TEXT PRIMARY KEY,
			machine_id TEXT NOT NULL,
			lease_until INTEGER NOT NULL,
			ownership_generation INTEGER NOT NULL DEFAULT 1,
			consumer_id TEXT,
			consumer_generation INTEGER NOT NULL DEFAULT 0,
			consumer_lease_until INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS conversations (
			id TEXT PRIMARY KEY,
			next_sequence INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS memberships (
			conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			endpoint TEXT NOT NULL,
			capabilities INTEGER NOT NULL,
			PRIMARY KEY (conversation_id, endpoint)
		)`,
		`CREATE TABLE IF NOT EXISTS messages (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			sequence INTEGER NOT NULL,
			from_endpoint TEXT NOT NULL,
			body TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE (conversation_id, sequence)
		)`,
		`CREATE TABLE IF NOT EXISTS deliveries (
			id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
			recipient_endpoint TEXT NOT NULL,
			lease_machine_id TEXT,
			lease_token TEXT,
			lease_generation INTEGER NOT NULL DEFAULT 0,
			ownership_generation INTEGER,
			consumer_generation INTEGER,
			lease_until INTEGER,
			acked_at INTEGER,
			UNIQUE (message_id, recipient_endpoint)
		)`,
		`CREATE TABLE IF NOT EXISTS recipient_cursors (
			recipient_endpoint TEXT NOT NULL,
			conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			sequence INTEGER NOT NULL DEFAULT 0 CHECK (sequence >= 0),
			PRIMARY KEY (recipient_endpoint, conversation_id)
		)`,
		`CREATE TABLE IF NOT EXISTS idempotency (
			machine_id TEXT NOT NULL,
			key TEXT NOT NULL,
			request_hash TEXT NOT NULL,
			message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (machine_id, key)
		)`,
		`CREATE TABLE IF NOT EXISTS conversation_idempotency (
			machine_id TEXT NOT NULL,
			key TEXT NOT NULL,
			request_hash TEXT NOT NULL,
			conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (machine_id, key)
		)`,
		`CREATE TABLE IF NOT EXISTS request_nonces (
			machine_id TEXT NOT NULL,
			nonce TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			PRIMARY KEY (machine_id, nonce)
		)`,
		"CREATE INDEX IF NOT EXISTS deliveries_recipient_pending ON deliveries(recipient_endpoint, acked_at, lease_until)",
		"CREATE INDEX IF NOT EXISTS request_nonces_expiry ON request_nonces(expires_at)",
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate relay database: %w", err)
		}
	}
	for _, column := range []struct {
		table, name, definition string
	}{
		{"endpoints", "ownership_generation", "INTEGER NOT NULL DEFAULT 1"},
		{"endpoints", "consumer_id", "TEXT"},
		{"endpoints", "consumer_generation", "INTEGER NOT NULL DEFAULT 0"},
		{"endpoints", "consumer_lease_until", "INTEGER"},
		{"deliveries", "ownership_generation", "INTEGER"},
		{"deliveries", "consumer_generation", "INTEGER"},
	} {
		if err := ensureSQLiteColumn(ctx, s.db, column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	return nil
}

func ensureSQLiteColumn(ctx context.Context, db *sql.DB, table, name, definition string) error {
	if table != "endpoints" && table != "deliveries" {
		return errors.New("invalid relay migration table")
	}
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")") // #nosec G202 -- table is restricted above to fixed internal names.
	if err != nil {
		return fmt.Errorf("inspect relay table %s: %w", table, err)
	}
	found := false
	for rows.Next() {
		var sequence int
		var columnName, columnType string
		var required, primaryKey int
		var defaultValue sql.NullString
		if err := rows.Scan(&sequence, &columnName, &columnType, &required, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inspect relay table %s: %w", table, err)
		}
		found = found || columnName == name
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("inspect relay table %s: %w", table, err)
	}
	if found {
		return nil
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+name+" "+definition); err != nil { // #nosec G202 -- all values come from the fixed migration list above.
		return fmt.Errorf("upgrade relay table %s: %w", table, err)
	}
	return nil
}

// AdvertiseEndpoints atomically replaces a machine's locally attached
// endpoints. Detached endpoints cannot fetch or acknowledge deliveries until
// their owning machine advertises them again.
func (s *Store) AdvertiseEndpoints(machineID string, endpoints []string, now time.Time, ttl time.Duration) error {
	if !ValidMachineID(machineID) || ttl <= 0 {
		return fmt.Errorf("invalid endpoint lease")
	}
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if !ValidEndpoint(endpoint) {
			return fmt.Errorf("endpoint is required")
		}
		if _, duplicate := seen[endpoint]; duplicate {
			return fmt.Errorf("duplicate endpoint %q", endpoint)
		}
		seen[endpoint] = struct{}{}
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	rows, err := tx.QueryContext(context.Background(), `SELECT endpoint FROM endpoints WHERE machine_id = ? AND lease_until > ?`, machineID, now.UnixMilli())
	if err != nil {
		return fmt.Errorf("find attached endpoints: %w", err)
	}
	var detached []string
	for rows.Next() {
		var endpoint string
		if err := rows.Scan(&endpoint); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read attached endpoint: %w", err)
		}
		if _, retained := seen[endpoint]; !retained {
			detached = append(detached, endpoint)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("find attached endpoints: %w", err)
	}
	for _, endpoint := range detached {
		if _, err := tx.ExecContext(context.Background(), `UPDATE endpoints
			SET lease_until = ?, ownership_generation = ownership_generation + 1,
			    consumer_id = NULL, consumer_lease_until = NULL
			WHERE endpoint = ? AND machine_id = ? AND lease_until > ?`, now.UnixMilli(), endpoint, machineID, now.UnixMilli()); err != nil {
			return fmt.Errorf("detach endpoint: %w", err)
		}
	}
	until := now.Add(ttl).UnixMilli()
	for endpoint := range seen {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO endpoints(endpoint, machine_id, lease_until) VALUES (?, ?, ?)
			ON CONFLICT(endpoint) DO UPDATE SET
				ownership_generation = CASE WHEN endpoints.machine_id <> excluded.machine_id OR endpoints.lease_until <= ? THEN endpoints.ownership_generation + 1 ELSE endpoints.ownership_generation END,
				consumer_id = CASE WHEN endpoints.machine_id <> excluded.machine_id OR endpoints.lease_until <= ? THEN NULL ELSE endpoints.consumer_id END,
				consumer_lease_until = CASE WHEN endpoints.machine_id <> excluded.machine_id OR endpoints.lease_until <= ? THEN NULL ELSE endpoints.consumer_lease_until END,
				machine_id = excluded.machine_id, lease_until = excluded.lease_until`, endpoint, machineID, until, now.UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
			return fmt.Errorf("advertise endpoint: %w", err)
		}
	}
	return tx.Commit()
}

// AssertEndpointOwnership verifies the currently attached owner without
// revealing endpoint inventory. It is used by routes whose operation creates
// authority from an endpoint label, such as initial conversation creation.
func (s *Store) AssertEndpointOwnership(machineID, endpoint string, now time.Time) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, endpoint, machineID, now); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateConversation creates a room only if its creator and every initial
// member are actively attached. The caller must grant itself all three rights,
// preventing a room that no live operator can administer.
func (s *Store) CreateConversation(creatorEndpoint string, members []Member, now time.Time) (Conversation, error) {
	return s.createConversation(CreateConversationInput{CreatorEndpoint: creatorEndpoint, Members: members, Now: now})
}

// CreateConversationIdempotent creates a room once for a signed machine retry
// domain. A repeated key with a different normalized request is a conflict.
func (s *Store) CreateConversationIdempotent(input CreateConversationInput) (Conversation, error) {
	if !ValidMachineID(input.MachineID) || !ValidRequestToken(input.IdempotencyKey) {
		return Conversation{}, fmt.Errorf("machine and idempotency key are required")
	}
	return s.createConversation(input)
}

func (s *Store) createConversation(input CreateConversationInput) (Conversation, error) {
	creatorEndpoint := input.CreatorEndpoint
	members := input.Members
	now := input.Now
	if !ValidEndpoint(creatorEndpoint) || len(members) == 0 || len(members) > 256 {
		return Conversation{}, fmt.Errorf("creator and members are required")
	}
	seen := make(map[string]struct{}, len(members))
	creatorAdmin := false
	for _, member := range members {
		if !ValidEndpoint(member.Endpoint) || member.Capabilities == 0 || member.Capabilities & ^(CapSend|CapReceive|CapAdmin) != 0 {
			return Conversation{}, fmt.Errorf("invalid conversation member")
		}
		if _, duplicate := seen[member.Endpoint]; duplicate {
			return Conversation{}, fmt.Errorf("duplicate conversation member")
		}
		seen[member.Endpoint] = struct{}{}
		if member.Endpoint == creatorEndpoint && member.Capabilities&(CapSend|CapReceive|CapAdmin) == (CapSend|CapReceive|CapAdmin) {
			creatorAdmin = true
		}
	}
	if !creatorAdmin {
		return Conversation{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Conversation{}, err
	}
	defer rollback(tx)
	if input.MachineID != "" {
		if err := endpointOwnedBy(tx, creatorEndpoint, input.MachineID, now); err != nil {
			return Conversation{}, err
		}
	}
	if input.MachineID != "" {
		requestHash := createConversationHash(creatorEndpoint, members)
		var existingID, existingHash string
		err = tx.QueryRowContext(context.Background(), "SELECT conversation_id, request_hash FROM conversation_idempotency WHERE machine_id = ? AND key = ?", input.MachineID, input.IdempotencyKey).Scan(&existingID, &existingHash)
		if err == nil {
			if existingHash != requestHash {
				return Conversation{}, ErrConflict
			}
			conversation, err := conversationByID(tx, existingID)
			if err != nil {
				return Conversation{}, err
			}
			if err := tx.Commit(); err != nil {
				return Conversation{}, err
			}
			return conversation, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return Conversation{}, fmt.Errorf("read conversation idempotency key: %w", err)
		}
	}
	for endpoint := range seen {
		if err := endpointActive(tx, endpoint, now); err != nil {
			return Conversation{}, err
		}
	}
	conversation := Conversation{ID: uuid.NewString()}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO conversations(id, created_at) VALUES (?, ?)", conversation.ID, now.UnixMilli()); err != nil {
		return Conversation{}, fmt.Errorf("create conversation: %w", err)
	}
	for _, member := range members {
		if _, err := tx.ExecContext(context.Background(), "INSERT INTO memberships(conversation_id, endpoint, capabilities) VALUES (?, ?, ?)", conversation.ID, member.Endpoint, member.Capabilities); err != nil {
			return Conversation{}, fmt.Errorf("add conversation member: %w", err)
		}
	}
	if input.MachineID != "" {
		if _, err := tx.ExecContext(context.Background(), "INSERT INTO conversation_idempotency(machine_id, key, request_hash, conversation_id, created_at) VALUES (?, ?, ?, ?, ?)", input.MachineID, input.IdempotencyKey, createConversationHash(creatorEndpoint, members), conversation.ID, now.UnixMilli()); err != nil {
			return Conversation{}, fmt.Errorf("record conversation idempotency key: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Conversation{}, err
	}
	return conversation, nil
}

// AuthorizeSender proves the exact live endpoint may append to a conversation
// without creating a message or idempotency record. Callers use it only as an
// advisory preflight; AppendMessage repeats every check at mutation time.
func (s *Store) AuthorizeSender(conversationID, machineID, endpoint string, now time.Time) error {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(machineID) == "" || strings.TrimSpace(endpoint) == "" {
		return ErrForbidden
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, endpoint, machineID, now); err != nil {
		return err
	}
	var capabilities Capability
	err = tx.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id = ? AND endpoint = ?", conversationID, endpoint).Scan(&capabilities)
	if errors.Is(err, sql.ErrNoRows) || capabilities&CapSend == 0 {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("authorize message sender: %w", err)
	}
	return tx.Commit()
}

// AppendMessage accepts one immutable, authorized message and creates one
// independent durable delivery per receiving endpoint, excluding the sender.
func (s *Store) AppendMessage(input AppendInput) (Message, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !ValidMachineID(input.SenderMachineID) || !ValidEndpoint(input.FromEndpoint) || !ValidRequestToken(input.IdempotencyKey) {
		return Message{}, false, fmt.Errorf("conversation, machine, endpoint, and idempotency key are required")
	}
	if len(input.Body) > maxMessageBodyBytes {
		return Message{}, false, fmt.Errorf("message body exceeds %d bytes", maxMessageBodyBytes)
	}
	requestHash := appendHash(input)
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Message{}, false, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, input.FromEndpoint, input.SenderMachineID, input.Now); err != nil {
		return Message{}, false, err
	}
	var capabilities Capability
	err = tx.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id = ? AND endpoint = ?", input.ConversationID, input.FromEndpoint).Scan(&capabilities)
	if errors.Is(err, sql.ErrNoRows) || capabilities&CapSend == 0 {
		return Message{}, false, ErrForbidden
	}
	if err != nil {
		return Message{}, false, fmt.Errorf("authorize message sender: %w", err)
	}
	var existingID, existingHash string
	err = tx.QueryRowContext(context.Background(), "SELECT message_id, request_hash FROM idempotency WHERE machine_id = ? AND key = ?", input.SenderMachineID, input.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if existingHash != requestHash {
			return Message{}, false, ErrConflict
		}
		message, err := messageByID(tx, existingID)
		if err != nil {
			return Message{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Message{}, false, err
		}
		return message, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Message{}, false, fmt.Errorf("read idempotency key: %w", err)
	}
	message := Message{ID: uuid.NewString(), ConversationID: input.ConversationID, FromEndpoint: input.FromEndpoint, Body: input.Body, CreatedAt: input.Now.UTC()}
	if err := tx.QueryRowContext(context.Background(), "UPDATE conversations SET next_sequence = next_sequence + 1 WHERE id = ? RETURNING next_sequence", input.ConversationID).Scan(&message.Sequence); errors.Is(err, sql.ErrNoRows) {
		return Message{}, false, ErrForbidden
	} else if err != nil {
		return Message{}, false, fmt.Errorf("allocate message sequence: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO messages(id, conversation_id, sequence, from_endpoint, body, created_at) VALUES (?, ?, ?, ?, ?, ?)`, message.ID, message.ConversationID, message.Sequence, message.FromEndpoint, message.Body, message.CreatedAt.UnixMilli()); err != nil {
		return Message{}, false, fmt.Errorf("append message: %w", err)
	}
	rows, err := tx.QueryContext(context.Background(), "SELECT endpoint FROM memberships WHERE conversation_id = ? AND (capabilities & ?) != 0 AND endpoint != ?", input.ConversationID, CapReceive, input.FromEndpoint)
	if err != nil {
		return Message{}, false, fmt.Errorf("find recipients: %w", err)
	}
	var recipients []string
	for rows.Next() {
		var endpoint string
		if err := rows.Scan(&endpoint); err != nil {
			_ = rows.Close()
			return Message{}, false, err
		}
		recipients = append(recipients, endpoint)
	}
	if err := rows.Close(); err != nil {
		return Message{}, false, err
	}
	for _, endpoint := range recipients {
		if _, err := tx.ExecContext(context.Background(), "INSERT INTO deliveries(id, message_id, recipient_endpoint) VALUES (?, ?, ?)", uuid.NewString(), message.ID, endpoint); err != nil {
			return Message{}, false, fmt.Errorf("create delivery: %w", err)
		}
	}
	if capabilities&CapReceive != 0 {
		if err := advanceRecipientCursor(tx, input.FromEndpoint, input.ConversationID); err != nil {
			return Message{}, false, err
		}
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO idempotency(machine_id, key, request_hash, message_id, created_at) VALUES (?, ?, ?, ?, ?)", input.SenderMachineID, input.IdempotencyKey, requestHash, message.ID, input.Now.UnixMilli()); err != nil {
		return Message{}, false, fmt.Errorf("record idempotency key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Message{}, false, err
	}
	return message, false, nil
}

// LeaseDeliveries leases a bounded page of pending deliveries for one active
// endpoint. A retry by the same machine receives its current lease; an expired
// lease receives a new token and monotonically increasing fence generation.
func (s *Store) LeaseDeliveries(machineID, consumerID, endpoint, conversationID string, now time.Time, ttl time.Duration, limit int) ([]Delivery, error) {
	if !ValidMachineID(machineID) || !ValidRequestToken(consumerID) || !ValidEndpoint(endpoint) || ttl <= 0 || limit < 1 || limit > 100 {
		return nil, fmt.Errorf("invalid delivery lease request")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	ownershipGeneration, err := endpointOwnership(tx, endpoint, machineID, now)
	if err != nil {
		return nil, err
	}
	var activeConsumer sql.NullString
	var consumerGeneration int64
	var consumerUntil sql.NullInt64
	if err := tx.QueryRowContext(context.Background(), `SELECT consumer_id, consumer_generation, consumer_lease_until FROM endpoints WHERE endpoint = ?`, endpoint).Scan(&activeConsumer, &consumerGeneration, &consumerUntil); err != nil {
		return nil, fmt.Errorf("read endpoint consumer lease: %w", err)
	}
	if activeConsumer.Valid && activeConsumer.String != consumerID && consumerUntil.Valid && consumerUntil.Int64 > now.UnixMilli() {
		return nil, ErrConflict
	}
	if !activeConsumer.Valid || activeConsumer.String != consumerID || !consumerUntil.Valid || consumerUntil.Int64 <= now.UnixMilli() {
		consumerGeneration++
	}
	consumerLeaseUntil := now.Add(ttl).UTC()
	if _, err := tx.ExecContext(context.Background(), `UPDATE endpoints SET consumer_id = ?, consumer_generation = ?, consumer_lease_until = ? WHERE endpoint = ? AND ownership_generation = ?`, consumerID, consumerGeneration, consumerLeaseUntil.UnixMilli(), endpoint, ownershipGeneration); err != nil {
		return nil, fmt.Errorf("claim endpoint consumer lease: %w", err)
	}
	query := `SELECT d.id, d.lease_machine_id, d.lease_token, d.lease_generation, d.ownership_generation, d.consumer_generation, d.lease_until,
		m.id, m.conversation_id, m.sequence, m.from_endpoint, m.body, m.created_at
		FROM deliveries d JOIN messages m ON m.id = d.message_id
		WHERE d.recipient_endpoint = ? AND d.acked_at IS NULL
		AND (d.lease_until IS NULL OR d.lease_until <= ? OR d.ownership_generation IS NULL OR d.ownership_generation <> ? OR d.consumer_generation IS NULL OR d.consumer_generation <> ? OR d.lease_machine_id = ?)`
	args := []any{endpoint, now.UnixMilli(), ownershipGeneration, consumerGeneration, machineID}
	if conversationID != "" {
		query += " AND m.conversation_id = ?"
		args = append(args, conversationID)
	}
	query += " ORDER BY m.sequence ASC LIMIT ?"
	args = append(args, limit)
	rows, err := tx.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil, fmt.Errorf("find deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var deliveries []Delivery
	for rows.Next() {
		var delivery Delivery
		var leaseMachine, leaseToken sql.NullString
		var leaseUntil, leaseOwnership, leaseConsumer sql.NullInt64
		var createdAt int64
		delivery.RecipientEndpoint = endpoint
		if err := rows.Scan(&delivery.ID, &leaseMachine, &leaseToken, &delivery.LeaseGeneration, &leaseOwnership, &leaseConsumer, &leaseUntil, &delivery.Message.ID, &delivery.Message.ConversationID, &delivery.Message.Sequence, &delivery.Message.FromEndpoint, &delivery.Message.Body, &createdAt); err != nil {
			return nil, err
		}
		delivery.Message.CreatedAt = fromMillis(createdAt)
		if leaseMachine.Valid && leaseMachine.String == machineID && leaseToken.Valid && leaseOwnership.Valid && leaseOwnership.Int64 == ownershipGeneration && leaseConsumer.Valid && leaseConsumer.Int64 == consumerGeneration && leaseUntil.Valid && leaseUntil.Int64 > now.UnixMilli() {
			delivery.LeaseToken = leaseToken.String
			delivery.LeaseUntil = fromMillis(leaseUntil.Int64)
		} else {
			token, err := randomToken()
			if err != nil {
				return nil, err
			}
			delivery.LeaseGeneration++
			delivery.LeaseToken = token
			delivery.LeaseUntil = now.Add(ttl).UTC()
			if _, err := tx.ExecContext(context.Background(), `UPDATE deliveries SET lease_machine_id = ?, lease_token = ?, lease_generation = ?, ownership_generation = ?, consumer_generation = ?, lease_until = ? WHERE id = ?`, machineID, token, delivery.LeaseGeneration, ownershipGeneration, consumerGeneration, delivery.LeaseUntil.UnixMilli(), delivery.ID); err != nil {
				return nil, fmt.Errorf("lease delivery: %w", err)
			}
		}
		deliveries = append(deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return deliveries, nil
}

// AckDelivery acknowledges a local mailbox handoff. It is idempotent after a
// successful acknowledgement, but pending deliveries require the exact live
// lease token and generation.
func (s *Store) AckDelivery(machineID, endpoint, deliveryID, token string, generation int64, now time.Time) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	ownershipGeneration, err := endpointOwnership(tx, endpoint, machineID, now)
	if err != nil {
		return err
	}
	var recipient, leaseMachine, leaseToken sql.NullString
	var leaseGeneration int64
	var leaseOwnership, leaseConsumer sql.NullInt64
	var leaseUntil, acknowledged sql.NullInt64
	err = tx.QueryRowContext(context.Background(), "SELECT recipient_endpoint, lease_machine_id, lease_token, lease_generation, ownership_generation, consumer_generation, lease_until, acked_at FROM deliveries WHERE id = ?", deliveryID).Scan(&recipient, &leaseMachine, &leaseToken, &leaseGeneration, &leaseOwnership, &leaseConsumer, &leaseUntil, &acknowledged)
	if errors.Is(err, sql.ErrNoRows) || !recipient.Valid || recipient.String != endpoint {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("read delivery acknowledgement state: %w", err)
	}
	if acknowledged.Valid && leaseToken.Valid && token == leaseToken.String && leaseGeneration == generation {
		return tx.Commit()
	}
	var currentConsumerGeneration int64
	if err := tx.QueryRowContext(context.Background(), `SELECT consumer_generation FROM endpoints WHERE endpoint = ?`, endpoint).Scan(&currentConsumerGeneration); err != nil {
		return ErrForbidden
	}
	if !leaseMachine.Valid || leaseMachine.String != machineID || !leaseToken.Valid || token != leaseToken.String || leaseGeneration != generation || !leaseOwnership.Valid || leaseOwnership.Int64 != ownershipGeneration || !leaseConsumer.Valid || leaseConsumer.Int64 != currentConsumerGeneration || !leaseUntil.Valid || leaseUntil.Int64 <= now.UnixMilli() {
		return ErrForbidden
	}
	if _, err := tx.ExecContext(context.Background(), "UPDATE deliveries SET acked_at = ? WHERE id = ? AND acked_at IS NULL", now.UnixMilli(), deliveryID); err != nil {
		return fmt.Errorf("acknowledge delivery: %w", err)
	}
	var conversationID string
	if err := tx.QueryRowContext(context.Background(), `SELECT message.conversation_id
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.id = ?`, deliveryID).Scan(&conversationID); err != nil {
		return fmt.Errorf("read delivery conversation: %w", err)
	}
	if err := advanceRecipientCursor(tx, endpoint, conversationID); err != nil {
		return err
	}
	return tx.Commit()
}

// RecipientCursor returns the highest conversation sequence for which this
// recipient has no earlier unacknowledged delivery. Sequences not addressed to
// the recipient do not create gaps.
func (s *Store) RecipientCursor(machineID, endpoint, conversationID string, now time.Time) (int64, error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, endpoint, machineID, now); err != nil {
		return 0, err
	}
	var capabilities Capability
	err = tx.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id = ? AND endpoint = ?", conversationID, endpoint).Scan(&capabilities)
	if errors.Is(err, sql.ErrNoRows) || capabilities&CapReceive == 0 {
		return 0, ErrForbidden
	}
	if err != nil {
		return 0, fmt.Errorf("authorize recipient cursor: %w", err)
	}
	var cursor int64
	err = tx.QueryRowContext(context.Background(), "SELECT sequence FROM recipient_cursors WHERE recipient_endpoint = ? AND conversation_id = ?", endpoint, conversationID).Scan(&cursor)
	if errors.Is(err, sql.ErrNoRows) {
		cursor = 0
	} else if err != nil {
		return 0, fmt.Errorf("read recipient cursor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return cursor, nil
}

func advanceRecipientCursor(tx *sql.Tx, endpoint, conversationID string) error {
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO recipient_cursors(recipient_endpoint, conversation_id, sequence)
		VALUES (?, ?, 0) ON CONFLICT(recipient_endpoint, conversation_id) DO NOTHING`, endpoint, conversationID); err != nil {
		return fmt.Errorf("initialize recipient cursor: %w", err)
	}
	var cursor int64
	if err := tx.QueryRowContext(context.Background(), "SELECT sequence FROM recipient_cursors WHERE recipient_endpoint = ? AND conversation_id = ?", endpoint, conversationID).Scan(&cursor); err != nil {
		return fmt.Errorf("read recipient cursor: %w", err)
	}
	var nextPending sql.NullInt64
	if err := tx.QueryRowContext(context.Background(), `SELECT MIN(message.sequence)
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.recipient_endpoint = ? AND message.conversation_id = ?
		  AND delivery.acked_at IS NULL AND message.sequence > ?`, endpoint, conversationID, cursor).Scan(&nextPending); err != nil {
		return fmt.Errorf("find recipient cursor gap: %w", err)
	}
	var target int64
	if nextPending.Valid {
		target = nextPending.Int64 - 1
	} else {
		var maximum int64
		if err := tx.QueryRowContext(context.Background(), `SELECT next_sequence FROM conversations WHERE id = ?`, conversationID).Scan(&maximum); err != nil {
			return fmt.Errorf("find recipient cursor maximum: %w", err)
		}
		target = maximum
	}
	if target > cursor {
		if _, err := tx.ExecContext(context.Background(), `UPDATE recipient_cursors SET sequence = ?
			WHERE recipient_endpoint = ? AND conversation_id = ? AND sequence = ?`, target, endpoint, conversationID, cursor); err != nil {
			return fmt.Errorf("advance recipient cursor: %w", err)
		}
	}
	return nil
}

// RecipientMachines returns active machine owners for a message's recipient
// deliveries. It is used only for best-effort wake hints; durable recipients
// are still represented by delivery rows even while detached.
func (s *Store) RecipientMachines(messageID string, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT DISTINCT e.machine_id FROM deliveries d
		JOIN endpoints e ON e.endpoint = d.recipient_endpoint
		WHERE d.message_id = ? AND e.lease_until > ?`, messageID, now.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("find message recipient machines: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var machines []string
	for rows.Next() {
		var machineID string
		if err := rows.Scan(&machineID); err != nil {
			return nil, err
		}
		machines = append(machines, machineID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return machines, nil
}

// ConversationsForMachine exposes only rooms containing an endpoint currently
// attached to the authenticated machine. It deliberately returns opaque IDs;
// membership and message access remain separately enforced.
func (s *Store) ConversationsForMachine(machineID string, now time.Time) ([]Conversation, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT DISTINCT c.id FROM conversations c
		JOIN memberships m ON m.conversation_id = c.id
		JOIN endpoints e ON e.endpoint = m.endpoint
		WHERE e.machine_id = ? AND e.lease_until > ? ORDER BY c.created_at ASC`, machineID, now.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("list machine conversations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var conversations []Conversation
	for rows.Next() {
		var conversation Conversation
		if err := rows.Scan(&conversation.ID); err != nil {
			return nil, err
		}
		conversations = append(conversations, conversation)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return conversations, nil
}

func endpointActive(tx *sql.Tx, endpoint string, now time.Time) error {
	var until int64
	err := tx.QueryRowContext(context.Background(), "SELECT lease_until FROM endpoints WHERE endpoint = ?", endpoint).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) || until <= now.UnixMilli() {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("read endpoint lease: %w", err)
	}
	return nil
}

func endpointOwnedBy(tx *sql.Tx, endpoint, machineID string, now time.Time) error {
	_, err := endpointOwnership(tx, endpoint, machineID, now)
	return err
}

func endpointOwnership(tx *sql.Tx, endpoint, machineID string, now time.Time) (int64, error) {
	var owner string
	var until int64
	var generation int64
	err := tx.QueryRowContext(context.Background(), "SELECT machine_id, lease_until, ownership_generation FROM endpoints WHERE endpoint = ?", endpoint).Scan(&owner, &until, &generation)
	if errors.Is(err, sql.ErrNoRows) || owner != machineID || until <= now.UnixMilli() {
		return 0, ErrForbidden
	}
	if err != nil {
		return 0, fmt.Errorf("read endpoint ownership: %w", err)
	}
	return generation, nil
}

func messageByID(tx *sql.Tx, messageID string) (Message, error) {
	var message Message
	var createdAt int64
	err := tx.QueryRowContext(context.Background(), "SELECT id, conversation_id, sequence, from_endpoint, body, created_at FROM messages WHERE id = ?", messageID).Scan(&message.ID, &message.ConversationID, &message.Sequence, &message.FromEndpoint, &message.Body, &createdAt)
	if err != nil {
		return Message{}, fmt.Errorf("read idempotent message: %w", err)
	}
	message.CreatedAt = fromMillis(createdAt)
	return message, nil
}

func conversationByID(tx *sql.Tx, conversationID string) (Conversation, error) {
	var conversation Conversation
	if err := tx.QueryRowContext(context.Background(), "SELECT id FROM conversations WHERE id = ?", conversationID).Scan(&conversation.ID); err != nil {
		return Conversation{}, fmt.Errorf("read idempotent conversation: %w", err)
	}
	return conversation, nil
}

func createConversationHash(creatorEndpoint string, members []Member) string {
	normalized := append([]Member(nil), members...)
	sort.Slice(normalized, func(left, right int) bool {
		if normalized[left].Endpoint == normalized[right].Endpoint {
			return normalized[left].Capabilities < normalized[right].Capabilities
		}
		return normalized[left].Endpoint < normalized[right].Endpoint
	})
	parts := make([]string, 1, 1+len(normalized)*2)
	parts[0] = creatorEndpoint
	for _, member := range normalized {
		parts = append(parts, member.Endpoint, fmt.Sprintf("%d", member.Capabilities))
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(digest[:])
}

func appendHash(input AppendInput) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{input.ConversationID, input.FromEndpoint, input.Body}, "\x00")))
	return hex.EncodeToString(digest[:])
}

func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate lease token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

func fromMillis(value int64) time.Time { return time.UnixMilli(value).UTC() }

func rollback(tx *sql.Tx) { _ = tx.Rollback() }
