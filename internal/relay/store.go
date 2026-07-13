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
	"strings"
	"time"

	"github.com/google/uuid"
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
)

// Capability controls an endpoint's membership in a conversation.
type Capability uint8

const (
	CapSend Capability = 1 << iota
	CapReceive
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
	store := &Store{db: db}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the durable state database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		`CREATE TABLE IF NOT EXISTS endpoints (
			endpoint TEXT PRIMARY KEY,
			machine_id TEXT NOT NULL,
			lease_until INTEGER NOT NULL
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
			lease_until INTEGER,
			acked_at INTEGER,
			UNIQUE (message_id, recipient_endpoint)
		)`,
		`CREATE TABLE IF NOT EXISTS idempotency (
			machine_id TEXT NOT NULL,
			key TEXT NOT NULL,
			request_hash TEXT NOT NULL,
			message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
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
	return nil
}

// AdvertiseEndpoints atomically replaces a machine's locally attached
// endpoints. Detached endpoints cannot fetch or acknowledge deliveries until
// their owning machine advertises them again.
func (s *Store) AdvertiseEndpoints(machineID string, endpoints []string, now time.Time, ttl time.Duration) error {
	if strings.TrimSpace(machineID) == "" || ttl <= 0 {
		return fmt.Errorf("invalid endpoint lease")
	}
	seen := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if strings.TrimSpace(endpoint) == "" {
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
	if _, err := tx.Exec("DELETE FROM endpoints WHERE machine_id = ?", machineID); err != nil {
		return fmt.Errorf("detach endpoints: %w", err)
	}
	until := now.Add(ttl).UnixMilli()
	for endpoint := range seen {
		if _, err := tx.Exec(`INSERT INTO endpoints(endpoint, machine_id, lease_until) VALUES (?, ?, ?)
			ON CONFLICT(endpoint) DO UPDATE SET machine_id = excluded.machine_id, lease_until = excluded.lease_until`, endpoint, machineID, until); err != nil {
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
	if strings.TrimSpace(creatorEndpoint) == "" || len(members) == 0 {
		return Conversation{}, fmt.Errorf("creator and members are required")
	}
	seen := make(map[string]struct{}, len(members))
	creatorAdmin := false
	for _, member := range members {
		if strings.TrimSpace(member.Endpoint) == "" || member.Capabilities == 0 || member.Capabilities & ^(CapSend|CapReceive|CapAdmin) != 0 {
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
	for endpoint := range seen {
		if err := endpointActive(tx, endpoint, now); err != nil {
			return Conversation{}, err
		}
	}
	conversation := Conversation{ID: uuid.NewString()}
	if _, err := tx.Exec("INSERT INTO conversations(id, created_at) VALUES (?, ?)", conversation.ID, now.UnixMilli()); err != nil {
		return Conversation{}, fmt.Errorf("create conversation: %w", err)
	}
	for _, member := range members {
		if _, err := tx.Exec("INSERT INTO memberships(conversation_id, endpoint, capabilities) VALUES (?, ?, ?)", conversation.ID, member.Endpoint, member.Capabilities); err != nil {
			return Conversation{}, fmt.Errorf("add conversation member: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Conversation{}, err
	}
	return conversation, nil
}

// AppendMessage accepts one immutable, authorized message and creates one
// independent durable delivery per receiving endpoint, excluding the sender.
func (s *Store) AppendMessage(input AppendInput) (Message, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || strings.TrimSpace(input.SenderMachineID) == "" || strings.TrimSpace(input.FromEndpoint) == "" || strings.TrimSpace(input.IdempotencyKey) == "" {
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
	var existingID, existingHash string
	err = tx.QueryRow("SELECT message_id, request_hash FROM idempotency WHERE machine_id = ? AND key = ?", input.SenderMachineID, input.IdempotencyKey).Scan(&existingID, &existingHash)
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
	if err := endpointOwnedBy(tx, input.FromEndpoint, input.SenderMachineID, input.Now); err != nil {
		return Message{}, false, err
	}
	var capabilities Capability
	err = tx.QueryRow("SELECT capabilities FROM memberships WHERE conversation_id = ? AND endpoint = ?", input.ConversationID, input.FromEndpoint).Scan(&capabilities)
	if errors.Is(err, sql.ErrNoRows) || capabilities&CapSend == 0 {
		return Message{}, false, ErrForbidden
	}
	if err != nil {
		return Message{}, false, fmt.Errorf("authorize message sender: %w", err)
	}
	message := Message{ID: uuid.NewString(), ConversationID: input.ConversationID, FromEndpoint: input.FromEndpoint, Body: input.Body, CreatedAt: input.Now.UTC()}
	if err := tx.QueryRow("UPDATE conversations SET next_sequence = next_sequence + 1 WHERE id = ? RETURNING next_sequence", input.ConversationID).Scan(&message.Sequence); errors.Is(err, sql.ErrNoRows) {
		return Message{}, false, ErrForbidden
	} else if err != nil {
		return Message{}, false, fmt.Errorf("allocate message sequence: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO messages(id, conversation_id, sequence, from_endpoint, body, created_at) VALUES (?, ?, ?, ?, ?, ?)`, message.ID, message.ConversationID, message.Sequence, message.FromEndpoint, message.Body, message.CreatedAt.UnixMilli()); err != nil {
		return Message{}, false, fmt.Errorf("append message: %w", err)
	}
	rows, err := tx.Query("SELECT endpoint FROM memberships WHERE conversation_id = ? AND (capabilities & ?) != 0 AND endpoint != ?", input.ConversationID, CapReceive, input.FromEndpoint)
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
		if _, err := tx.Exec("INSERT INTO deliveries(id, message_id, recipient_endpoint) VALUES (?, ?, ?)", uuid.NewString(), message.ID, endpoint); err != nil {
			return Message{}, false, fmt.Errorf("create delivery: %w", err)
		}
	}
	if _, err := tx.Exec("INSERT INTO idempotency(machine_id, key, request_hash, message_id, created_at) VALUES (?, ?, ?, ?, ?)", input.SenderMachineID, input.IdempotencyKey, requestHash, message.ID, input.Now.UnixMilli()); err != nil {
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
func (s *Store) LeaseDeliveries(machineID, endpoint, conversationID string, now time.Time, ttl time.Duration, limit int) ([]Delivery, error) {
	if ttl <= 0 || limit < 1 || limit > 100 {
		return nil, fmt.Errorf("invalid delivery lease request")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, endpoint, machineID, now); err != nil {
		return nil, err
	}
	query := `SELECT d.id, d.lease_machine_id, d.lease_token, d.lease_generation, d.lease_until,
		m.id, m.conversation_id, m.sequence, m.from_endpoint, m.body, m.created_at
		FROM deliveries d JOIN messages m ON m.id = d.message_id
		WHERE d.recipient_endpoint = ? AND d.acked_at IS NULL
		AND (d.lease_until IS NULL OR d.lease_until <= ? OR d.lease_machine_id = ?)`
	args := []any{endpoint, now.UnixMilli(), machineID}
	if conversationID != "" {
		query += " AND m.conversation_id = ?"
		args = append(args, conversationID)
	}
	query += " ORDER BY m.sequence ASC LIMIT ?"
	args = append(args, limit)
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("find deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var deliveries []Delivery
	for rows.Next() {
		var delivery Delivery
		var leaseMachine, leaseToken sql.NullString
		var leaseUntil sql.NullInt64
		var createdAt int64
		delivery.RecipientEndpoint = endpoint
		if err := rows.Scan(&delivery.ID, &leaseMachine, &leaseToken, &delivery.LeaseGeneration, &leaseUntil, &delivery.Message.ID, &delivery.Message.ConversationID, &delivery.Message.Sequence, &delivery.Message.FromEndpoint, &delivery.Message.Body, &createdAt); err != nil {
			return nil, err
		}
		delivery.Message.CreatedAt = fromMillis(createdAt)
		if leaseMachine.Valid && leaseMachine.String == machineID && leaseToken.Valid && leaseUntil.Valid && leaseUntil.Int64 > now.UnixMilli() {
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
			if _, err := tx.Exec(`UPDATE deliveries SET lease_machine_id = ?, lease_token = ?, lease_generation = ?, lease_until = ? WHERE id = ?`, machineID, token, delivery.LeaseGeneration, delivery.LeaseUntil.UnixMilli(), delivery.ID); err != nil {
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
	if err := endpointOwnedBy(tx, endpoint, machineID, now); err != nil {
		return err
	}
	var recipient, leaseMachine, leaseToken sql.NullString
	var leaseGeneration int64
	var leaseUntil, acknowledged sql.NullInt64
	err = tx.QueryRow("SELECT recipient_endpoint, lease_machine_id, lease_token, lease_generation, lease_until, acked_at FROM deliveries WHERE id = ?", deliveryID).Scan(&recipient, &leaseMachine, &leaseToken, &leaseGeneration, &leaseUntil, &acknowledged)
	if errors.Is(err, sql.ErrNoRows) || !recipient.Valid || recipient.String != endpoint {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("read delivery acknowledgement state: %w", err)
	}
	if acknowledged.Valid {
		return tx.Commit()
	}
	if !leaseMachine.Valid || leaseMachine.String != machineID || !leaseToken.Valid || token != leaseToken.String || leaseGeneration != generation || !leaseUntil.Valid || leaseUntil.Int64 <= now.UnixMilli() {
		return ErrForbidden
	}
	if _, err := tx.Exec("UPDATE deliveries SET acked_at = ? WHERE id = ? AND acked_at IS NULL", now.UnixMilli(), deliveryID); err != nil {
		return fmt.Errorf("acknowledge delivery: %w", err)
	}
	return tx.Commit()
}

func endpointActive(tx *sql.Tx, endpoint string, now time.Time) error {
	var until int64
	err := tx.QueryRow("SELECT lease_until FROM endpoints WHERE endpoint = ?", endpoint).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) || until <= now.UnixMilli() {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("read endpoint lease: %w", err)
	}
	return nil
}

func endpointOwnedBy(tx *sql.Tx, endpoint, machineID string, now time.Time) error {
	var owner string
	var until int64
	err := tx.QueryRow("SELECT machine_id, lease_until FROM endpoints WHERE endpoint = ?", endpoint).Scan(&owner, &until)
	if errors.Is(err, sql.ErrNoRows) || owner != machineID || until <= now.UnixMilli() {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("read endpoint ownership: %w", err)
	}
	return nil
}

func messageByID(tx *sql.Tx, messageID string) (Message, error) {
	var message Message
	var createdAt int64
	err := tx.QueryRow("SELECT id, conversation_id, sequence, from_endpoint, body, created_at FROM messages WHERE id = ?", messageID).Scan(&message.ID, &message.ConversationID, &message.Sequence, &message.FromEndpoint, &message.Body, &createdAt)
	if err != nil {
		return Message{}, fmt.Errorf("read idempotent message: %w", err)
	}
	message.CreatedAt = fromMillis(createdAt)
	return message, nil
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
