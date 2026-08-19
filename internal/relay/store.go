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
	"sync"
	"time"

	"github.com/google/uuid"
	// sqlite is the durable embedded relay store driver.
	_ "modernc.org/sqlite"
)

const maxMessageBodyBytes = 32 << 10

// MaxActiveRolesPerSession bounds role-derived lease identities below SQLite's
// parameter limit while keeping one session's work bounded.
const MaxActiveRolesPerSession = 128

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
	// ErrMigrationSourcePrepared means the SQLite relay is fenced for a
	// resumable PostgreSQL cutover epoch and cannot accept writes.
	ErrMigrationSourcePrepared = errors.New("relay migration source is prepared")
	// ErrMigrationSourceRetired means PostgreSQL cutover crossed the permanent
	// source-retirement boundary. The SQLite file is forensic evidence only.
	ErrMigrationSourceRetired = errors.New("relay migration source is retired")
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
	// CapInvoke permits a content-free, server-authorized start handoff for an
	// offline receiving member. Existing send/admin grants never imply it.
	CapInvoke
)

// Member is an explicitly authorized conversation endpoint.
type Member struct {
	Endpoint      string     `json:"endpoint"`
	Role          string     `json:"role,omitempty"`
	RoleMachineID string     `json:"role_machine_id,omitempty"`
	Capabilities  Capability `json:"capabilities"`
}

// ControlOperation names an explicit, server-authorized membership mutation.
// It is intentionally not representable as message content.
type ControlOperation string

const (
	// ControlUpsertMember adds a member or replaces its capability set.
	ControlUpsertMember ControlOperation = "upsert_member"
	// ControlRemoveMember removes one member while preserving another admin.
	ControlRemoveMember ControlOperation = "remove_member"
)

// ControlInput is one signed-machine retry domain for a membership mutation.
// ActorEndpoint is only an asserted local endpoint; ownership and admin
// capability are rechecked durably by the relay before every mutation.
type ControlInput struct {
	ConversationID string
	ActorMachineID string
	ActorEndpoint  string
	Operation      ControlOperation
	Member         Member
	IdempotencyKey string
	Now            time.Time
}

// ControlEvent is an immutable, content-free audit record for a control-plane
// transition. It deliberately has no message body or credential material.
type ControlEvent struct {
	ID             string           `json:"id"`
	ConversationID string           `json:"conversation_id"`
	ActorEndpoint  string           `json:"actor_endpoint"`
	Operation      ControlOperation `json:"operation"`
	Member         Member           `json:"member"`
	CreatedAt      time.Time        `json:"created_at"`
}

// Conversation is an immutable identifier returned when a room is created.
type Conversation struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
}

// Message is immutable accepted message data. Bodies must be treated as
// untrusted opaque text by every adapter and gateway.
type Message struct {
	ID                       string    `json:"id"`
	ConversationID           string    `json:"conversation_id"`
	Sequence                 int64     `json:"sequence"`
	FromEndpoint             string    `json:"from_endpoint,omitempty"`
	FromRole                 string    `json:"from_role,omitempty"`
	FromParticipant          string    `json:"from_participant,omitempty"`
	InReplyToPunaroMessageID string    `json:"in_reply_to_punaro_message_id,omitempty"`
	InReplyToEndpoint        string    `json:"in_reply_to_endpoint,omitempty"`
	TelegramThreadID         int64     `json:"telegram_thread_id,omitempty"`
	Body                     string    `json:"body"`
	CreatedAt                time.Time `json:"created_at"`
}

// Delivery is a recipient-specific lease for one immutable message.
type Delivery struct {
	ID                string    `json:"id"`
	RecipientEndpoint string    `json:"recipient_endpoint"`
	RecipientRole     string    `json:"recipient_role,omitempty"`
	Message           Message   `json:"message"`
	LeaseToken        string    `json:"lease_token"`
	LeaseGeneration   int64     `json:"lease_generation"`
	LeaseUntil        time.Time `json:"lease_until"`
}

// DeliveryLeasePage atomically binds leased delivery fences to the durable
// cursors returned in the same HTTP response.
type DeliveryLeasePage struct {
	Deliveries []Delivery       `json:"deliveries"`
	Cursors    map[string]int64 `json:"cursors"`
}

// AppendInput contains one client retry domain. IdempotencyKey is scoped to
// SenderMachineID and may only be reused with identical message data.
type AppendInput struct {
	ConversationID           string
	SenderMachineID          string
	PrincipalID              string
	CredentialLookupID       string
	CredentialGeneration     int64
	FromEndpoint             string
	TargetRole               string
	FromParticipant          string
	InReplyToPunaroMessageID string
	InReplyToEndpoint        string
	TelegramThreadID         int64
	Body                     string
	ArtifactIDs              []string
	IdempotencyKey           string
	Now                      time.Time
}

// CreateConversationInput identifies one create retry domain. IdempotencyKey
// is scoped to MachineID and is bound to the creator, normalized members, and
// display name.
type CreateConversationInput struct {
	MachineID            string
	PrincipalID          string
	CredentialLookupID   string
	CredentialGeneration int64
	ProjectID            string
	IdempotencyKey       string
	CreatorEndpoint      string
	DisplayName          string
	Members              []Member
	Now                  time.Time
}

// RegisterRoleInput is one signed-machine retry domain for opt-in role identity.
// The authenticated machine is the owner; callers never supply a machine field.
type RegisterRoleInput struct {
	MachineID         string
	Role              string
	DisplayName       string
	DirectAddressable bool
	IdempotencyKey    string
	Now               time.Time
}

// RoleProfile is the public addressable identity of one durable role.
// It never includes bindings, endpoints, credentials, or memberships.
type RoleProfile struct {
	Role              string    `json:"role"`
	DisplayName       string    `json:"display_name,omitempty"`
	DirectAddressable bool      `json:"direct_addressable"`
	UpdatedAt         time.Time `json:"updated_at"`
}

const (
	// DefaultRoleListLimit is the page size when a list request omits limit.
	DefaultRoleListLimit = 50
	// MaxRoleListLimit is the inclusive upper bound for one directory page.
	MaxRoleListLimit = 100
	// MaxRoleResolveMatches is the inclusive cap for ambiguous slug matches.
	MaxRoleResolveMatches = 20
	// RoleResolveResolved is a unique visible directory match.
	RoleResolveResolved = "resolved"
	// RoleResolveNotFound is the uniform missing/hidden/legacy answer.
	RoleResolveNotFound = "not_found"
	// RoleResolveAmbiguous means more than one visible role shares the slug.
	RoleResolveAmbiguous = "ambiguous"
)

// RoleContact is one opted-in public role. It never includes sessions or membership.
type RoleContact struct {
	Role        string `json:"role"`
	DisplayName string `json:"display_name,omitempty"`
	MachineID   string `json:"machine_id,omitempty"`
	Online      bool   `json:"online"`
}

// RoleResolveMatch is one qualified candidate from an ambiguous short name.
// It never includes machine ID, online state, or session inventory.
type RoleResolveMatch struct {
	Role        string `json:"role"`
	DisplayName string `json:"display_name,omitempty"`
}

// RoleListInput is one authenticated, bounded directory page request.
type RoleListInput struct {
	Cursor string
	Limit  int
	Now    time.Time
}

// RoleListPage is one cursor-stable page of opted-in roles.
type RoleListPage struct {
	Roles      []RoleContact `json:"roles"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

// RoleResolveInput looks up one public name. Display names are never keys.
type RoleResolveInput struct {
	Name string
	Now  time.Time
}

// DirectMessageInput is one signed-machine retry domain for a direct role send.
// The conversation ID is assigned server-side for the unordered role pair.
type DirectMessageInput struct {
	SenderMachineID string
	FromRole        string
	ToRole          string
	Body            string
	IdempotencyKey  string
	Now             time.Time
}

// RoleResolveResult is a deterministic directory answer. Ambiguous matches
// contain only canonical roles and display names.
type RoleResolveResult struct {
	Status      string             `json:"status"`
	Role        string             `json:"role,omitempty"`
	DisplayName string             `json:"display_name,omitempty"`
	MachineID   string             `json:"machine_id,omitempty"`
	Online      bool               `json:"online"`
	Matches     []RoleResolveMatch `json:"matches,omitempty"`
}

// SetDisplayNameInput is one signed-machine retry domain for renaming a room.
// ActorEndpoint is only an asserted local endpoint; ownership and admin
// capability are rechecked durably before every mutation.
type SetDisplayNameInput struct {
	ConversationID string
	ActorMachineID string
	ActorEndpoint  string
	DisplayName    string
	IdempotencyKey string
	Now            time.Time
}

// TelegramClaimInput reserves one conversation for gateway claim execution.
type TelegramClaimInput struct {
	ConversationID string
	MachineID      string
	Endpoint       string
	IdempotencyKey string
	Now            time.Time
}

// TelegramClaimCompleteInput is authorized only by a live telegram/primary
// advertisement. The complete body is empty; identity is not request JSON.
type TelegramClaimCompleteInput struct {
	ConversationID string
	MachineID      string
	Now            time.Time
}

// TelegramClaim is the durable reservation or completed claim for one room.
type TelegramClaim struct {
	ConversationID string     `json:"conversation_id"`
	Status         string     `json:"status"`
	DisplayName    string     `json:"display_name"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

// UnclaimedTopic is one named room without a completed claim.
type UnclaimedTopic struct {
	ID            string     `json:"id"`
	DisplayName   string     `json:"display_name"`
	LastMessageAt *time.Time `json:"last_message_at,omitempty"`
}

// SessionTopic is the caller's sole named or claimed occupancy.
type SessionTopic struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
	Claimed     bool   `json:"claimed"`
}

// TelegramInboundInput is gateway-only inbound mail plus inert reply metadata.
type TelegramInboundInput struct {
	ConversationID     string
	SenderMachineID    string
	FromEndpoint       string
	FromParticipant    string
	Body               string
	InReplyToMessageID string
	InReplyToEndpoint  string
	TelegramThreadID   int64
	IdempotencyKey     string
	Now                time.Time
}

// AdoptPrepareInput is the host-local one-shot that drops TelegramCodexRole
// from a still-unnamed non-keeper and then names that room. It never talks to
// HTTP or Telegram and never grants telegram/primary CapAdmin.
type AdoptPrepareInput struct {
	KeeperID      string
	NonKeeperID   string
	NonKeeperName string
	Now           time.Time
}

// InvocationStatus is the durable state of a server-authorized runtime
// handoff. A runtime receives no message body: it attaches the endpoint and
// then obtains pending delivery through the normal path.
type InvocationStatus string

const (
	// InvocationPending is queued or eligible for a retry lease.
	InvocationPending InvocationStatus = "pending"
	// InvocationAlreadyRunning records the idempotent no-op for an attached target.
	InvocationAlreadyRunning InvocationStatus = "already_running"
	// InvocationSucceeded records a host-local runtime acceptance.
	InvocationSucceeded InvocationStatus = "succeeded"
	// InvocationFailed records a terminal failure after bounded retry exhaustion.
	InvocationFailed InvocationStatus = "failed"
)

// InvokeInput binds one caller retry domain to a receiving conversation member.
// The target machine is derived from durable server state, never request JSON.
type InvokeInput struct {
	ConversationID  string
	SenderMachineID string
	FromEndpoint    string
	TargetEndpoint  string
	IdempotencyKey  string
	Now             time.Time
}

// Invocation is content-free runtime work. Fence remains stable for every
// retry so a host-local runtime can reject duplicate process starts.
type Invocation struct {
	ID              string           `json:"id"`
	ConversationID  string           `json:"conversation_id"`
	TargetEndpoint  string           `json:"target_endpoint"`
	TargetMachineID string           `json:"target_machine_id"`
	Fence           string           `json:"fence"`
	Status          InvocationStatus `json:"status"`
	LeaseToken      string           `json:"lease_token,omitempty"`
	LeaseGeneration int64            `json:"lease_generation,omitempty"`
	LeaseUntil      time.Time        `json:"lease_until,omitempty"`
	RecoveryOnly    bool             `json:"recovery_only,omitempty"`
}

// InvocationAuditEvent is body-free durable evidence of authorization,
// leasing, retry, and terminal handoff outcomes.
type InvocationAuditEvent struct {
	Action    string    `json:"action"`
	CreatedAt time.Time `json:"created_at"`
}

// Store owns SQLite-backed relay state.
type Store struct {
	db               *sql.DB
	rateMu           sync.Mutex
	rateLimits       RateLimitConfig
	quotaMu          sync.Mutex
	quota            QuotaConfig
	retentionMu      sync.Mutex
	retention        RetentionConfig
	pendingMetricsMu sync.Mutex
	metrics          *Metrics
}

// Open creates or opens a SQLite WAL database with the full durable delivery
// schema. The database directory is private to the service account.
func Open(database string) (*Store, error) {
	return openStore(database, true)
}

// OpenForCapacityRepair opens a SQLite relay without the fail-closed quota
// consistency check so a confirmed operator reconcile can rebuild counters.
func OpenForCapacityRepair(database string) (*Store, error) {
	return openStore(database, false)
}

func openStore(database string, verifyQuota bool) (*Store, error) {
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
	store := &Store{db: db, rateLimits: DefaultRateLimitConfig(), quota: DefaultQuotaConfig(), retention: DefaultRetentionConfig()}
	var migrationControlExists bool
	if err := db.QueryRowContext(context.Background(), `SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type='table' AND name='relay_migration_control')`).Scan(&migrationControlExists); err != nil {
		_ = db.Close()
		return nil, errors.New("relay migration source state is unavailable")
	}
	if migrationControlExists {
		var migrationPhase MigrationSourcePhase
		if err := db.QueryRowContext(context.Background(), `SELECT phase FROM relay_migration_control WHERE singleton=1`).Scan(&migrationPhase); err != nil {
			_ = db.Close()
			return nil, errors.New("relay migration source state is unavailable")
		}
		switch migrationPhase {
		case MigrationSourcePrepared:
			_ = db.Close()
			return nil, ErrMigrationSourcePrepared
		case MigrationSourceRetired:
			_ = db.Close()
			return nil, ErrMigrationSourceRetired
		case MigrationSourceActive:
		default:
			_ = db.Close()
			return nil, errors.New("relay migration source control is invalid")
		}
	}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	var migrationPhase MigrationSourcePhase
	if err := db.QueryRowContext(context.Background(), `SELECT phase FROM relay_migration_control WHERE singleton=1`).Scan(&migrationPhase); err != nil {
		_ = db.Close()
		return nil, errors.New("relay migration source state is unavailable")
	}
	switch migrationPhase {
	case MigrationSourceActive:
	case MigrationSourcePrepared:
		_ = db.Close()
		return nil, ErrMigrationSourcePrepared
	case MigrationSourceRetired:
		_ = db.Close()
		return nil, ErrMigrationSourceRetired
	default:
		_ = db.Close()
		return nil, errors.New("relay migration source control is invalid")
	}
	if verifyQuota {
		if err := store.VerifyPendingQuota(); err != nil {
			_ = db.Close()
			return nil, err
		}
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
	var migrationControlExisted bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type='table' AND name='relay_migration_control')`).Scan(&migrationControlExisted); err != nil {
		return fmt.Errorf("inspect relay migration control: %w", err)
	}
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate relay database: %w", err)
		}
	}
	// One WAL commit for schema install. Each CREATE/TRIGGER is otherwise its
	// own fsync; parallel tests then serialize on disk and miss the race timeout.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate relay database: %w", err)
	}
	defer rollback(tx)
	for _, statement := range []string{
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
		`CREATE TABLE IF NOT EXISTS roles (
			role TEXT PRIMARY KEY,
			machine_id TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS role_memberships (
			conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			role TEXT NOT NULL REFERENCES roles(role) ON DELETE RESTRICT,
			capabilities INTEGER NOT NULL,
			PRIMARY KEY (conversation_id, role)
		)`,
		`CREATE TABLE IF NOT EXISTS role_bindings (
			role TEXT PRIMARY KEY REFERENCES roles(role) ON DELETE CASCADE,
			session_endpoint TEXT NOT NULL,
			machine_id TEXT NOT NULL,
			ownership_generation INTEGER NOT NULL,
			lease_until INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS role_profiles (
			role TEXT PRIMARY KEY REFERENCES roles(role) ON DELETE CASCADE,
			display_name TEXT,
			direct_addressable INTEGER NOT NULL DEFAULT 0 CHECK (direct_addressable IN (0, 1)),
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS role_profile_idempotency (
			machine_id TEXT NOT NULL,
			key TEXT NOT NULL,
			request_hash TEXT NOT NULL,
			role TEXT NOT NULL REFERENCES role_profiles(role) ON DELETE CASCADE,
			display_name TEXT,
			direct_addressable INTEGER NOT NULL CHECK (direct_addressable IN (0, 1)),
			updated_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (machine_id, key)
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
		`CREATE TABLE IF NOT EXISTS conversation_controls (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			actor_endpoint TEXT NOT NULL,
			operation TEXT NOT NULL CHECK (operation IN ('upsert_member','remove_member')),
			member_endpoint TEXT NOT NULL,
			member_capabilities INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS conversation_control_idempotency (
			machine_id TEXT NOT NULL,
			key TEXT NOT NULL,
			request_hash TEXT NOT NULL,
			control_id TEXT NOT NULL REFERENCES conversation_controls(id) ON DELETE CASCADE,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (machine_id, key)
		)`,
		`CREATE TABLE IF NOT EXISTS conversation_display_name_idempotency (
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
		`CREATE TABLE IF NOT EXISTS rate_buckets (
			kind TEXT NOT NULL CHECK (kind IN ('sender','conversation')),
			bucket_key TEXT NOT NULL,
			tokens INTEGER NOT NULL CHECK (tokens >= 0),
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (kind, bucket_key)
		)`,
		`CREATE TABLE IF NOT EXISTS pending_quota_recipients (
			recipient_endpoint TEXT PRIMARY KEY,
			pending_count INTEGER NOT NULL CHECK (pending_count >= 0),
			pending_bytes INTEGER NOT NULL CHECK (pending_bytes >= 0)
		)`,
		`CREATE TABLE IF NOT EXISTS pending_quota_install (
			singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
			pending_count INTEGER NOT NULL CHECK (pending_count >= 0),
			pending_bytes INTEGER NOT NULL CHECK (pending_bytes >= 0)
		)`,
		`CREATE TABLE IF NOT EXISTS delivery_terminals (
			delivery_id TEXT PRIMARY KEY,
			message_id TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			recipient_endpoint TEXT NOT NULL,
			sequence INTEGER NOT NULL CHECK (sequence >= 1),
			closed_reason TEXT NOT NULL CHECK (closed_reason IN ('acked','expired','revoked')),
			lease_generation INTEGER NOT NULL CHECK (lease_generation >= 0),
			created_at INTEGER NOT NULL,
			closed_at INTEGER NOT NULL
		)`,
		"CREATE INDEX IF NOT EXISTS delivery_terminals_closed_at ON delivery_terminals(closed_at, delivery_id)",
		`CREATE TABLE IF NOT EXISTS direct_conversations (
			role_low TEXT NOT NULL REFERENCES roles(role) ON DELETE RESTRICT,
			role_high TEXT NOT NULL REFERENCES roles(role) ON DELETE RESTRICT,
			conversation_id TEXT NOT NULL UNIQUE REFERENCES conversations(id) ON DELETE CASCADE,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (role_low, role_high),
			CHECK (role_low < role_high)
		)`,
		`CREATE TABLE IF NOT EXISTS message_from_roles (
			message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
			from_role TEXT NOT NULL REFERENCES roles(role) ON DELETE RESTRICT
		)`,
		`CREATE TABLE IF NOT EXISTS direct_message_idempotency (
			machine_id TEXT NOT NULL,
			key TEXT NOT NULL,
			request_hash TEXT NOT NULL,
			from_role TEXT NOT NULL,
			to_role TEXT NOT NULL,
			conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
			sequence INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			PRIMARY KEY (machine_id, key)
		)`,
		`CREATE TABLE IF NOT EXISTS telegram_claims (
			conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
			status TEXT NOT NULL CHECK (status IN ('pending','complete')),
			requested_by_machine TEXT NOT NULL,
			requested_by_endpoint TEXT NOT NULL,
			idempotency_key TEXT NOT NULL,
			request_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			completed_at INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS telegram_participants (
			conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
			label TEXT NOT NULL CHECK (label = 'user-telegram'),
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS telegram_claim_events (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			event TEXT NOT NULL CHECK (event = 'complete'),
			actor_machine TEXT NOT NULL,
			actor_endpoint TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS relay_migration_control (
			singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
			source_id TEXT NOT NULL,
			phase TEXT NOT NULL DEFAULT 'active' CHECK (phase IN ('active', 'prepared', 'retired')),
			epoch_id TEXT,
			target_identity TEXT,
			fingerprint TEXT,
			last_epoch_id TEXT,
			last_target_identity TEXT,
			last_expected_fingerprint TEXT,
			last_result_fingerprint TEXT,
			last_cutoff INTEGER,
			last_transition TEXT CHECK (last_transition IS NULL OR last_transition IN ('prepared', 'aborted', 'retired')),
			changed_at INTEGER NOT NULL,
			CHECK (
				(phase = 'active' AND epoch_id IS NULL AND target_identity IS NULL AND fingerprint IS NULL)
				OR (phase IN ('prepared', 'retired') AND epoch_id IS NOT NULL AND target_identity IS NOT NULL AND fingerprint IS NOT NULL)
			)
		)`,
		"CREATE INDEX IF NOT EXISTS deliveries_recipient_pending ON deliveries(recipient_endpoint, acked_at, lease_until)",
		"CREATE INDEX IF NOT EXISTS role_bindings_session ON role_bindings(machine_id, session_endpoint, ownership_generation, lease_until)",
		"CREATE INDEX IF NOT EXISTS request_nonces_expiry ON request_nonces(expires_at)",
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate relay database: %w", err)
		}
	}
	if !migrationControlExisted {
		if _, err := tx.ExecContext(ctx, `INSERT INTO relay_migration_control(singleton,source_id,changed_at) VALUES(1,?,?)`, uuid.NewString(), time.Now().UTC().UnixMilli()); err != nil {
			return fmt.Errorf("initialize relay migration control: %w", err)
		}
	}
	for _, table := range []string{"endpoints", "conversations", "memberships", "roles", "role_memberships", "role_bindings", "role_profiles", "role_profile_idempotency", "messages", "deliveries", "recipient_cursors", "idempotency", "conversation_idempotency", "conversation_controls", "conversation_control_idempotency", "conversation_display_name_idempotency", "request_nonces", "rate_buckets", "pending_quota_recipients", "pending_quota_install", "delivery_terminals", "direct_conversations", "message_from_roles", "direct_message_idempotency", "telegram_claims", "telegram_participants", "telegram_claim_events"} {
		for _, operation := range []string{"INSERT", "UPDATE", "DELETE"} {
			name := "relay_migration_guard_" + table + "_" + strings.ToLower(operation)
			statement := fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS %s BEFORE %s ON %s
				WHEN COALESCE((SELECT phase FROM relay_migration_control WHERE singleton=1), 'missing') <> 'active'
				BEGIN SELECT RAISE(ABORT, 'relay migration source is not writable'); END`, name, operation, table) // #nosec G201 -- identifiers come only from fixed internal allowlists.
			if _, err := tx.ExecContext(ctx, statement); err != nil { // #nosec G202 -- identifiers come only from fixed internal allowlists above.
				return fmt.Errorf("install relay migration guard: %w", err)
			}
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
		{"relay_migration_control", "last_epoch_id", "TEXT"},
		{"relay_migration_control", "last_target_identity", "TEXT"},
		{"relay_migration_control", "last_expected_fingerprint", "TEXT"},
		{"relay_migration_control", "last_result_fingerprint", "TEXT"},
		{"relay_migration_control", "last_cutoff", "INTEGER"},
		{"relay_migration_control", "last_transition", "TEXT"},
		{"conversations", "display_name", "TEXT"},
		{"messages", "from_participant", "TEXT"},
		{"messages", "in_reply_to_message_id", "TEXT"},
		{"messages", "in_reply_to_endpoint", "TEXT"},
		{"messages", "telegram_thread_id", "INTEGER"},
	} {
		if err := ensureSQLiteColumn(ctx, tx, column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	if err := bootstrapPendingQuota(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate relay database: %w", err)
	}
	return nil
}

// ApplyControl performs one explicit membership mutation after rechecking that
// the caller owns a currently attached admin endpoint. A stable retry key
// returns the original audit event; key reuse for another mutation conflicts.
func (s *Store) ApplyControl(input ControlInput) (ControlEvent, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !ValidMachineID(input.ActorMachineID) || !ValidEndpoint(input.ActorEndpoint) || !ValidRequestToken(input.IdempotencyKey) || !validControlOperation(input.Operation) || !ValidEndpoint(input.Member.Endpoint) || ReservedRelayMember(input.Member.Endpoint) {
		return ControlEvent{}, false, ErrForbidden
	}
	if input.Operation == ControlUpsertMember && !validCapabilities(input.Member.Capabilities) {
		return ControlEvent{}, false, ErrForbidden
	}
	if input.Operation == ControlRemoveMember && input.Member.Capabilities != 0 {
		return ControlEvent{}, false, ErrForbidden
	}
	requestHash := controlHash(input)
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return ControlEvent{}, false, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, input.ActorEndpoint, input.ActorMachineID, input.Now); err != nil {
		return ControlEvent{}, false, err
	}
	actorCapabilities, err := sessionCapabilities(tx, input.ConversationID, input.ActorMachineID, input.ActorEndpoint, input.Now)
	if err != nil {
		return ControlEvent{}, false, fmt.Errorf("authorize control actor: %w", err)
	}
	if actorCapabilities&CapAdmin == 0 {
		return ControlEvent{}, false, ErrForbidden
	}
	revoked := 0
	var existingID, existingHash string
	err = tx.QueryRowContext(context.Background(), "SELECT control_id,request_hash FROM conversation_control_idempotency WHERE machine_id=? AND key=?", input.ActorMachineID, input.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if existingHash != requestHash {
			return ControlEvent{}, false, ErrConflict
		}
		event, err := controlEventByID(tx, existingID)
		if err != nil {
			return ControlEvent{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return ControlEvent{}, false, err
		}
		return event, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ControlEvent{}, false, fmt.Errorf("read control idempotency key: %w", err)
	}
	if input.Operation == ControlUpsertMember {
		var previous Capability
		err := tx.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?", input.ConversationID, input.Member.Endpoint).Scan(&previous)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ControlEvent{}, false, fmt.Errorf("read existing control member: %w", err)
		}
		if errors.Is(err, sql.ErrNoRows) {
			if err := endpointActive(tx, input.Member.Endpoint, input.Now); err != nil {
				return ControlEvent{}, false, err
			}
			var members int
			if err := tx.QueryRowContext(context.Background(), "SELECT (SELECT COUNT(*) FROM memberships WHERE conversation_id=?) + (SELECT COUNT(*) FROM role_memberships WHERE conversation_id=?)", input.ConversationID, input.ConversationID).Scan(&members); err != nil {
				return ControlEvent{}, false, fmt.Errorf("count conversation members: %w", err)
			}
			if members >= 256 {
				return ControlEvent{}, false, ErrConflict
			}
			if exclusive, exclusiveErr := conversationIsExclusive(tx, input.ConversationID); exclusiveErr != nil {
				return ControlEvent{}, false, exclusiveErr
			} else if exclusive {
				if err := sessionOccupiesOtherExclusiveConversation(tx, input.Member.Endpoint, input.ConversationID, input.Now); err != nil {
					return ControlEvent{}, false, err
				}
			}
		}
		if err == nil && previous&CapAdmin != 0 && input.Member.Capabilities&CapAdmin == 0 {
			var remaining int
			if err := tx.QueryRowContext(context.Background(), "SELECT (SELECT COUNT(*) FROM memberships WHERE conversation_id=? AND (capabilities & ?) != 0 AND endpoint != ?) + (SELECT COUNT(*) FROM role_memberships WHERE conversation_id=? AND (capabilities & ?) != 0)", input.ConversationID, CapAdmin, input.Member.Endpoint, input.ConversationID, CapAdmin).Scan(&remaining); err != nil {
				return ControlEvent{}, false, fmt.Errorf("count remaining admins: %w", err)
			}
			if remaining == 0 {
				return ControlEvent{}, false, ErrConflict
			}
		}
		if err == nil && previous&CapReceive != 0 && input.Member.Capabilities&CapReceive == 0 {
			n, err := retireRecipientDeliveries(tx, input.Member.Endpoint, input.ConversationID, input.Now)
			if err != nil {
				return ControlEvent{}, false, err
			}
			revoked += n
			if err := advanceRecipientCursor(tx, input.Member.Endpoint, input.ConversationID); err != nil {
				return ControlEvent{}, false, err
			}
			if err := failRevokedInvocations(tx, input.ConversationID, input.Member.Endpoint, input.Now); err != nil {
				return ControlEvent{}, false, err
			}
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO memberships(conversation_id,endpoint,capabilities) VALUES(?,?,?) ON CONFLICT(conversation_id,endpoint) DO UPDATE SET capabilities=excluded.capabilities`, input.ConversationID, input.Member.Endpoint, input.Member.Capabilities); err != nil {
			return ControlEvent{}, false, fmt.Errorf("upsert conversation member: %w", err)
		}
		if input.Member.Capabilities&CapReceive != 0 {
			if err := advanceRecipientCursor(tx, input.Member.Endpoint, input.ConversationID); err != nil {
				return ControlEvent{}, false, err
			}
		}
	} else {
		var targetCapabilities Capability
		err := tx.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?", input.ConversationID, input.Member.Endpoint).Scan(&targetCapabilities)
		if errors.Is(err, sql.ErrNoRows) {
			return ControlEvent{}, false, ErrForbidden
		}
		if err != nil {
			return ControlEvent{}, false, fmt.Errorf("read control member: %w", err)
		}
		if targetCapabilities&CapAdmin != 0 {
			var remaining int
			if err := tx.QueryRowContext(context.Background(), "SELECT (SELECT COUNT(*) FROM memberships WHERE conversation_id=? AND (capabilities & ?) != 0 AND endpoint != ?) + (SELECT COUNT(*) FROM role_memberships WHERE conversation_id=? AND (capabilities & ?) != 0)", input.ConversationID, CapAdmin, input.Member.Endpoint, input.ConversationID, CapAdmin).Scan(&remaining); err != nil {
				return ControlEvent{}, false, fmt.Errorf("count remaining admins: %w", err)
			}
			if remaining == 0 {
				return ControlEvent{}, false, ErrConflict
			}
		}
		n, err := retireRecipientDeliveries(tx, input.Member.Endpoint, input.ConversationID, input.Now)
		if err != nil {
			return ControlEvent{}, false, err
		}
		revoked += n
		if err := advanceRecipientCursor(tx, input.Member.Endpoint, input.ConversationID); err != nil {
			return ControlEvent{}, false, err
		}
		if err := failRevokedInvocations(tx, input.ConversationID, input.Member.Endpoint, input.Now); err != nil {
			return ControlEvent{}, false, err
		}
		if _, err := tx.ExecContext(context.Background(), "DELETE FROM memberships WHERE conversation_id=? AND endpoint=?", input.ConversationID, input.Member.Endpoint); err != nil {
			return ControlEvent{}, false, fmt.Errorf("remove conversation member: %w", err)
		}
	}
	createdAt := input.Now.UTC().Truncate(time.Millisecond)
	var latestCreatedAt sql.NullInt64
	if err := tx.QueryRowContext(context.Background(), "SELECT MAX(created_at) FROM conversation_controls WHERE conversation_id=?", input.ConversationID).Scan(&latestCreatedAt); err != nil {
		return ControlEvent{}, false, fmt.Errorf("read latest control audit event: %w", err)
	}
	if latestCreatedAt.Valid && createdAt.UnixMilli() <= latestCreatedAt.Int64 {
		createdAt = time.UnixMilli(latestCreatedAt.Int64 + 1).UTC()
	}
	event := ControlEvent{ID: uuid.NewString(), ConversationID: input.ConversationID, ActorEndpoint: input.ActorEndpoint, Operation: input.Operation, Member: input.Member, CreatedAt: createdAt}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO conversation_controls(id,conversation_id,actor_endpoint,operation,member_endpoint,member_capabilities,created_at) VALUES(?,?,?,?,?,?,?)", event.ID, event.ConversationID, event.ActorEndpoint, event.Operation, event.Member.Endpoint, event.Member.Capabilities, event.CreatedAt.UnixMilli()); err != nil {
		return ControlEvent{}, false, fmt.Errorf("record control audit event: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO conversation_control_idempotency(machine_id,key,request_hash,control_id,created_at) VALUES(?,?,?,?,?)", input.ActorMachineID, input.IdempotencyKey, requestHash, event.ID, input.Now.UnixMilli()); err != nil {
		return ControlEvent{}, false, fmt.Errorf("record control idempotency key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ControlEvent{}, false, err
	}
	s.metrics.ObserveTerminals(ClosedRevoked, revoked)
	s.refreshPendingMetrics(input.Now)
	return event, false, nil
}

// ControlAudit returns bounded, newest-first content-free control history only
// to a current admin endpoint on the requesting machine.
func (s *Store) ControlAudit(conversationID, machineID, actorEndpoint string, now time.Time) ([]ControlEvent, error) {
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, actorEndpoint, machineID, now); err != nil {
		return nil, err
	}
	capabilities, err := sessionCapabilities(tx, conversationID, machineID, actorEndpoint, now)
	if err != nil {
		return nil, fmt.Errorf("authorize control audit: %w", err)
	}
	if capabilities&CapAdmin == 0 {
		return nil, ErrForbidden
	}
	rows, err := tx.QueryContext(context.Background(), "SELECT id,conversation_id,actor_endpoint,operation,member_endpoint,member_capabilities,created_at FROM conversation_controls WHERE conversation_id=? ORDER BY created_at DESC,id DESC LIMIT 100", conversationID)
	if err != nil {
		return nil, fmt.Errorf("read control audit: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var events []ControlEvent
	for rows.Next() {
		var event ControlEvent
		var millis int64
		if err := rows.Scan(&event.ID, &event.ConversationID, &event.ActorEndpoint, &event.Operation, &event.Member.Endpoint, &event.Member.Capabilities, &millis); err != nil {
			return nil, fmt.Errorf("read control audit event: %w", err)
		}
		event.CreatedAt = time.UnixMilli(millis).UTC()
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read control audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return events, nil
}

// SetConversationDisplayName updates a room label after rechecking a live
// admin session. A stored (machine, key) replay returns the original completed
// operation without mutating a later label; a different label on the same key
// conflicts.
func (s *Store) SetConversationDisplayName(input SetDisplayNameInput) (Conversation, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !ValidMachineID(input.ActorMachineID) || !ValidEndpoint(input.ActorEndpoint) || !ValidRequestToken(input.IdempotencyKey) {
		return Conversation{}, false, ErrForbidden
	}
	displayName, err := SanitizeConversationDisplayName(input.DisplayName)
	if err != nil || displayName == "" {
		return Conversation{}, false, fmt.Errorf("invalid conversation display name")
	}
	requestHash := DisplayNameRequestHash(input.ConversationID, input.ActorEndpoint, displayName)
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Conversation{}, false, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, input.ActorEndpoint, input.ActorMachineID, input.Now); err != nil {
		return Conversation{}, false, err
	}
	actorCapabilities, err := sessionCapabilities(tx, input.ConversationID, input.ActorMachineID, input.ActorEndpoint, input.Now)
	if err != nil {
		return Conversation{}, false, fmt.Errorf("authorize display name actor: %w", err)
	}
	if actorCapabilities&CapAdmin == 0 {
		return Conversation{}, false, ErrForbidden
	}
	var existingID, existingHash string
	err = tx.QueryRowContext(context.Background(), "SELECT conversation_id,request_hash FROM conversation_display_name_idempotency WHERE machine_id=? AND key=?", input.ActorMachineID, input.IdempotencyKey).Scan(&existingID, &existingHash)
	if err == nil {
		if existingHash != requestHash {
			return Conversation{}, false, ErrConflict
		}
		conversation, err := conversationByID(tx, existingID)
		if err != nil {
			return Conversation{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Conversation{}, false, err
		}
		return conversation, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Conversation{}, false, fmt.Errorf("read display name idempotency key: %w", err)
	}
	conversation, err := conversationByID(tx, input.ConversationID)
	if err != nil {
		return Conversation{}, false, ErrForbidden
	}
	duplicate := conversation.DisplayName == displayName
	if !duplicate {
		if conversation.DisplayName == "" {
			if err := rejectExclusiveRenameOccupancy(tx, input.ConversationID, input.Now); err != nil {
				return Conversation{}, false, err
			}
		}
		if _, err := tx.ExecContext(context.Background(), "UPDATE conversations SET display_name=? WHERE id=?", displayName, input.ConversationID); err != nil {
			return Conversation{}, false, fmt.Errorf("update conversation display name: %w", err)
		}
		conversation.DisplayName = displayName
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO conversation_display_name_idempotency(machine_id,key,request_hash,conversation_id,created_at) VALUES(?,?,?,?,?)", input.ActorMachineID, input.IdempotencyKey, requestHash, input.ConversationID, input.Now.UnixMilli()); err != nil {
		return Conversation{}, false, fmt.Errorf("record display name idempotency key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Conversation{}, false, err
	}
	return conversation, duplicate, nil
}

// PrepareTelegramAdopt drops TelegramCodexRole from the still-unnamed
// non-keeper, retires that role recipient's pending deliveries and cursor
// using the same SQL as a receive revoke, occupancy-checks the remainder
// (only telegram/primary is legal), and then sets the non-keeper display
// name. The keeper must already be named and still hold the role.
func (s *Store) PrepareTelegramAdopt(input AdoptPrepareInput) error {
	if strings.TrimSpace(input.KeeperID) == "" || strings.TrimSpace(input.NonKeeperID) == "" || input.KeeperID == input.NonKeeperID {
		return fmt.Errorf("keeper and non-keeper conversations are required")
	}
	displayName, err := SanitizeConversationDisplayName(input.NonKeeperName)
	if err != nil || displayName == "" {
		return fmt.Errorf("invalid conversation display name")
	}
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	keeper, err := conversationByID(tx, input.KeeperID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrForbidden
	}
	if err != nil {
		return err
	}
	if keeper.DisplayName == "" {
		return fmt.Errorf("keeper conversation is unnamed")
	}
	nonKeeper, err := conversationByID(tx, input.NonKeeperID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrForbidden
	}
	if err != nil {
		return err
	}
	if nonKeeper.DisplayName != "" {
		return fmt.Errorf("non-keeper conversation is already named")
	}
	if err := requireRoleMembership(tx, keeper.ID, TelegramCodexRole); err != nil {
		return err
	}
	if err := requireRoleMembership(tx, nonKeeper.ID, TelegramCodexRole); err != nil {
		return err
	}
	if _, err := tx.ExecContext(context.Background(), "DELETE FROM role_memberships WHERE conversation_id=? AND role=?", nonKeeper.ID, TelegramCodexRole); err != nil {
		return fmt.Errorf("drop durable role member: %w", err)
	}
	recipient := roleRecipient(TelegramCodexRole)
	if _, err := retireRecipientDeliveries(tx, recipient, nonKeeper.ID, now); err != nil {
		return err
	}
	if err := advanceRecipientCursor(tx, recipient, nonKeeper.ID); err != nil {
		return err
	}
	if err := rejectAdoptPrepareOccupancy(tx, nonKeeper.ID, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(context.Background(), "UPDATE conversations SET display_name=? WHERE id=?", displayName, nonKeeper.ID); err != nil {
		return fmt.Errorf("update conversation display name: %w", err)
	}
	return tx.Commit()
}

func requireRoleMembership(tx *sql.Tx, conversationID, role string) error {
	var present bool
	if err := tx.QueryRowContext(context.Background(), "SELECT EXISTS(SELECT 1 FROM role_memberships WHERE conversation_id=? AND role=?)", conversationID, role).Scan(&present); err != nil {
		return fmt.Errorf("read durable role membership: %w", err)
	}
	if !present {
		return ErrConflict
	}
	return nil
}

func rejectAdoptPrepareOccupancy(tx *sql.Tx, conversationID string, now time.Time) error {
	var extra int
	if err := tx.QueryRowContext(context.Background(), `SELECT (SELECT COUNT(*) FROM memberships WHERE conversation_id=? AND endpoint<>?) + (SELECT COUNT(*) FROM role_memberships WHERE conversation_id=?)`, conversationID, TelegramPrimaryEndpoint, conversationID).Scan(&extra); err != nil {
		return fmt.Errorf("count remaining occupants: %w", err)
	}
	if extra != 0 {
		return ErrConflict
	}
	var gateway bool
	if err := tx.QueryRowContext(context.Background(), "SELECT EXISTS(SELECT 1 FROM memberships WHERE conversation_id=? AND endpoint=?)", conversationID, TelegramPrimaryEndpoint).Scan(&gateway); err != nil {
		return fmt.Errorf("read gateway membership: %w", err)
	}
	if !gateway {
		return ErrConflict
	}
	return rejectExclusiveRenameOccupancy(tx, conversationID, now)
}

func telegramClaimRequestHash(conversationID string) string {
	digest := sha256.Sum256([]byte(conversationID))
	return hex.EncodeToString(digest[:])
}

func requireCompleteTelegramClaim(tx *sql.Tx, conversationID string) error {
	var status string
	err := tx.QueryRowContext(context.Background(), "SELECT status FROM telegram_claims WHERE conversation_id = ?", conversationID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) || status != "complete" {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("read telegram claim: %w", err)
	}
	return nil
}

func telegramClaimByConversation(tx *sql.Tx, conversationID string) (TelegramClaim, error) {
	var claim TelegramClaim
	var createdAt int64
	var completedAt sql.NullInt64
	if err := tx.QueryRowContext(context.Background(), `SELECT claim.conversation_id, claim.status, COALESCE(conversation.display_name, ''), claim.created_at, claim.completed_at
		FROM telegram_claims AS claim
		JOIN conversations AS conversation ON conversation.id = claim.conversation_id
		WHERE claim.conversation_id = ?`, conversationID).Scan(&claim.ConversationID, &claim.Status, &claim.DisplayName, &createdAt, &completedAt); err != nil {
		return TelegramClaim{}, fmt.Errorf("read telegram claim: %w", err)
	}
	claim.CreatedAt = fromMillis(createdAt)
	if completedAt.Valid {
		completed := fromMillis(completedAt.Int64)
		claim.CompletedAt = &completed
	}
	return claim, nil
}

// ReserveTelegramClaim is a singleton ensure: the first successful reserve
// wins, and any later key returns that row without rewriting it.
func (s *Store) ReserveTelegramClaim(input TelegramClaimInput) (TelegramClaim, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !ValidMachineID(input.MachineID) || !ValidEndpoint(input.Endpoint) || !ValidRequestToken(input.IdempotencyKey) {
		return TelegramClaim{}, false, ErrForbidden
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return TelegramClaim{}, false, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, input.Endpoint, input.MachineID, input.Now); err != nil {
		return TelegramClaim{}, false, err
	}
	conversation, err := conversationByID(tx, input.ConversationID)
	if err != nil || conversation.DisplayName == "" {
		return TelegramClaim{}, false, ErrForbidden
	}
	if input.Endpoint != TelegramGatewayEndpoint {
		capabilities, err := sessionCapabilities(tx, input.ConversationID, input.MachineID, input.Endpoint, input.Now)
		if err != nil {
			return TelegramClaim{}, false, fmt.Errorf("authorize claim actor: %w", err)
		}
		if capabilities == 0 {
			return TelegramClaim{}, false, ErrForbidden
		}
	}
	var existing string
	err = tx.QueryRowContext(context.Background(), "SELECT conversation_id FROM telegram_claims WHERE conversation_id = ?", input.ConversationID).Scan(&existing)
	if err == nil {
		claim, err := telegramClaimByConversation(tx, input.ConversationID)
		if err != nil {
			return TelegramClaim{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return TelegramClaim{}, false, err
		}
		return claim, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return TelegramClaim{}, false, fmt.Errorf("read telegram claim: %w", err)
	}
	if err := rejectExclusiveClaimOccupancy(tx, input.ConversationID, input.Now); err != nil {
		return TelegramClaim{}, false, err
	}
	createdAt := input.Now.UTC().Truncate(time.Millisecond)
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO telegram_claims(conversation_id, status, requested_by_machine, requested_by_endpoint, idempotency_key, request_hash, created_at)
		VALUES (?, 'pending', ?, ?, ?, ?, ?)`, input.ConversationID, input.MachineID, input.Endpoint, input.IdempotencyKey, telegramClaimRequestHash(input.ConversationID), createdAt.UnixMilli()); err != nil {
		return TelegramClaim{}, false, fmt.Errorf("reserve telegram claim: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return TelegramClaim{}, false, err
	}
	return TelegramClaim{ConversationID: input.ConversationID, Status: "pending", DisplayName: conversation.DisplayName, CreatedAt: createdAt}, false, nil
}

// CompleteTelegramClaim materializes telegram/primary and user-telegram after
// a pending reservation. A completed row is an idempotent no-op.
func (s *Store) CompleteTelegramClaim(input TelegramClaimCompleteInput) (TelegramClaim, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !ValidMachineID(input.MachineID) {
		return TelegramClaim{}, false, ErrForbidden
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return TelegramClaim{}, false, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, TelegramGatewayEndpoint, input.MachineID, input.Now); err != nil {
		return TelegramClaim{}, false, err
	}
	claim, err := telegramClaimByConversation(tx, input.ConversationID)
	if err != nil {
		return TelegramClaim{}, false, ErrForbidden
	}
	if claim.Status == "complete" {
		if err := tx.Commit(); err != nil {
			return TelegramClaim{}, false, err
		}
		return claim, true, nil
	}
	if claim.Status != "pending" {
		return TelegramClaim{}, false, ErrForbidden
	}
	if err := ensureTelegramGatewayMembership(tx, input.ConversationID); err != nil {
		return TelegramClaim{}, false, err
	}
	completedAt := input.Now.UTC().Truncate(time.Millisecond)
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO telegram_participants(conversation_id, label, created_at) VALUES (?, ?, ?)", input.ConversationID, TelegramUserParticipant, completedAt.UnixMilli()); err != nil {
		return TelegramClaim{}, false, fmt.Errorf("insert telegram participant: %w", err)
	}
	result, err := tx.ExecContext(context.Background(), "UPDATE telegram_claims SET status='complete', completed_at=? WHERE conversation_id=? AND status='pending'", completedAt.UnixMilli(), input.ConversationID)
	if err != nil {
		return TelegramClaim{}, false, fmt.Errorf("complete telegram claim: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return TelegramClaim{}, false, fmt.Errorf("complete telegram claim: %w", err)
	}
	if updated == 0 {
		claim, err := telegramClaimByConversation(tx, input.ConversationID)
		if err != nil {
			return TelegramClaim{}, false, ErrForbidden
		}
		if claim.Status == "complete" {
			if err := tx.Commit(); err != nil {
				return TelegramClaim{}, false, err
			}
			return claim, true, nil
		}
		return TelegramClaim{}, false, ErrForbidden
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO telegram_claim_events(id, conversation_id, event, actor_machine, actor_endpoint, created_at) VALUES (?, ?, 'complete', ?, ?, ?)", uuid.NewString(), input.ConversationID, input.MachineID, TelegramGatewayEndpoint, completedAt.UnixMilli()); err != nil {
		return TelegramClaim{}, false, fmt.Errorf("record telegram claim event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return TelegramClaim{}, false, err
	}
	claim.Status = "complete"
	claim.CompletedAt = &completedAt
	return claim, false, nil
}

// PendingTelegramClaims is a gateway poll of pending reservations, not a lease.
func (s *Store) PendingTelegramClaims(machineID string, now time.Time, limit int, after string) ([]TelegramClaim, error) {
	if !ValidMachineID(machineID) || limit < 1 || limit > 100 || (after != "" && strings.TrimSpace(after) != after) {
		return nil, ErrForbidden
	}
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, TelegramGatewayEndpoint, machineID, now); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT claim.conversation_id, claim.status, COALESCE(conversation.display_name, ''), claim.created_at, claim.completed_at
		FROM telegram_claims AS claim
		JOIN conversations AS conversation ON conversation.id = claim.conversation_id
		WHERE claim.status = 'pending'
		  AND (? = '' OR (claim.created_at, claim.conversation_id) > (
			SELECT cursor.created_at, cursor.conversation_id FROM telegram_claims AS cursor WHERE cursor.conversation_id = ?
		  ))
		ORDER BY claim.created_at ASC, claim.conversation_id ASC
		LIMIT ?`, after, after, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending telegram claims: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var claims []TelegramClaim
	for rows.Next() {
		var claim TelegramClaim
		var createdAt int64
		var completedAt sql.NullInt64
		if err := rows.Scan(&claim.ConversationID, &claim.Status, &claim.DisplayName, &createdAt, &completedAt); err != nil {
			return nil, fmt.Errorf("read pending telegram claim: %w", err)
		}
		claim.CreatedAt = fromMillis(createdAt)
		if completedAt.Valid {
			completed := fromMillis(completedAt.Int64)
			claim.CompletedAt = &completed
		}
		claims = append(claims, claim)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list pending telegram claims: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claims, nil
}

// UnclaimedNamedConversations returns the newest named rooms without a
// completed claim. Last-message time is computed from messages.created_at.
func (s *Store) UnclaimedNamedConversations(machineID string, now time.Time, limit int) ([]UnclaimedTopic, error) {
	if !ValidMachineID(machineID) || limit < 1 || limit > 100 {
		return nil, ErrForbidden
	}
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, TelegramGatewayEndpoint, machineID, now); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT conversation.id, conversation.display_name, MAX(message.created_at)
		FROM conversations AS conversation
		LEFT JOIN messages AS message ON message.conversation_id = conversation.id
		WHERE conversation.display_name IS NOT NULL AND conversation.display_name <> ''
		  AND NOT EXISTS (SELECT 1 FROM telegram_claims WHERE conversation_id = conversation.id AND status = 'complete')
		GROUP BY conversation.id
		ORDER BY MAX(message.created_at) IS NULL, MAX(message.created_at) DESC, conversation.created_at DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list unclaimed conversations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var topics []UnclaimedTopic
	for rows.Next() {
		var topic UnclaimedTopic
		var lastMessage sql.NullInt64
		if err := rows.Scan(&topic.ID, &topic.DisplayName, &lastMessage); err != nil {
			return nil, fmt.Errorf("read unclaimed conversation: %w", err)
		}
		if lastMessage.Valid {
			at := fromMillis(lastMessage.Int64)
			topic.LastMessageAt = &at
		}
		topics = append(topics, topic)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list unclaimed conversations: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return topics, nil
}

// SessionTopic returns the endpoint's sole named or claimed occupancy.
func (s *Store) SessionTopic(machineID, endpoint string, now time.Time) (SessionTopic, error) {
	if !ValidMachineID(machineID) || !ValidEndpoint(endpoint) {
		return SessionTopic{}, ErrForbidden
	}
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return SessionTopic{}, err
	}
	defer rollback(tx)
	if err := endpointOwnedBy(tx, endpoint, machineID, now); err != nil {
		return SessionTopic{}, err
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT conversation.id, COALESCE(conversation.display_name, ''), EXISTS(SELECT 1 FROM telegram_claims WHERE conversation_id = conversation.id AND status = 'complete')
		FROM conversations AS conversation
		WHERE `+exclusiveConversationPredicate("conversation")+`
		  AND (
			EXISTS (SELECT 1 FROM memberships WHERE conversation_id = conversation.id AND endpoint = ?)
			OR EXISTS (
				SELECT 1 FROM role_memberships AS membership
				JOIN role_bindings AS binding ON binding.role = membership.role
				JOIN endpoints AS live ON live.endpoint = binding.session_endpoint
				WHERE membership.conversation_id = conversation.id
				  AND binding.session_endpoint = ?
				  AND binding.lease_until > ?
				  AND live.machine_id = binding.machine_id
				  AND live.ownership_generation = binding.ownership_generation
				  AND live.lease_until > ?
			)
		  )`, endpoint, endpoint, now.UnixMilli(), now.UnixMilli()) // #nosec G202 -- exclusive predicate uses a fixed alias and table names.
	if err != nil {
		return SessionTopic{}, fmt.Errorf("read session topic: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var topics []SessionTopic
	for rows.Next() {
		var topic SessionTopic
		var claimed bool
		if err := rows.Scan(&topic.ID, &topic.DisplayName, &claimed); err != nil {
			return SessionTopic{}, fmt.Errorf("read session topic: %w", err)
		}
		topic.Claimed = claimed
		topics = append(topics, topic)
	}
	if err := rows.Err(); err != nil {
		return SessionTopic{}, fmt.Errorf("read session topic: %w", err)
	}
	if len(topics) == 0 {
		return SessionTopic{}, ErrForbidden
	}
	if len(topics) > 1 {
		return SessionTopic{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return SessionTopic{}, err
	}
	return topics[0], nil
}

// AppendTelegramInbound accepts gateway inbound mail. Metadata is stored but
// excluded from the append hash so a later reply-map fill cannot conflict.
func (s *Store) AppendTelegramInbound(input TelegramInboundInput) (Message, bool, error) {
	if err := ValidateTelegramInbound(input); err != nil {
		return Message{}, false, err
	}
	requestHash := appendHash(AppendInput{ConversationID: input.ConversationID, FromEndpoint: input.FromEndpoint, Body: input.Body})
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Message{}, false, err
	}
	defer rollback(tx)
	if err := requireCompleteTelegramClaim(tx, input.ConversationID); err != nil {
		return Message{}, false, err
	}
	capabilities, err := sessionCapabilities(tx, input.ConversationID, input.SenderMachineID, input.FromEndpoint, input.Now)
	if err != nil {
		return Message{}, false, err
	}
	if capabilities&CapSend == 0 {
		return Message{}, false, ErrForbidden
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
	if err := s.consumeRateLimits(tx, input.SenderMachineID, input.ConversationID, input.Now); err != nil {
		return Message{}, false, err
	}
	deliveryRecipients, err := appendDeliveryRecipients(tx, input.ConversationID, input.FromEndpoint, "")
	if err != nil {
		return Message{}, false, err
	}
	if err := s.consumeQuota(tx, deliveryRecipients, int64(len(input.Body))); err != nil {
		return Message{}, false, err
	}
	message := Message{
		ID:                       uuid.NewString(),
		ConversationID:           input.ConversationID,
		FromEndpoint:             input.FromEndpoint,
		FromParticipant:          input.FromParticipant,
		InReplyToPunaroMessageID: input.InReplyToMessageID,
		InReplyToEndpoint:        input.InReplyToEndpoint,
		TelegramThreadID:         input.TelegramThreadID,
		Body:                     input.Body,
		CreatedAt:                input.Now.UTC().Truncate(time.Millisecond),
	}
	if err := tx.QueryRowContext(context.Background(), "UPDATE conversations SET next_sequence = next_sequence + 1 WHERE id = ? RETURNING next_sequence", input.ConversationID).Scan(&message.Sequence); errors.Is(err, sql.ErrNoRows) {
		return Message{}, false, ErrForbidden
	} else if err != nil {
		return Message{}, false, fmt.Errorf("allocate message sequence: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO messages(id, conversation_id, sequence, from_endpoint, from_participant, in_reply_to_message_id, in_reply_to_endpoint, telegram_thread_id, body, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, message.ID, message.ConversationID, message.Sequence, message.FromEndpoint, nullableText(message.FromParticipant), nullableText(message.InReplyToPunaroMessageID), nullableText(message.InReplyToEndpoint), nullableThreadID(message.TelegramThreadID), message.Body, message.CreatedAt.UnixMilli()); err != nil {
		return Message{}, false, fmt.Errorf("append telegram inbound: %w", err)
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
	roleRows, err := tx.QueryContext(context.Background(), "SELECT role FROM role_memberships WHERE conversation_id = ? AND (capabilities & ?) != 0", input.ConversationID, CapReceive)
	if err != nil {
		return Message{}, false, fmt.Errorf("find durable role recipients: %w", err)
	}
	var roles []string
	for roleRows.Next() {
		var role string
		if err := roleRows.Scan(&role); err != nil {
			_ = roleRows.Close()
			return Message{}, false, err
		}
		roles = append(roles, role)
	}
	if err := roleRows.Close(); err != nil {
		return Message{}, false, fmt.Errorf("find durable role recipients: %w", err)
	}
	for _, role := range roles {
		if _, err := tx.ExecContext(context.Background(), "INSERT INTO deliveries(id, message_id, recipient_endpoint) VALUES (?, ?, ?)", uuid.NewString(), message.ID, roleRecipient(role)); err != nil {
			return Message{}, false, fmt.Errorf("create durable role delivery: %w", err)
		}
	}
	if err := advanceSessionCursors(tx, input.SenderMachineID, input.FromEndpoint, input.ConversationID, input.Now); err != nil {
		return Message{}, false, err
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO idempotency(machine_id, key, request_hash, message_id, created_at) VALUES (?, ?, ?, ?, ?)", input.SenderMachineID, input.IdempotencyKey, requestHash, message.ID, input.Now.UnixMilli()); err != nil {
		return Message{}, false, fmt.Errorf("record idempotency key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Message{}, false, err
	}
	return message, false, nil
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableThreadID(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func validControlOperation(operation ControlOperation) bool {
	return operation == ControlUpsertMember || operation == ControlRemoveMember
}
func validCapabilities(capabilities Capability) bool {
	return capabilities != 0 && capabilities&^(CapSend|CapReceive|CapAdmin|CapInvoke) == 0
}
func controlHash(input ControlInput) string {
	return stableHash(input.ConversationID, input.ActorEndpoint, string(input.Operation), input.Member.Endpoint, fmt.Sprintf("%d", input.Member.Capabilities))
}

// ControlRequestHash binds a control retry key to the exact typed mutation.
func ControlRequestHash(input ControlInput) string { return controlHash(input) }

func controlEventByID(tx *sql.Tx, id string) (ControlEvent, error) {
	var event ControlEvent
	var millis int64
	if err := tx.QueryRowContext(context.Background(), "SELECT id,conversation_id,actor_endpoint,operation,member_endpoint,member_capabilities,created_at FROM conversation_controls WHERE id=?", id).Scan(&event.ID, &event.ConversationID, &event.ActorEndpoint, &event.Operation, &event.Member.Endpoint, &event.Member.Capabilities, &millis); err != nil {
		return ControlEvent{}, fmt.Errorf("read control audit event: %w", err)
	}
	event.CreatedAt = time.UnixMilli(millis).UTC()
	return event, nil
}

type sqliteExecQueryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func ensureSQLiteColumn(ctx context.Context, db sqliteExecQueryer, table, name, definition string) error {
	if table != "endpoints" && table != "deliveries" && table != "invocations" && table != "relay_migration_control" && table != "conversations" && table != "messages" {
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
	// Read optional invocation state under the same SQLite transaction that
	// changes endpoint ownership. A pre-transaction snapshot could miss a
	// concurrently committed start lease and permit its owner to be replaced.
	invocationSchemaExists, err := invocationSchemaExistsTx(tx)
	if err != nil {
		return err
	}
	if invocationSchemaExists {
		for endpoint := range seen {
			var handoffReserved bool
			err := tx.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM invocations WHERE target_endpoint=? AND target_machine_id<>? AND ((status=? AND (lease_machine_id IS NOT NULL AND lease_until>? OR (lease_generation>0 AND last_activity_at>?))) OR (status=? AND not_before>?)))`, endpoint, machineID, InvocationPending, now.UnixMilli(), now.Add(-invocationPendingRetention).UnixMilli(), InvocationSucceeded, now.UnixMilli()).Scan(&handoffReserved)
			if err != nil {
				return fmt.Errorf("inspect live invocation lease: %w", err)
			}
			if handoffReserved {
				return ErrConflict
			}
		}
	}
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
		if _, err := tx.ExecContext(context.Background(), `UPDATE role_bindings SET lease_until = ?
			WHERE machine_id = ? AND session_endpoint = ?
			  AND lease_until > ?
			  AND ownership_generation = (SELECT ownership_generation FROM endpoints WHERE endpoint = ?
			    AND machine_id = ? AND lease_until = ?)`, until, machineID, endpoint, now.UnixMilli(), endpoint, machineID, until); err != nil {
			return fmt.Errorf("renew durable role binding: %w", err)
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

// BindRoleToSession renewably assigns one durable role to a currently attached
// session of its configured machine. A role never follows a session address:
// the binding is replaced explicitly and expires no later than that session's
// own attachment lease.
func (s *Store) BindRoleToSession(machineID, role, sessionEndpoint string, now time.Time, ttl time.Duration) error {
	if !ValidMachineID(machineID) || !ValidRole(role) || role == TelegramUserParticipant || !ValidEndpoint(sessionEndpoint) || ttl <= 0 {
		return ErrForbidden
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer rollback(tx)
	generation, until, err := endpointOwnershipUntil(tx, sessionEndpoint, machineID, now)
	if err != nil {
		return err
	}
	var owner string
	err = tx.QueryRowContext(context.Background(), "SELECT machine_id FROM roles WHERE role = ?", role).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) || owner != machineID {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("read durable role owner: %w", err)
	}
	bindingUntil := now.Add(ttl).UnixMilli()
	if bindingUntil > until {
		bindingUntil = until
	}
	if bindingUntil <= now.UnixMilli() {
		return ErrForbidden
	}
	var activeRoles int
	if err := tx.QueryRowContext(context.Background(), `SELECT count(*) FROM role_bindings
		WHERE machine_id=? AND session_endpoint=? AND ownership_generation=? AND lease_until>? AND role<>?`, machineID, sessionEndpoint, generation, now.UnixMilli(), role).Scan(&activeRoles); err != nil {
		return fmt.Errorf("count active durable roles: %w", err)
	}
	if activeRoles >= MaxActiveRolesPerSession {
		return ErrConflict
	}
	if err := rejectExclusiveBindOccupancy(tx, sessionEndpoint, role, now); err != nil {
		return err
	}
	var previousSession string
	var previousGeneration, previousLeaseUntil int64
	err = tx.QueryRowContext(context.Background(), "SELECT session_endpoint, ownership_generation, lease_until FROM role_bindings WHERE role=?", role).Scan(&previousSession, &previousGeneration, &previousLeaseUntil)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read durable role binding: %w", err)
	}
	rebinding := err == nil && (previousSession != sessionEndpoint || previousGeneration != generation || previousLeaseUntil <= now.UnixMilli())
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO role_bindings(role, session_endpoint, machine_id, ownership_generation, lease_until)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(role) DO UPDATE SET session_endpoint=excluded.session_endpoint, machine_id=excluded.machine_id,
		ownership_generation=excluded.ownership_generation, lease_until=excluded.lease_until`, role, sessionEndpoint, machineID, generation, bindingUntil); err != nil {
		return fmt.Errorf("bind durable role: %w", err)
	}
	if rebinding {
		if _, err := tx.ExecContext(context.Background(), `UPDATE deliveries
			SET lease_machine_id=NULL,lease_token=NULL,ownership_generation=NULL,consumer_generation=NULL,lease_until=NULL
			WHERE recipient_endpoint=? AND acked_at IS NULL`, roleRecipient(role)); err != nil {
			return fmt.Errorf("invalidate rebound role leases: %w", err)
		}
	}
	return tx.Commit()
}

// RegisterRoleProfile creates or updates one machine-owned canonical role
// profile. Exact retries return the first result; later calls may change only
// display name and addressability.
func (s *Store) RegisterRoleProfile(input RegisterRoleInput) (RoleProfile, bool, error) {
	displayName, ok := NormalizeRoleDisplayName(input.DisplayName)
	if !ok || !ValidMachineID(input.MachineID) || !ValidRequestToken(input.IdempotencyKey) || !CanonicalRoleForMachine(input.Role, input.MachineID) {
		return RoleProfile{}, false, fmt.Errorf("invalid role registration")
	}
	requestHash := RegisterRoleRequestHash(input.Role, displayName, input.DirectAddressable)
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return RoleProfile{}, false, err
	}
	defer rollback(tx)
	existing, _, err := readRoleProfileIdempotency(tx, input.MachineID, input.IdempotencyKey)
	if err == nil {
		if existing.requestHash != requestHash {
			return RoleProfile{}, false, ErrConflict
		}
		if err := tx.Commit(); err != nil {
			return RoleProfile{}, false, err
		}
		return existing.profile, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return RoleProfile{}, false, err
	}
	var owner string
	err = tx.QueryRowContext(context.Background(), "SELECT machine_id FROM roles WHERE role = ?", input.Role).Scan(&owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(context.Background(), "INSERT INTO roles(role, machine_id) VALUES (?, ?)", input.Role, input.MachineID); err != nil {
			return RoleProfile{}, false, fmt.Errorf("create durable role: %w", err)
		}
		owner = input.MachineID
	case err != nil:
		return RoleProfile{}, false, fmt.Errorf("read durable role owner: %w", err)
	case owner != input.MachineID:
		return RoleProfile{}, false, ErrForbidden
	}
	var existingUpdatedAt int64
	err = tx.QueryRowContext(context.Background(), "SELECT updated_at FROM role_profiles WHERE role = ?", input.Role).Scan(&existingUpdatedAt)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return RoleProfile{}, false, fmt.Errorf("read role profile: %w", err)
	}
	addressable := 0
	if input.DirectAddressable {
		addressable = 1
	}
	var display any
	if displayName != "" {
		display = displayName
	}
	updatedAt := input.Now.UTC().Truncate(time.Millisecond)
	if created {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO role_profiles(role, display_name, direct_addressable, updated_at) VALUES (?, ?, ?, ?)`, input.Role, display, addressable, updatedAt.UnixMilli()); err != nil {
			return RoleProfile{}, false, fmt.Errorf("create role profile: %w", err)
		}
	} else if _, err := tx.ExecContext(context.Background(), `UPDATE role_profiles SET display_name = ?, direct_addressable = ?, updated_at = ? WHERE role = ?`, display, addressable, updatedAt.UnixMilli(), input.Role); err != nil {
		return RoleProfile{}, false, fmt.Errorf("update role profile: %w", err)
	}
	profile := RoleProfile{Role: input.Role, DisplayName: displayName, DirectAddressable: input.DirectAddressable, UpdatedAt: updatedAt}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO role_profile_idempotency(machine_id, key, request_hash, role, display_name, direct_addressable, updated_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, input.MachineID, input.IdempotencyKey, requestHash, input.Role, display, addressable, profile.UpdatedAt.UnixMilli(), updatedAt.UnixMilli()); err != nil {
		return RoleProfile{}, false, fmt.Errorf("record role profile idempotency key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RoleProfile{}, false, err
	}
	return profile, created, nil
}

// SendDirectMessage creates or reuses the unique unordered-role conversation
// and appends one targeted message. Exact retries return the original result.
func (s *Store) SendDirectMessage(input DirectMessageInput) (Message, bool, error) {
	if !ValidMachineID(input.SenderMachineID) || !ValidRequestToken(input.IdempotencyKey) || !CanonicalRoleForMachine(input.FromRole, input.SenderMachineID) || !CanonicalRoleHandle(input.ToRole) || input.FromRole == input.ToRole {
		return Message{}, false, fmt.Errorf("invalid direct message request")
	}
	if len(input.Body) > maxMessageBodyBytes {
		return Message{}, false, fmt.Errorf("message body exceeds %d bytes", maxMessageBodyBytes)
	}
	if !ValidMessageBody(input.Body) {
		return Message{}, false, errors.New("message body is not portable UTF-8 text")
	}
	roleLow, roleHigh, ok := OrderedDirectRolePair(input.FromRole, input.ToRole)
	if !ok {
		return Message{}, false, fmt.Errorf("invalid direct message request")
	}
	requestHash := DirectMessageRequestHash(input.FromRole, input.ToRole, input.Body)
	now := input.Now.UTC().Truncate(time.Millisecond)
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Message{}, false, err
	}
	defer rollback(tx)
	var existingHash, existingMessageID string
	err = tx.QueryRowContext(context.Background(), `SELECT request_hash, message_id FROM direct_message_idempotency WHERE machine_id = ? AND key = ?`, input.SenderMachineID, input.IdempotencyKey).Scan(&existingHash, &existingMessageID)
	if err == nil {
		if existingHash != requestHash {
			return Message{}, false, ErrConflict
		}
		message, err := messageByID(tx, existingMessageID)
		if err != nil {
			return Message{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Message{}, false, err
		}
		return message, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Message{}, false, fmt.Errorf("read direct message idempotency key: %w", err)
	}
	session, err := liveBoundRoleSession(tx, input.SenderMachineID, input.FromRole, now)
	if err != nil {
		return Message{}, false, err
	}
	// Hold the target profile write lock through commit so a concurrent opt-out
	// cannot revoke addressability after this read and still land a message.
	locked, err := tx.ExecContext(context.Background(), `UPDATE role_profiles SET updated_at = updated_at WHERE role = ?`, input.ToRole)
	if err != nil {
		return Message{}, false, fmt.Errorf("lock target role profile: %w", err)
	}
	affected, err := locked.RowsAffected()
	if err != nil {
		return Message{}, false, fmt.Errorf("lock target role profile: %w", err)
	}
	if affected == 0 {
		return Message{}, false, ErrForbidden
	}
	var addressable int
	err = tx.QueryRowContext(context.Background(), `SELECT direct_addressable FROM role_profiles WHERE role = ?`, input.ToRole).Scan(&addressable)
	if errors.Is(err, sql.ErrNoRows) || addressable != 1 {
		return Message{}, false, ErrForbidden
	}
	if err != nil {
		return Message{}, false, fmt.Errorf("read target role profile: %w", err)
	}
	conversationID, err := getOrCreateDirectConversation(tx, roleLow, roleHigh, input.FromRole, input.ToRole, now)
	if err != nil {
		return Message{}, false, err
	}
	if err := s.consumeRateLimits(tx, input.SenderMachineID, conversationID, now); err != nil {
		return Message{}, false, err
	}
	if err := s.consumeQuota(tx, []string{roleRecipient(input.ToRole)}, int64(len(input.Body))); err != nil {
		return Message{}, false, err
	}
	message := Message{ID: uuid.NewString(), ConversationID: conversationID, FromRole: input.FromRole, Body: input.Body, CreatedAt: now}
	if err := tx.QueryRowContext(context.Background(), "UPDATE conversations SET next_sequence = next_sequence + 1 WHERE id = ? RETURNING next_sequence", conversationID).Scan(&message.Sequence); errors.Is(err, sql.ErrNoRows) {
		return Message{}, false, ErrForbidden
	} else if err != nil {
		return Message{}, false, fmt.Errorf("allocate message sequence: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO messages(id, conversation_id, sequence, from_endpoint, body, created_at) VALUES (?, ?, ?, ?, ?, ?)`, message.ID, message.ConversationID, message.Sequence, session, message.Body, message.CreatedAt.UnixMilli()); err != nil {
		return Message{}, false, fmt.Errorf("append direct message: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO message_from_roles(message_id, from_role) VALUES (?, ?)`, message.ID, input.FromRole); err != nil {
		return Message{}, false, fmt.Errorf("record direct message sender role: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO deliveries(id, message_id, recipient_endpoint) VALUES (?, ?, ?)`, uuid.NewString(), message.ID, roleRecipient(input.ToRole)); err != nil {
		return Message{}, false, fmt.Errorf("create direct role delivery: %w", err)
	}
	if err := advanceRecipientCursor(tx, roleRecipient(input.FromRole), conversationID); err != nil {
		return Message{}, false, err
	}
	if err := advanceSessionCursors(tx, input.SenderMachineID, session, conversationID, now); err != nil {
		return Message{}, false, err
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO direct_message_idempotency(machine_id, key, request_hash, from_role, to_role, conversation_id, message_id, sequence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, input.SenderMachineID, input.IdempotencyKey, requestHash, input.FromRole, input.ToRole, conversationID, message.ID, message.Sequence, now.UnixMilli()); err != nil {
		return Message{}, false, fmt.Errorf("record direct message idempotency key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Message{}, false, err
	}
	s.refreshPendingMetrics(now)
	return message, false, nil
}

func rejectDirectConversationAppend(tx *sql.Tx, conversationID string) error {
	var exists int
	if err := tx.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM direct_conversations WHERE conversation_id = ?)`, conversationID).Scan(&exists); err != nil {
		return fmt.Errorf("read direct conversation: %w", err)
	}
	if exists == 1 {
		return ErrForbidden
	}
	return nil
}

func liveBoundRoleSession(tx *sql.Tx, machineID, role string, now time.Time) (string, error) {
	var session string
	err := tx.QueryRowContext(context.Background(), `SELECT rb.session_endpoint FROM role_bindings rb
		JOIN endpoints e ON e.endpoint = rb.session_endpoint
		WHERE rb.role = ? AND rb.machine_id = ? AND e.machine_id = ?
		  AND rb.ownership_generation = e.ownership_generation
		  AND rb.lease_until > ? AND e.lease_until > ?`, role, machineID, machineID, now.UnixMilli(), now.UnixMilli()).Scan(&session)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrForbidden
	}
	if err != nil {
		return "", fmt.Errorf("read live role binding: %w", err)
	}
	return session, nil
}

func getOrCreateDirectConversation(tx *sql.Tx, roleLow, roleHigh, fromRole, toRole string, now time.Time) (string, error) {
	if _, err := tx.ExecContext(context.Background(), `SAVEPOINT create_direct_conversation`); err != nil {
		return "", fmt.Errorf("begin direct conversation create: %w", err)
	}
	conversationID := uuid.NewString()
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO conversations(id, created_at) VALUES (?, ?)`, conversationID, now.UnixMilli()); err != nil {
		return "", fmt.Errorf("create direct conversation: %w", err)
	}
	for _, role := range []string{fromRole, toRole} {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO role_memberships(conversation_id, role, capabilities) VALUES (?, ?, ?)`, conversationID, role, CapSend|CapReceive); err != nil {
			return "", fmt.Errorf("add direct conversation role member: %w", err)
		}
	}
	result, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO direct_conversations(role_low, role_high, conversation_id, created_at) VALUES (?, ?, ?, ?)`, roleLow, roleHigh, conversationID, now.UnixMilli())
	if err != nil {
		return "", fmt.Errorf("record direct conversation pair: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("record direct conversation pair: %w", err)
	}
	if affected == 1 {
		if _, err := tx.ExecContext(context.Background(), `RELEASE create_direct_conversation`); err != nil {
			return "", fmt.Errorf("commit direct conversation create: %w", err)
		}
		return conversationID, nil
	}
	if _, err := tx.ExecContext(context.Background(), `ROLLBACK TO create_direct_conversation`); err != nil {
		return "", fmt.Errorf("discard duplicate direct conversation: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), `RELEASE create_direct_conversation`); err != nil {
		return "", fmt.Errorf("release direct conversation savepoint: %w", err)
	}
	if err := tx.QueryRowContext(context.Background(), `SELECT conversation_id FROM direct_conversations WHERE role_low = ? AND role_high = ?`, roleLow, roleHigh).Scan(&conversationID); err != nil {
		return "", fmt.Errorf("read converged direct conversation: %w", err)
	}
	return conversationID, nil
}

// RoleProfile returns one registered profile. Unregistered and legacy roles are
// indistinguishable from missing.
func (s *Store) RoleProfile(role string) (RoleProfile, error) {
	if !ValidRole(role) {
		return RoleProfile{}, ErrForbidden
	}
	var display sql.NullString
	var addressable int
	var updatedAt int64
	err := s.db.QueryRowContext(context.Background(), `SELECT display_name, direct_addressable, updated_at FROM role_profiles WHERE role = ?`, role).Scan(&display, &addressable, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RoleProfile{}, ErrForbidden
	}
	if err != nil {
		return RoleProfile{}, fmt.Errorf("read role profile: %w", err)
	}
	return RoleProfile{Role: role, DisplayName: display.String, DirectAddressable: addressable == 1, UpdatedAt: fromMillis(updatedAt)}, nil
}

const roleDirectoryOnlineSQL = `EXISTS (
		SELECT 1 FROM role_bindings AS binding
		JOIN endpoints AS endpoint ON endpoint.endpoint = binding.session_endpoint
			AND endpoint.machine_id = binding.machine_id
			AND endpoint.ownership_generation = binding.ownership_generation
		WHERE binding.role = profiles.role
			AND binding.machine_id = roles.machine_id
			AND binding.lease_until > ?
			AND endpoint.lease_until > ?
	)`

const listAddressableRolesSQL = `SELECT profiles.role, profiles.display_name, roles.machine_id, ` + roleDirectoryOnlineSQL + `
		FROM role_profiles AS profiles
		JOIN roles ON roles.role = profiles.role
		WHERE profiles.direct_addressable = 1 AND (? = '' OR profiles.role > ?)
		ORDER BY profiles.role ASC
		LIMIT ?`

const lookupAddressableContactSQL = `SELECT profiles.role, profiles.display_name, roles.machine_id, ` + roleDirectoryOnlineSQL + `
		FROM role_profiles AS profiles
		JOIN roles ON roles.role = profiles.role
		WHERE profiles.direct_addressable = 1 AND profiles.role = ?`

const resolveAddressableRoleSQL = `SELECT profiles.role, profiles.display_name, roles.machine_id, ` + roleDirectoryOnlineSQL + `
		FROM role_profiles AS profiles
		JOIN roles ON roles.role = profiles.role
		WHERE profiles.direct_addressable = 1 AND profiles.role LIKE ? ESCAPE '\'
		ORDER BY profiles.role ASC
		LIMIT ?`

func scanRoleContact(scanner interface {
	Scan(dest ...any) error
}) (RoleContact, error) {
	var contact RoleContact
	var display sql.NullString
	var online int
	if err := scanner.Scan(&contact.Role, &display, &contact.MachineID, &online); err != nil {
		return RoleContact{}, err
	}
	contact.DisplayName = display.String
	contact.Online = online == 1
	return contact, nil
}

// ListAddressableRoles returns one bounded page of opted-in public roles.
func (s *Store) ListAddressableRoles(input RoleListInput) (RoleListPage, error) {
	after, ok := DecodeRoleListCursor(input.Cursor)
	if !ok || input.Limit < 1 || input.Limit > MaxRoleListLimit {
		return RoleListPage{}, fmt.Errorf("invalid role directory request")
	}
	now := input.Now.UnixMilli()
	rows, err := s.db.QueryContext(context.Background(), listAddressableRolesSQL, now, now, after, after, input.Limit+1)
	if err != nil {
		return RoleListPage{}, fmt.Errorf("list addressable roles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var contacts []RoleContact
	for rows.Next() {
		contact, err := scanRoleContact(rows)
		if err != nil {
			return RoleListPage{}, err
		}
		contacts = append(contacts, contact)
	}
	if err := rows.Err(); err != nil {
		return RoleListPage{}, err
	}
	page := RoleListPage{Roles: contacts}
	if len(page.Roles) > input.Limit {
		last := page.Roles[input.Limit-1]
		page.Roles = page.Roles[:input.Limit]
		page.NextCursor = EncodeRoleListCursor(last.Role)
	}
	if page.Roles == nil {
		page.Roles = []RoleContact{}
	}
	return page, nil
}

func resolvedRoleContact(contact RoleContact, err error) (RoleResolveResult, error) {
	if errors.Is(err, ErrForbidden) {
		return RoleResolveResult{Status: RoleResolveNotFound}, nil
	}
	if err != nil {
		return RoleResolveResult{}, err
	}
	return RoleResolveResult{Status: RoleResolveResolved, Role: contact.Role, DisplayName: contact.DisplayName, MachineID: contact.MachineID, Online: contact.Online}, nil
}

func (s *Store) lookupAddressableContact(role string, now int64) (RoleContact, error) {
	row := s.db.QueryRowContext(context.Background(), lookupAddressableContactSQL, now, now, role)
	contact, err := scanRoleContact(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RoleContact{}, ErrForbidden
	}
	return contact, err
}

// ResolveAddressableRole answers one public name without guessing.
func (s *Store) ResolveAddressableRole(input RoleResolveInput) (RoleResolveResult, error) {
	name := strings.TrimSpace(input.Name)
	now := input.Now.UnixMilli()
	if CanonicalRoleHandle(name) {
		return resolvedRoleContact(s.lookupAddressableContact(name, now))
	}
	if !ValidRoleSlug(name) {
		return RoleResolveResult{Status: RoleResolveNotFound}, nil
	}
	like := "%/" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(name)
	rows, err := s.db.QueryContext(context.Background(), resolveAddressableRoleSQL, now, now, like, MaxRoleResolveMatches+1)
	if err != nil {
		return RoleResolveResult{}, fmt.Errorf("resolve addressable role: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var matches []RoleResolveMatch
	for rows.Next() {
		contact, err := scanRoleContact(rows)
		if err != nil {
			return RoleResolveResult{}, err
		}
		if slug, ok := CanonicalRoleSlug(contact.Role); !ok || slug != name {
			continue
		}
		matches = append(matches, RoleResolveMatch{Role: contact.Role, DisplayName: contact.DisplayName})
	}
	if err := rows.Err(); err != nil {
		return RoleResolveResult{}, err
	}
	switch {
	case len(matches) == 0:
		return RoleResolveResult{Status: RoleResolveNotFound}, nil
	case len(matches) == 1:
		return resolvedRoleContact(s.lookupAddressableContact(matches[0].Role, now))
	default:
		if len(matches) > MaxRoleResolveMatches {
			matches = matches[:MaxRoleResolveMatches]
		}
		return RoleResolveResult{Status: RoleResolveAmbiguous, Matches: matches}, nil
	}
}

type roleProfileIdempotency struct {
	requestHash string
	profile     RoleProfile
}

func readRoleProfileIdempotency(tx *sql.Tx, machineID, key string) (roleProfileIdempotency, bool, error) {
	var record roleProfileIdempotency
	var display sql.NullString
	var addressable, updatedAt int64
	err := tx.QueryRowContext(context.Background(), `SELECT request_hash, role, display_name, direct_addressable, updated_at FROM role_profile_idempotency WHERE machine_id = ? AND key = ?`, machineID, key).Scan(&record.requestHash, &record.profile.Role, &display, &addressable, &updatedAt)
	if err != nil {
		return roleProfileIdempotency{}, false, err
	}
	record.profile.DisplayName = display.String
	record.profile.DirectAddressable = addressable == 1
	record.profile.UpdatedAt = fromMillis(updatedAt)
	return record, true, nil
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
	if !ValidMachineID(input.MachineID) || !ValidRequestToken(input.IdempotencyKey) || input.ProjectID != "" {
		return Conversation{}, fmt.Errorf("machine and idempotency key are required")
	}
	return s.createConversation(input)
}

func (s *Store) createConversation(input CreateConversationInput) (Conversation, error) {
	creatorEndpoint := input.CreatorEndpoint
	members := input.Members
	now := input.Now
	displayName, err := SanitizeConversationDisplayName(input.DisplayName)
	if err != nil {
		return Conversation{}, err
	}
	if !ValidEndpoint(creatorEndpoint) || len(members) == 0 || len(members) > 256 {
		return Conversation{}, fmt.Errorf("creator and members are required")
	}
	seenEndpoints := make(map[string]struct{}, len(members))
	seenRoles := make(map[string]struct{}, len(members))
	creatorAdmin := false
	for _, member := range members {
		if member.Capabilities == 0 || member.Capabilities & ^(CapSend|CapReceive|CapAdmin|CapInvoke) != 0 {
			return Conversation{}, fmt.Errorf("invalid conversation member")
		}
		switch {
		case member.Endpoint != "" && member.Role == "" && member.RoleMachineID == "":
			if !ValidEndpoint(member.Endpoint) || ReservedRelayMember(member.Endpoint) {
				return Conversation{}, fmt.Errorf("invalid conversation member")
			}
			if _, duplicate := seenEndpoints[member.Endpoint]; duplicate {
				return Conversation{}, fmt.Errorf("duplicate conversation member")
			}
			seenEndpoints[member.Endpoint] = struct{}{}
			if member.Endpoint == creatorEndpoint && member.Capabilities&(CapSend|CapReceive|CapAdmin) == (CapSend|CapReceive|CapAdmin) {
				creatorAdmin = true
			}
		case member.Endpoint == "" && ValidRole(member.Role) && member.Role != TelegramUserParticipant && ValidMachineID(member.RoleMachineID):
			if member.Capabilities&CapInvoke != 0 {
				return Conversation{}, fmt.Errorf("invalid conversation member")
			}
			if _, duplicate := seenRoles[member.Role]; duplicate {
				return Conversation{}, fmt.Errorf("duplicate conversation member")
			}
			seenRoles[member.Role] = struct{}{}
		default:
			return Conversation{}, fmt.Errorf("invalid conversation member")
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
		requestHash := CreateConversationRequestHash(creatorEndpoint, members, displayName)
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
	for endpoint := range seenEndpoints {
		if err := endpointActive(tx, endpoint, now); err != nil {
			return Conversation{}, err
		}
	}
	if displayName != "" {
		if err := rejectExclusiveCreateOccupancy(tx, seenEndpoints, seenRoles, now); err != nil {
			return Conversation{}, err
		}
	}
	for _, member := range members {
		if member.Role == "" {
			continue
		}
		var owner string
		err := tx.QueryRowContext(context.Background(), "SELECT machine_id FROM roles WHERE role = ?", member.Role).Scan(&owner)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if _, err := tx.ExecContext(context.Background(), "INSERT INTO roles(role, machine_id) VALUES (?, ?)", member.Role, member.RoleMachineID); err != nil {
				return Conversation{}, fmt.Errorf("create durable role: %w", err)
			}
		case err != nil:
			return Conversation{}, fmt.Errorf("read durable role: %w", err)
		case owner != member.RoleMachineID:
			return Conversation{}, ErrForbidden
		}
	}
	conversation := Conversation{ID: uuid.NewString(), DisplayName: displayName}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO conversations(id, created_at, display_name) VALUES (?, ?, ?)", conversation.ID, now.UnixMilli(), nullableDisplayName(displayName)); err != nil {
		return Conversation{}, fmt.Errorf("create conversation: %w", err)
	}
	for _, member := range members {
		if member.Endpoint != "" {
			if _, err := tx.ExecContext(context.Background(), "INSERT INTO memberships(conversation_id, endpoint, capabilities) VALUES (?, ?, ?)", conversation.ID, member.Endpoint, member.Capabilities); err != nil {
				return Conversation{}, fmt.Errorf("add conversation member: %w", err)
			}
		} else if _, err := tx.ExecContext(context.Background(), "INSERT INTO role_memberships(conversation_id, role, capabilities) VALUES (?, ?, ?)", conversation.ID, member.Role, member.Capabilities); err != nil {
			return Conversation{}, fmt.Errorf("add durable role member: %w", err)
		}
	}
	if input.MachineID != "" {
		if _, err := tx.ExecContext(context.Background(), "INSERT INTO conversation_idempotency(machine_id, key, request_hash, conversation_id, created_at) VALUES (?, ?, ?, ?, ?)", input.MachineID, input.IdempotencyKey, CreateConversationRequestHash(creatorEndpoint, members, displayName), conversation.ID, now.UnixMilli()); err != nil {
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
	capabilities, err := sessionCapabilities(tx, conversationID, machineID, endpoint, now)
	if err != nil {
		return err
	}
	if capabilities&CapSend == 0 {
		return ErrForbidden
	}
	if err := rejectDirectConversationAppend(tx, conversationID); err != nil {
		return err
	}
	return tx.Commit()
}

// AppendMessage accepts one immutable, authorized message and creates one
// independent durable delivery per receiving endpoint, excluding the sender.
// Direct-role conversations are writable only through SendDirectMessage.
func (s *Store) AppendMessage(input AppendInput) (Message, bool, error) {
	if strings.TrimSpace(input.ConversationID) == "" || !ValidMachineID(input.SenderMachineID) || !ValidEndpoint(input.FromEndpoint) || (input.TargetRole != "" && !ValidRole(input.TargetRole)) || !ValidRequestToken(input.IdempotencyKey) || len(input.ArtifactIDs) != 0 {
		return Message{}, false, fmt.Errorf("conversation, machine, endpoint, and idempotency key are required")
	}
	if len(input.Body) > maxMessageBodyBytes {
		return Message{}, false, fmt.Errorf("message body exceeds %d bytes", maxMessageBodyBytes)
	}
	if !ValidMessageBody(input.Body) {
		return Message{}, false, errors.New("message body is not portable UTF-8 text")
	}
	requestHash := appendHash(input)
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Message{}, false, err
	}
	defer rollback(tx)
	capabilities, err := sessionCapabilities(tx, input.ConversationID, input.SenderMachineID, input.FromEndpoint, input.Now)
	if err != nil {
		return Message{}, false, err
	}
	if capabilities&CapSend == 0 {
		return Message{}, false, ErrForbidden
	}
	if err := rejectDirectConversationAppend(tx, input.ConversationID); err != nil {
		return Message{}, false, err
	}
	if input.TargetRole == TelegramUserParticipant {
		if err := requireCompleteTelegramClaim(tx, input.ConversationID); err != nil {
			return Message{}, false, err
		}
		var allowed bool
		if err := tx.QueryRowContext(context.Background(), "SELECT EXISTS(SELECT 1 FROM memberships WHERE conversation_id = ? AND endpoint = ? AND (capabilities & ?) != 0)", input.ConversationID, TelegramGatewayEndpoint, CapReceive).Scan(&allowed); err != nil {
			return Message{}, false, fmt.Errorf("authorize telegram participant: %w", err)
		}
		if !allowed {
			return Message{}, false, ErrForbidden
		}
	} else if input.TargetRole != "" {
		var allowed bool
		if err := tx.QueryRowContext(context.Background(), "SELECT EXISTS(SELECT 1 FROM role_memberships WHERE conversation_id = ? AND role = ? AND (capabilities & ?) != 0)", input.ConversationID, input.TargetRole, CapReceive).Scan(&allowed); err != nil {
			return Message{}, false, fmt.Errorf("authorize target role: %w", err)
		}
		if !allowed {
			return Message{}, false, ErrForbidden
		}
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
	if err := s.consumeRateLimits(tx, input.SenderMachineID, input.ConversationID, input.Now); err != nil {
		return Message{}, false, err
	}
	deliveryRecipients, err := appendDeliveryRecipients(tx, input.ConversationID, input.FromEndpoint, input.TargetRole)
	if err != nil {
		return Message{}, false, err
	}
	if err := s.consumeQuota(tx, deliveryRecipients, int64(len(input.Body))); err != nil {
		return Message{}, false, err
	}
	message := Message{ID: uuid.NewString(), ConversationID: input.ConversationID, FromEndpoint: input.FromEndpoint, Body: input.Body, CreatedAt: input.Now.UTC().Truncate(time.Millisecond)}
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
		if input.TargetRole == "" || (input.TargetRole == TelegramUserParticipant && endpoint == TelegramGatewayEndpoint) {
			if _, err := tx.ExecContext(context.Background(), "INSERT INTO deliveries(id, message_id, recipient_endpoint) VALUES (?, ?, ?)", uuid.NewString(), message.ID, endpoint); err != nil {
				return Message{}, false, fmt.Errorf("create delivery: %w", err)
			}
		} else if err := advanceRecipientCursor(tx, endpoint, input.ConversationID); err != nil {
			return Message{}, false, err
		}
	}
	roleRows, err := tx.QueryContext(context.Background(), "SELECT role FROM role_memberships WHERE conversation_id = ? AND (capabilities & ?) != 0", input.ConversationID, CapReceive)
	if err != nil {
		return Message{}, false, fmt.Errorf("find durable role recipients: %w", err)
	}
	var roles []string
	for roleRows.Next() {
		var role string
		if err := roleRows.Scan(&role); err != nil {
			_ = roleRows.Close()
			return Message{}, false, err
		}
		roles = append(roles, role)
	}
	if err := roleRows.Close(); err != nil {
		return Message{}, false, fmt.Errorf("find durable role recipients: %w", err)
	}
	for _, role := range roles {
		recipient := roleRecipient(role)
		if input.TargetRole == TelegramUserParticipant {
			if err := advanceRecipientCursor(tx, recipient, input.ConversationID); err != nil {
				return Message{}, false, err
			}
			continue
		}
		if input.TargetRole == "" || role == input.TargetRole {
			if _, err := tx.ExecContext(context.Background(), "INSERT INTO deliveries(id, message_id, recipient_endpoint) VALUES (?, ?, ?)", uuid.NewString(), message.ID, recipient); err != nil {
				return Message{}, false, fmt.Errorf("create durable role delivery: %w", err)
			}
		} else if err := advanceRecipientCursor(tx, recipient, input.ConversationID); err != nil {
			return Message{}, false, err
		}
	}
	if err := advanceSessionCursors(tx, input.SenderMachineID, input.FromEndpoint, input.ConversationID, input.Now); err != nil {
		return Message{}, false, err
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO idempotency(machine_id, key, request_hash, message_id, created_at) VALUES (?, ?, ?, ?, ?)", input.SenderMachineID, input.IdempotencyKey, requestHash, message.ID, input.Now.UnixMilli()); err != nil {
		return Message{}, false, fmt.Errorf("record idempotency key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Message{}, false, err
	}
	s.refreshPendingMetrics(input.Now)
	return message, false, nil
}

func (s *Store) consumeRateLimits(tx *sql.Tx, senderMachineID, conversationID string, now time.Time) error {
	cfg := s.rateLimitConfig()
	sender, err := loadRateBucket(tx, rateBucketSender, senderMachineID, now, int64(cfg.SenderBurst))
	if err != nil {
		return err
	}
	conversation, err := loadRateBucket(tx, rateBucketConversation, conversationID, now, int64(cfg.ConversationBurst))
	if err != nil {
		return err
	}
	decision := DecideRateLimit(cfg, sender, conversation, now)
	if !decision.Allowed {
		s.metrics.ObserveRateLimited()
		return &RateLimitedError{RetryAfterSeconds: decision.RetryAfterSeconds}
	}
	if err := saveRateBucket(tx, rateBucketSender, senderMachineID, decision.Sender); err != nil {
		return err
	}
	return saveRateBucket(tx, rateBucketConversation, conversationID, decision.Conversation)
}

func loadRateBucket(tx *sql.Tx, kind, key string, now time.Time, burst int64) (RateBucket, error) {
	now = now.UTC().Truncate(time.Millisecond)
	if _, err := tx.ExecContext(context.Background(), `INSERT OR IGNORE INTO rate_buckets(kind, bucket_key, tokens, updated_at) VALUES (?, ?, ?, ?)`, kind, key, burst, now.UnixMilli()); err != nil {
		return RateBucket{}, fmt.Errorf("initialize rate bucket: %w", err)
	}
	var tokens, updatedAt int64
	if err := tx.QueryRowContext(context.Background(), `SELECT tokens, updated_at FROM rate_buckets WHERE kind = ? AND bucket_key = ?`, kind, key).Scan(&tokens, &updatedAt); err != nil {
		return RateBucket{}, fmt.Errorf("read rate bucket: %w", err)
	}
	return RateBucket{Tokens: tokens, UpdatedAt: fromMillis(updatedAt)}, nil
}

func saveRateBucket(tx *sql.Tx, kind, key string, bucket RateBucket) error {
	if _, err := tx.ExecContext(context.Background(), `UPDATE rate_buckets SET tokens = ?, updated_at = ? WHERE kind = ? AND bucket_key = ?`, bucket.Tokens, bucket.UpdatedAt.UTC().Truncate(time.Millisecond).UnixMilli(), kind, key); err != nil {
		return fmt.Errorf("update rate bucket: %w", err)
	}
	return nil
}

// LeaseDeliveries leases a bounded page of pending deliveries for one active
// endpoint. A retry by the same machine receives its current lease; an expired
// lease receives a new token and monotonically increasing fence generation.
func (s *Store) LeaseDeliveries(machineID, consumerID, endpoint, conversationID string, now time.Time, ttl time.Duration, limit int) (DeliveryLeasePage, error) {
	if !ValidMachineID(machineID) || !ValidRequestToken(consumerID) || !ValidEndpoint(endpoint) || ttl <= 0 || limit < 1 || limit > 100 {
		return DeliveryLeasePage{}, fmt.Errorf("invalid delivery lease request")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return DeliveryLeasePage{}, err
	}
	defer rollback(tx)
	ownershipGeneration, err := endpointOwnership(tx, endpoint, machineID, now)
	if err != nil {
		return DeliveryLeasePage{}, err
	}
	recipientIDs, err := sessionRecipientIDs(tx, machineID, endpoint, ownershipGeneration, now)
	if err != nil {
		return DeliveryLeasePage{}, err
	}
	var activeConsumer sql.NullString
	var consumerGeneration int64
	var consumerUntil sql.NullInt64
	if err := tx.QueryRowContext(context.Background(), `SELECT consumer_id, consumer_generation, consumer_lease_until FROM endpoints WHERE endpoint = ?`, endpoint).Scan(&activeConsumer, &consumerGeneration, &consumerUntil); err != nil {
		return DeliveryLeasePage{}, fmt.Errorf("read endpoint consumer lease: %w", err)
	}
	if activeConsumer.Valid && activeConsumer.String != consumerID && consumerUntil.Valid && consumerUntil.Int64 > now.UnixMilli() {
		return DeliveryLeasePage{}, ErrConflict
	}
	if !activeConsumer.Valid || activeConsumer.String != consumerID || !consumerUntil.Valid || consumerUntil.Int64 <= now.UnixMilli() {
		consumerGeneration++
	}
	consumerLeaseUntil := now.Add(ttl).UTC()
	if _, err := tx.ExecContext(context.Background(), `UPDATE endpoints SET consumer_id = ?, consumer_generation = ?, consumer_lease_until = ? WHERE endpoint = ? AND ownership_generation = ?`, consumerID, consumerGeneration, consumerLeaseUntil.UnixMilli(), endpoint, ownershipGeneration); err != nil {
		return DeliveryLeasePage{}, fmt.Errorf("claim endpoint consumer lease: %w", err)
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(recipientIDs)), ",")
	query := `SELECT d.id, d.recipient_endpoint, d.lease_machine_id, d.lease_token, d.lease_generation, d.ownership_generation, d.consumer_generation, d.lease_until,
		m.id, m.conversation_id, m.sequence, m.from_endpoint, m.from_participant, m.in_reply_to_message_id, m.in_reply_to_endpoint, m.telegram_thread_id, m.body, m.created_at, sender.from_role
		FROM deliveries d JOIN messages m ON m.id = d.message_id
		LEFT JOIN message_from_roles sender ON sender.message_id = m.id
		WHERE d.recipient_endpoint IN (` + placeholders + `) AND d.acked_at IS NULL
		AND (d.lease_until IS NULL OR d.lease_until <= ? OR d.ownership_generation IS NULL OR d.ownership_generation <> ? OR d.consumer_generation IS NULL OR d.consumer_generation <> ? OR d.lease_machine_id = ?)` // #nosec G202 -- placeholders are generated only from bounded, server-derived recipient identities.
	args := make([]any, 0, len(recipientIDs)+5)
	for _, recipientID := range recipientIDs {
		args = append(args, recipientID)
	}
	args = append(args, now.UnixMilli(), ownershipGeneration, consumerGeneration, machineID)
	if conversationID != "" {
		query += " AND m.conversation_id = ? ORDER BY m.sequence, m.id"
		args = append(args, conversationID)
	} else {
		query += " ORDER BY m.created_at, m.conversation_id, m.sequence, m.id"
	}
	query += " LIMIT ?"
	args = append(args, limit)
	rows, err := tx.QueryContext(context.Background(), query, args...)
	if err != nil {
		return DeliveryLeasePage{}, fmt.Errorf("find deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var deliveries []Delivery
	var redeliveries int
	for rows.Next() {
		var delivery Delivery
		var leaseMachine, leaseToken sql.NullString
		var leaseUntil, leaseOwnership, leaseConsumer sql.NullInt64
		var createdAt int64
		var recipientID string
		var fromRole, fromParticipant, replyMessage, replyEndpoint sql.NullString
		var threadID sql.NullInt64
		if err := rows.Scan(&delivery.ID, &recipientID, &leaseMachine, &leaseToken, &delivery.LeaseGeneration, &leaseOwnership, &leaseConsumer, &leaseUntil, &delivery.Message.ID, &delivery.Message.ConversationID, &delivery.Message.Sequence, &delivery.Message.FromEndpoint, &fromParticipant, &replyMessage, &replyEndpoint, &threadID, &delivery.Message.Body, &createdAt, &fromRole); err != nil {
			return DeliveryLeasePage{}, err
		}
		applyMessageMetadata(&delivery.Message, fromParticipant, replyMessage, replyEndpoint, threadID)
		applyDirectSender(&delivery.Message, fromRole)
		delivery.RecipientEndpoint = endpoint
		if role, isRole := parseRoleRecipient(recipientID); isRole {
			delivery.RecipientRole = role
		}
		delivery.Message.CreatedAt = fromMillis(createdAt)
		if leaseMachine.Valid && leaseMachine.String == machineID && leaseToken.Valid && leaseOwnership.Valid && leaseOwnership.Int64 == ownershipGeneration && leaseConsumer.Valid && leaseConsumer.Int64 == consumerGeneration && leaseUntil.Valid && leaseUntil.Int64 > now.UnixMilli() {
			delivery.LeaseToken = leaseToken.String
			delivery.LeaseUntil = fromMillis(leaseUntil.Int64)
		} else {
			token, err := randomToken()
			if err != nil {
				return DeliveryLeasePage{}, err
			}
			if leaseUntil.Valid && leaseUntil.Int64 <= now.UnixMilli() {
				redeliveries++
			}
			delivery.LeaseGeneration++
			delivery.LeaseToken = token
			delivery.LeaseUntil = now.Add(ttl).UTC()
			if _, err := tx.ExecContext(context.Background(), `UPDATE deliveries SET lease_machine_id = ?, lease_token = ?, lease_generation = ?, ownership_generation = ?, consumer_generation = ?, lease_until = ? WHERE id = ?`, machineID, token, delivery.LeaseGeneration, ownershipGeneration, consumerGeneration, delivery.LeaseUntil.UnixMilli(), delivery.ID); err != nil {
				return DeliveryLeasePage{}, fmt.Errorf("lease delivery: %w", err)
			}
		}
		deliveries = append(deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return DeliveryLeasePage{}, err
	}
	if err := rows.Close(); err != nil {
		return DeliveryLeasePage{}, err
	}
	conversationIDs := make(map[string]struct{})
	if conversationID != "" {
		conversationIDs[conversationID] = struct{}{}
	}
	for _, delivery := range deliveries {
		conversationIDs[delivery.Message.ConversationID] = struct{}{}
	}
	cursors := make(map[string]int64, len(conversationIDs))
	for id := range conversationIDs {
		cursor, err := recipientCursorForLease(tx, recipientIDs, id)
		if err != nil {
			return DeliveryLeasePage{}, err
		}
		cursors[id] = cursor
	}
	if err := tx.Commit(); err != nil {
		return DeliveryLeasePage{}, err
	}
	s.metrics.ObserveLeaseRedeliveries(redeliveries)
	return DeliveryLeasePage{Deliveries: deliveries, Cursors: cursors}, nil
}

func recipientCursorForLease(tx *sql.Tx, recipientIDs []string, conversationID string) (int64, error) {
	var minimum int64
	found := false
	for _, recipientID := range recipientIDs {
		var capabilities Capability
		var err error
		if role, isRole := parseRoleRecipient(recipientID); isRole {
			err = tx.QueryRowContext(context.Background(), "SELECT capabilities FROM role_memberships WHERE conversation_id = ? AND role = ?", conversationID, role).Scan(&capabilities)
		} else {
			err = tx.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id = ? AND endpoint = ?", conversationID, recipientID).Scan(&capabilities)
		}
		if errors.Is(err, sql.ErrNoRows) || capabilities&CapReceive == 0 {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("authorize recipient cursor: %w", err)
		}
		var cursor int64
		err = tx.QueryRowContext(context.Background(), "SELECT sequence FROM recipient_cursors WHERE recipient_endpoint = ? AND conversation_id = ?", recipientID, conversationID).Scan(&cursor)
		if errors.Is(err, sql.ErrNoRows) {
			cursor = 0
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("read recipient cursor: %w", err)
		}
		if !found || cursor < minimum {
			minimum, found = cursor, true
		}
	}
	if !found {
		return 0, ErrForbidden
	}
	return minimum, nil
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
	recipientIDs, err := sessionRecipientIDs(tx, machineID, endpoint, ownershipGeneration, now)
	if err != nil {
		return err
	}
	var recipient, leaseMachine, leaseToken sql.NullString
	var leaseGeneration int64
	var leaseOwnership, leaseConsumer sql.NullInt64
	var leaseUntil, acknowledged sql.NullInt64
	err = tx.QueryRowContext(context.Background(), "SELECT recipient_endpoint, lease_machine_id, lease_token, lease_generation, ownership_generation, consumer_generation, lease_until, acked_at FROM deliveries WHERE id = ?", deliveryID).Scan(&recipient, &leaseMachine, &leaseToken, &leaseGeneration, &leaseOwnership, &leaseConsumer, &leaseUntil, &acknowledged)
	if errors.Is(err, sql.ErrNoRows) || !recipient.Valid || !containsString(recipientIDs, recipient.String) {
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
	result, err := tx.ExecContext(context.Background(), "UPDATE deliveries SET acked_at = ? WHERE id = ? AND acked_at IS NULL", now.UnixMilli(), deliveryID)
	if err != nil {
		return fmt.Errorf("acknowledge delivery: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("acknowledge delivery: %w", err)
	}
	var conversationID string
	var bodyBytes int64
	if err := tx.QueryRowContext(context.Background(), `SELECT message.conversation_id, length(CAST(message.body AS BLOB))
		FROM deliveries AS delivery JOIN messages AS message ON message.id = delivery.message_id
		WHERE delivery.id = ?`, deliveryID).Scan(&conversationID, &bodyBytes); err != nil {
		return fmt.Errorf("read delivery conversation: %w", err)
	}
	acked := 0
	if affected == 1 {
		if err := releaseQuota(tx, recipient.String, bodyBytes); err != nil {
			return err
		}
		if err := recordAckedTerminal(tx, deliveryID, now); err != nil {
			return err
		}
		acked = 1
	}
	if err := advanceRecipientCursor(tx, recipient.String, conversationID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.metrics.ObserveTerminals(ClosedAcked, acked)
	s.refreshPendingMetrics(now)
	return nil
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
	generation, err := endpointOwnership(tx, endpoint, machineID, now)
	if err != nil {
		return 0, err
	}
	recipientIDs, err := sessionRecipientIDs(tx, machineID, endpoint, generation, now)
	if err != nil {
		return 0, err
	}
	cursor, err := recipientCursorForLease(tx, recipientIDs, conversationID)
	if err != nil {
		return 0, err
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
	rows, err := s.db.QueryContext(context.Background(), `SELECT DISTINCT machine_id FROM (
		SELECT e.machine_id FROM deliveries d
		JOIN endpoints e ON e.endpoint = d.recipient_endpoint
		WHERE d.message_id = ? AND e.lease_until > ?
		UNION
		SELECT rb.machine_id FROM deliveries d
		JOIN role_bindings rb ON d.recipient_endpoint = ? || rb.role
		JOIN endpoints e ON e.endpoint = rb.session_endpoint
		WHERE d.message_id = ? AND rb.lease_until > ? AND e.machine_id = rb.machine_id
		  AND e.ownership_generation = rb.ownership_generation AND e.lease_until > ?
	) ORDER BY machine_id`, messageID, now.UnixMilli(), roleRecipient(""), messageID, now.UnixMilli(), now.UnixMilli())
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
	rows, err := s.db.QueryContext(context.Background(), `SELECT id, display_name FROM (
		SELECT c.id, c.display_name, c.created_at FROM conversations c
		JOIN memberships m ON m.conversation_id = c.id
		JOIN endpoints e ON e.endpoint = m.endpoint
		WHERE e.machine_id = ? AND e.lease_until > ?
		UNION
		SELECT c.id, c.display_name, c.created_at FROM conversations c
		JOIN role_memberships rm ON rm.conversation_id = c.id
		JOIN role_bindings rb ON rb.role = rm.role
		JOIN endpoints e ON e.endpoint = rb.session_endpoint
		WHERE rb.machine_id = ? AND rb.lease_until > ? AND e.machine_id = rb.machine_id
		  AND e.ownership_generation = rb.ownership_generation AND e.lease_until > ?
	) ORDER BY created_at ASC`, machineID, now.UnixMilli(), machineID, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("list machine conversations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var conversations []Conversation
	for rows.Next() {
		var conversation Conversation
		var displayName sql.NullString
		if err := rows.Scan(&conversation.ID, &displayName); err != nil {
			return nil, err
		}
		conversation.DisplayName = displayName.String
		conversations = append(conversations, conversation)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return conversations, nil
}

// roleRecipient is intentionally not a valid endpoint: the leading record
// separator makes durable role deliveries unambiguous even if an endpoint is
// named "role:...". This internal key is never exposed at the relay API.
func roleRecipient(role string) string { return "\x1erole:" + role }

func parseRoleRecipient(value string) (string, bool) {
	role, found := strings.CutPrefix(value, "\x1erole:")
	return role, found && ValidRole(role)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sessionCapabilities(tx *sql.Tx, conversationID, machineID, endpoint string, now time.Time) (Capability, error) {
	generation, err := endpointOwnership(tx, endpoint, machineID, now)
	if err != nil {
		return 0, err
	}
	var capabilities Capability
	if err := tx.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id = ? AND endpoint = ?", conversationID, endpoint).Scan(&capabilities); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("read endpoint conversation membership: %w", err)
	}
	rows, err := tx.QueryContext(context.Background(), `SELECT rm.capabilities FROM role_memberships rm
		JOIN role_bindings rb ON rb.role = rm.role
		WHERE rm.conversation_id = ? AND rb.machine_id = ? AND rb.session_endpoint = ?
		  AND rb.ownership_generation = ? AND rb.lease_until > ?`, conversationID, machineID, endpoint, generation, now.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("read durable role membership: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var roleCapabilities Capability
		if err := rows.Scan(&roleCapabilities); err != nil {
			return 0, err
		}
		capabilities |= roleCapabilities
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return capabilities, nil
}

func sessionRecipientIDs(tx *sql.Tx, machineID, endpoint string, generation int64, now time.Time) ([]string, error) {
	identities := []string{endpoint}
	rows, err := tx.QueryContext(context.Background(), `SELECT role FROM role_bindings
		WHERE machine_id = ? AND session_endpoint = ? AND ownership_generation = ? AND lease_until > ?`, machineID, endpoint, generation, now.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("read durable role bindings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		identities = append(identities, roleRecipient(role))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return identities, nil
}

func advanceSessionCursors(tx *sql.Tx, machineID, endpoint, conversationID string, now time.Time) error {
	if _, err := endpointOwnership(tx, endpoint, machineID, now); err != nil {
		return err
	}
	var capabilities Capability
	err := tx.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id = ? AND endpoint = ?", conversationID, endpoint).Scan(&capabilities)
	if errors.Is(err, sql.ErrNoRows) || capabilities&CapReceive == 0 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("authorize sender cursor: %w", err)
	}
	if err := advanceRecipientCursor(tx, endpoint, conversationID); err != nil {
		return err
	}
	return nil
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
	generation, _, err := endpointOwnershipUntil(tx, endpoint, machineID, now)
	return generation, err
}

func endpointOwnershipUntil(tx *sql.Tx, endpoint, machineID string, now time.Time) (int64, int64, error) {
	var owner string
	var until int64
	var generation int64
	err := tx.QueryRowContext(context.Background(), "SELECT machine_id, lease_until, ownership_generation FROM endpoints WHERE endpoint = ?", endpoint).Scan(&owner, &until, &generation)
	if errors.Is(err, sql.ErrNoRows) || owner != machineID || until <= now.UnixMilli() {
		return 0, 0, ErrForbidden
	}
	if err != nil {
		return 0, 0, fmt.Errorf("read endpoint ownership: %w", err)
	}
	return generation, until, nil
}

func messageByID(tx *sql.Tx, messageID string) (Message, error) {
	var message Message
	var createdAt int64
	var fromRole, fromParticipant, replyMessage, replyEndpoint sql.NullString
	var threadID sql.NullInt64
	err := tx.QueryRowContext(context.Background(), `SELECT m.id, m.conversation_id, m.sequence, m.from_endpoint, m.from_participant, m.in_reply_to_message_id, m.in_reply_to_endpoint, m.telegram_thread_id, m.body, m.created_at, sender.from_role
		FROM messages m LEFT JOIN message_from_roles sender ON sender.message_id = m.id
		WHERE m.id = ?`, messageID).Scan(&message.ID, &message.ConversationID, &message.Sequence, &message.FromEndpoint, &fromParticipant, &replyMessage, &replyEndpoint, &threadID, &message.Body, &createdAt, &fromRole)
	if err != nil {
		return Message{}, fmt.Errorf("read idempotent message: %w", err)
	}
	applyMessageMetadata(&message, fromParticipant, replyMessage, replyEndpoint, threadID)
	message.CreatedAt = fromMillis(createdAt)
	applyDirectSender(&message, fromRole)
	return message, nil
}

func applyDirectSender(message *Message, fromRole sql.NullString) {
	if fromRole.Valid && fromRole.String != "" {
		message.FromRole = fromRole.String
		message.FromEndpoint = ""
	}
}

func applyMessageMetadata(message *Message, fromParticipant, replyMessage, replyEndpoint sql.NullString, threadID sql.NullInt64) {
	if fromParticipant.Valid {
		message.FromParticipant = fromParticipant.String
	}
	if replyMessage.Valid {
		message.InReplyToPunaroMessageID = replyMessage.String
	}
	if replyEndpoint.Valid {
		message.InReplyToEndpoint = replyEndpoint.String
	}
	if threadID.Valid {
		message.TelegramThreadID = threadID.Int64
	}
}

func conversationByID(tx *sql.Tx, conversationID string) (Conversation, error) {
	var conversation Conversation
	var displayName sql.NullString
	if err := tx.QueryRowContext(context.Background(), "SELECT id, display_name FROM conversations WHERE id = ?", conversationID).Scan(&conversation.ID, &displayName); err != nil {
		return Conversation{}, fmt.Errorf("read idempotent conversation: %w", err)
	}
	conversation.DisplayName = displayName.String
	return conversation, nil
}

func exclusiveConversationPredicate(alias string) string {
	return "((" + alias + ".display_name IS NOT NULL AND " + alias + ".display_name <> '') OR EXISTS (SELECT 1 FROM telegram_claims WHERE conversation_id = " + alias + ".id))"
}

func conversationIsExclusive(tx *sql.Tx, conversationID string) (bool, error) {
	var exclusive bool
	err := tx.QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM conversations WHERE id = ? AND display_name IS NOT NULL AND display_name <> ''
	) OR EXISTS (SELECT 1 FROM telegram_claims WHERE conversation_id = ?)`, conversationID, conversationID).Scan(&exclusive)
	if err != nil {
		return false, fmt.Errorf("read conversation occupancy: %w", err)
	}
	var exists bool
	if err := tx.QueryRowContext(context.Background(), "SELECT EXISTS(SELECT 1 FROM conversations WHERE id = ?)", conversationID).Scan(&exists); err != nil {
		return false, fmt.Errorf("read conversation occupancy: %w", err)
	}
	if !exists {
		return false, ErrForbidden
	}
	return exclusive, nil
}

func sessionOccupiesOtherExclusiveConversation(tx *sql.Tx, endpoint, excludeConversationID string, now time.Time) error {
	if endpoint == TelegramPrimaryEndpoint {
		return nil
	}
	var occupied bool
	err := tx.QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM memberships AS membership
		JOIN conversations AS conversation ON conversation.id = membership.conversation_id
		WHERE membership.endpoint = ?
		  AND membership.conversation_id <> ?
		  AND `+exclusiveConversationPredicate("conversation")+`
		UNION ALL
		SELECT 1 FROM role_bindings AS binding
		JOIN role_memberships AS membership ON membership.role = binding.role
		JOIN conversations AS conversation ON conversation.id = membership.conversation_id
		JOIN endpoints AS live ON live.endpoint = binding.session_endpoint
		WHERE binding.session_endpoint = ?
		  AND binding.lease_until > ?
		  AND live.machine_id = binding.machine_id
		  AND live.ownership_generation = binding.ownership_generation
		  AND live.lease_until > ?
		  AND membership.conversation_id <> ?
		  AND `+exclusiveConversationPredicate("conversation")+`
	)`, endpoint, excludeConversationID, endpoint, now.UnixMilli(), now.UnixMilli(), excludeConversationID).Scan(&occupied)
	if err != nil {
		return fmt.Errorf("inspect exclusive conversation occupancy: %w", err)
	}
	if occupied {
		return ErrConflict
	}
	return nil
}

func rejectExclusiveCreateOccupancy(tx *sql.Tx, endpoints, roles map[string]struct{}, now time.Time) error {
	sessions := make(map[string]struct{}, len(endpoints)+len(roles))
	for endpoint := range endpoints {
		sessions[endpoint] = struct{}{}
	}
	for role := range roles {
		var session string
		err := tx.QueryRowContext(context.Background(), `SELECT binding.session_endpoint FROM role_bindings AS binding
			JOIN endpoints AS live ON live.endpoint = binding.session_endpoint
			WHERE binding.role = ? AND binding.lease_until > ?
			  AND live.machine_id = binding.machine_id
			  AND live.ownership_generation = binding.ownership_generation
			  AND live.lease_until > ?`, role, now.UnixMilli(), now.UnixMilli()).Scan(&session)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read live role occupancy: %w", err)
		}
		sessions[session] = struct{}{}
	}
	for session := range sessions {
		if err := sessionOccupiesOtherExclusiveConversation(tx, session, "", now); err != nil {
			return err
		}
	}
	return nil
}

func rejectExclusiveClaimOccupancy(tx *sql.Tx, conversationID string, now time.Time) error {
	return rejectExclusiveOccupants(tx, conversationID, now)
}

func rejectExclusiveRenameOccupancy(tx *sql.Tx, conversationID string, now time.Time) error {
	return rejectExclusiveOccupants(tx, conversationID, now)
}

func ensureTelegramGatewayMembership(tx *sql.Tx, conversationID string) error {
	var previous Capability
	err := tx.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?", conversationID, TelegramGatewayEndpoint).Scan(&previous)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(context.Background(), "INSERT INTO memberships(conversation_id, endpoint, capabilities) VALUES (?, ?, ?)", conversationID, TelegramGatewayEndpoint, TelegramGatewayCapabilities); err != nil {
			return fmt.Errorf("insert telegram gateway member: %w", err)
		}
		return advanceRecipientCursor(tx, TelegramGatewayEndpoint, conversationID)
	}
	if err != nil {
		return fmt.Errorf("read telegram gateway member: %w", err)
	}
	if previous != TelegramGatewayCapabilities {
		if _, err := tx.ExecContext(context.Background(), "UPDATE memberships SET capabilities=? WHERE conversation_id=? AND endpoint=?", TelegramGatewayCapabilities, conversationID, TelegramGatewayEndpoint); err != nil {
			return fmt.Errorf("clamp telegram gateway member: %w", err)
		}
	}
	if previous&CapReceive == 0 {
		return advanceRecipientCursor(tx, TelegramGatewayEndpoint, conversationID)
	}
	return nil
}

func rejectExclusiveOccupants(tx *sql.Tx, conversationID string, now time.Time) error {
	rows, err := tx.QueryContext(context.Background(), `SELECT endpoint FROM memberships WHERE conversation_id = ?
		UNION
		SELECT binding.session_endpoint FROM role_memberships AS membership
		JOIN role_bindings AS binding ON binding.role = membership.role
		JOIN endpoints AS live ON live.endpoint = binding.session_endpoint
		WHERE membership.conversation_id = ?
		  AND binding.lease_until > ?
		  AND live.machine_id = binding.machine_id
		  AND live.ownership_generation = binding.ownership_generation
		  AND live.lease_until > ?`, conversationID, conversationID, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return fmt.Errorf("list conversation occupants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var occupants []string
	for rows.Next() {
		var endpoint string
		if err := rows.Scan(&endpoint); err != nil {
			return fmt.Errorf("read conversation occupant: %w", err)
		}
		occupants = append(occupants, endpoint)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list conversation occupants: %w", err)
	}
	for _, endpoint := range occupants {
		if err := sessionOccupiesOtherExclusiveConversation(tx, endpoint, conversationID, now); err != nil {
			return err
		}
	}
	return nil
}

func rejectExclusiveBindOccupancy(tx *sql.Tx, sessionEndpoint, role string, now time.Time) error {
	if sessionEndpoint == TelegramPrimaryEndpoint {
		return nil
	}
	var count int
	err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM (
		SELECT membership.conversation_id AS id FROM memberships AS membership
		JOIN conversations AS conversation ON conversation.id = membership.conversation_id
		WHERE membership.endpoint = ?
		  AND `+exclusiveConversationPredicate("conversation")+`
		UNION
		SELECT membership.conversation_id FROM role_memberships AS membership
		JOIN conversations AS conversation ON conversation.id = membership.conversation_id
		JOIN role_bindings AS binding ON binding.role = membership.role
		JOIN endpoints AS live ON live.endpoint = binding.session_endpoint
		WHERE binding.session_endpoint = ?
		  AND binding.role <> ?
		  AND binding.lease_until > ?
		  AND live.machine_id = binding.machine_id
		  AND live.ownership_generation = binding.ownership_generation
		  AND live.lease_until > ?
		  AND `+exclusiveConversationPredicate("conversation")+`
		UNION
		SELECT membership.conversation_id FROM role_memberships AS membership
		JOIN conversations AS conversation ON conversation.id = membership.conversation_id
		WHERE membership.role = ?
		  AND `+exclusiveConversationPredicate("conversation")+`
	)`, sessionEndpoint, sessionEndpoint, role, now.UnixMilli(), now.UnixMilli(), role).Scan(&count)
	if err != nil {
		return fmt.Errorf("inspect role-binding occupancy: %w", err)
	}
	if count > 1 {
		return ErrConflict
	}
	return nil
}

func nullableDisplayName(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func createConversationHash(creatorEndpoint string, members []Member) string {
	hasRole := false
	for _, member := range members {
		hasRole = hasRole || member.Role != ""
	}
	if !hasRole {
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
	normalized := append([]Member(nil), members...)
	sort.Slice(normalized, func(left, right int) bool {
		leftID, rightID := memberIdentity(normalized[left]), memberIdentity(normalized[right])
		if leftID == rightID {
			return normalized[left].Capabilities < normalized[right].Capabilities
		}
		return leftID < rightID
	})
	parts := make([]string, 1, 1+len(normalized)*3)
	parts[0] = creatorEndpoint
	for _, member := range normalized {
		parts = append(parts, memberIdentity(member), member.RoleMachineID, fmt.Sprintf("%d", member.Capabilities))
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(digest[:])
}

func memberIdentity(member Member) string {
	if member.Role != "" {
		return roleRecipient(member.Role)
	}
	return "endpoint:" + member.Endpoint
}

func appendHash(input AppendInput) string {
	parts := []string{input.ConversationID, input.FromEndpoint, input.Body}
	// Preserve the exact pre-targeting hash for broadcasts so an accepted
	// request can be retried safely across an in-place upgrade.
	if input.TargetRole != "" {
		parts = append(parts, "target-role:"+input.TargetRole)
	}
	if len(input.ArtifactIDs) != 0 {
		parts = append(parts, input.PrincipalID)
		parts = append(parts, input.ArtifactIDs...)
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(digest[:])
}

func stableHash(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
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
