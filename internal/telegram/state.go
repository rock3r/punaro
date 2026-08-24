// Package telegram holds durable, content-free control state for the optional
// Telegram gateway. Bot text is never stored here.
package telegram

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	// sqlite is the content-free Telegram route and replay state driver.
	_ "modernc.org/sqlite"
)

// Stable persisted gateway failure classifications.
const (
	callbackTokenTTL  = 15 * time.Minute
	maxCallbackTokens = 100
)

// Claim execution phases persisted in claim_executions.
const (
	ClaimPhaseReserved       = "reserved"
	ClaimPhaseCreating       = "creating"
	ClaimPhaseTopicCreated   = "topic_created"
	ClaimPhaseAdopting       = "adopting"
	ClaimPhaseRoutePersisted = "route_persisted"
	ClaimPhaseComplete       = "complete"
)

var telegramOutboundLimit = 10000

const gatewayLegacyTarget = "__legacy_unattributed__"

// ClaimExecution is one gateway-local claim phase. It stores no mail bodies.
type ClaimExecution struct {
	ConversationID string
	ThreadID       int64
	ChatID         int64
	Phase          string
	DisplayName    string
	SkipReserve    bool
}

// OutboundRef maps one Telegram message back to a Punaro delivery identity.
type OutboundRef struct {
	ConversationID  string
	PunaroMessageID string
	FromEndpoint    string
}

// State owns durable, content-free Telegram replay and topic routing state.
type State struct{ db *sql.DB }

// Open creates the durable control-state database at database.
func Open(database string) (*State, error) {
	if strings.TrimSpace(database) == "" {
		return nil, fmt.Errorf("telegram state path is required")
	}
	if err := os.MkdirAll(filepath.Dir(database), 0o700); err != nil {
		return nil, fmt.Errorf("create telegram state directory: %w", err)
	}
	db, err := sql.Open("sqlite", database)
	if err != nil {
		return nil, err
	}
	for _, statement := range []string{
		"PRAGMA journal_mode = WAL", "PRAGMA busy_timeout = 5000",
		"CREATE TABLE IF NOT EXISTS processed_updates (update_id INTEGER PRIMARY KEY)",
		"CREATE TABLE IF NOT EXISTS topic_routes (chat_id INTEGER NOT NULL, thread_id INTEGER NOT NULL, conversation_id TEXT NOT NULL, PRIMARY KEY(chat_id, thread_id))",
		"CREATE UNIQUE INDEX IF NOT EXISTS topic_routes_conversation ON topic_routes(conversation_id)",
		"CREATE TABLE IF NOT EXISTS callback_tokens (token_hash TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER)",
		"CREATE TABLE IF NOT EXISTS claim_executions (conversation_id TEXT PRIMARY KEY, thread_id INTEGER, phase TEXT NOT NULL, display_name TEXT, skip_reserve INTEGER NOT NULL DEFAULT 0, chat_id INTEGER)",
		"CREATE TABLE IF NOT EXISTS telegram_outbound (chat_id INTEGER NOT NULL, message_id INTEGER NOT NULL, conversation_id TEXT NOT NULL, punaro_message_id TEXT NOT NULL, from_endpoint TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (chat_id, message_id))",
		"CREATE TABLE IF NOT EXISTS gateway_cursors (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
		`CREATE TABLE IF NOT EXISTS gateway_health (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			last_cycle_at INTEGER NOT NULL,
			last_success_at INTEGER,
			last_poll_at INTEGER,
			last_relay_at INTEGER,
			last_telegram_at INTEGER,
			last_progress_at INTEGER NOT NULL,
			last_outbound_progress_at INTEGER,
			offset INTEGER NOT NULL,
			outbound_blocked INTEGER NOT NULL DEFAULT 0,
			consecutive_failures INTEGER NOT NULL,
			last_failure TEXT NOT NULL,
			terminal_inbound INTEGER NOT NULL,
			terminal_outbound INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gateway_terminal_outbound_targets (
			conversation_id TEXT PRIMARY KEY,
			failures INTEGER NOT NULL CHECK (failures > 0),
			failure_class TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gateway_terminal_inbound_targets (
			conversation_id TEXT PRIMARY KEY,
			failures INTEGER NOT NULL CHECK (failures > 0)
		)`,
		`CREATE TABLE IF NOT EXISTS gateway_terminal_outbound_events (
			delivery_id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			failure_class TEXT NOT NULL
		)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize telegram state: %w", err)
		}
	}
	if err := ensureClaimExecutionChatID(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize telegram state: %w", err)
	}
	if err := ensureGatewayHealthOutboundProgress(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize telegram state: %w", err)
	}
	if err := ensureGatewayTerminalTargetLedgers(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize telegram state: %w", err)
	}
	return &State{db: db}, nil
}

// GatewayFailureClass is a closed, content-free retry outcome persisted for
// doctor. It never contains provider text or message identifiers.
type GatewayFailureClass string

// Stable persisted gateway failure classifications.
const (
	GatewayFailureNone                      GatewayFailureClass = ""
	GatewayFailureTransient                 GatewayFailureClass = "transient"
	GatewayFailureMessageLessPoll           GatewayFailureClass = "message_less_poll"
	GatewayFailureInboundRelayPermanent     GatewayFailureClass = "inbound_relay_permanent"
	GatewayFailureOutboundTelegramPermanent GatewayFailureClass = "outbound_telegram_permanent"
	GatewayFailureDeletedTopic              GatewayFailureClass = "deleted_topic"
)

// GatewayTargetEvent records content-free evidence that a conversation target
// either rejected an operation terminally or later accepted one.
type GatewayTargetEvent struct {
	ConversationID string
	Terminal       bool
	Staged         bool
	Failure        GatewayFailureClass
}

// GatewayInboundTargetEvent is conversation-scoped inbound health evidence.
type GatewayInboundTargetEvent = GatewayTargetEvent

// GatewayOutboundTargetEvent is conversation-scoped outbound health evidence.
type GatewayOutboundTargetEvent = GatewayTargetEvent

// GatewayCycleRecord contains only content-free cycle health evidence.
type GatewayCycleRecord struct {
	At                   time.Time
	Offset               int64
	PollOK               bool
	RelayOK              bool
	TelegramOK           bool
	OutboundBlocked      bool
	OutboundProgress     bool
	TerminalInbound      int
	TerminalOutbound     int
	InboundTargetEvents  []GatewayInboundTargetEvent
	OutboundTargetEvents []GatewayOutboundTargetEvent
	Failure              GatewayFailureClass
}

// GatewayStateSnapshot is the bounded, content-free state used by doctor.
type GatewayStateSnapshot struct {
	Integrity           bool
	RoutesConsistent    bool
	HasHealth           bool
	HasSuccess          bool
	HasPoll             bool
	HasRelay            bool
	HasTelegram         bool
	RouteCount          int
	IncompleteClaims    int
	LastCycleAge        time.Duration
	LastSuccessAge      time.Duration
	LastPollAge         time.Duration
	LastRelayAge        time.Duration
	LastTelegramAge     time.Duration
	ConsecutiveFailures int
	LastFailure         GatewayFailureClass
	TerminalInbound     int
	TerminalOutbound    int
	DeletedTopicTargets int
	StuckHead           bool
}

func validGatewayFailure(class GatewayFailureClass) bool {
	switch class {
	case GatewayFailureNone, GatewayFailureTransient, GatewayFailureMessageLessPoll, GatewayFailureInboundRelayPermanent, GatewayFailureOutboundTelegramPermanent, GatewayFailureDeletedTopic:
		return true
	default:
		return false
	}
}

// RecordGatewayCycle updates the content-free liveness ledger during normal
// gateway operation. Doctor itself never calls this method.
func (s *State) RecordGatewayCycle(record GatewayCycleRecord) error {
	if record.At.IsZero() || record.Offset < 0 || record.OutboundProgress && !record.OutboundBlocked || record.TerminalInbound < 0 || record.TerminalOutbound < 0 || record.Failure == GatewayFailureNone && (record.TerminalInbound > 0 || record.TerminalOutbound > 0) || !validGatewayFailure(record.Failure) {
		return fmt.Errorf("invalid gateway cycle record")
	}
	inboundTerminalEvents, outboundTerminalEvents := 0, 0
	for _, event := range record.InboundTargetEvents {
		if strings.TrimSpace(event.ConversationID) == "" {
			return fmt.Errorf("invalid gateway cycle record")
		}
		if event.Staged && !event.Terminal {
			return fmt.Errorf("invalid gateway cycle record")
		}
		if event.Terminal {
			inboundTerminalEvents++
			if event.Failure != GatewayFailureNone && event.Failure != GatewayFailureInboundRelayPermanent {
				return fmt.Errorf("invalid gateway cycle record")
			}
		}
	}
	for _, event := range record.OutboundTargetEvents {
		if strings.TrimSpace(event.ConversationID) == "" {
			return fmt.Errorf("invalid gateway cycle record")
		}
		if event.Terminal {
			outboundTerminalEvents++
			if event.Failure != GatewayFailureNone && event.Failure != GatewayFailureOutboundTelegramPermanent && event.Failure != GatewayFailureDeletedTopic {
				return fmt.Errorf("invalid gateway cycle record")
			}
		}
		if event.Staged && !event.Terminal {
			return fmt.Errorf("invalid gateway cycle record")
		}
	}
	now := record.At.UTC().UnixMilli()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var previousOffset, previousProgress int64
	var previousConsecutive, previousTerminalInbound, previousTerminalOutbound int
	var previousFailure string
	var previousOutboundProgress sql.NullInt64
	var previousOutboundBlocked bool
	err = tx.QueryRowContext(context.Background(), `SELECT offset,last_progress_at,last_outbound_progress_at,outbound_blocked,consecutive_failures,last_failure,terminal_inbound,terminal_outbound FROM gateway_health WHERE id = 1`).Scan(&previousOffset, &previousProgress, &previousOutboundProgress, &previousOutboundBlocked, &previousConsecutive, &previousFailure, &previousTerminalInbound, &previousTerminalOutbound)
	first := errors.Is(err, sql.ErrNoRows)
	if err != nil && !first {
		return err
	}
	progressAt := now
	if !first && previousOffset == record.Offset {
		progressAt = previousProgress
	}
	outboundBlocked := record.OutboundBlocked
	if !first && previousOutboundBlocked && record.Failure != GatewayFailureNone && !record.OutboundProgress {
		// A failure before the outbound phase cannot prove that the known
		// unacknowledged head advanced. Preserve its durable age until a full
		// successful cycle or explicit outbound progress does prove that.
		outboundBlocked = true
	}
	outboundProgressAt := now
	if !first && outboundBlocked && !record.OutboundProgress && previousOutboundBlocked {
		if previousOutboundProgress.Valid {
			outboundProgressAt = previousOutboundProgress.Int64
		} else {
			outboundProgressAt = previousProgress
		}
	}
	successAt, pollAt, relayAt, telegramAt := any(nil), any(nil), any(nil), any(nil)
	if record.Failure == GatewayFailureNone {
		successAt = now
	}
	if record.PollOK {
		pollAt = now
	}
	if record.RelayOK {
		relayAt = now
	}
	if record.TelegramOK {
		telegramAt = now
	}
	inboundDelta, outboundDelta := record.TerminalInbound, record.TerminalOutbound
	if inboundDelta == 0 && record.Failure == GatewayFailureInboundRelayPermanent {
		inboundDelta = 1
	}
	if outboundDelta == 0 && (record.Failure == GatewayFailureOutboundTelegramPermanent || record.Failure == GatewayFailureDeletedTopic) {
		outboundDelta = 1
	}
	if inboundTerminalEvents > inboundDelta || outboundTerminalEvents > outboundDelta {
		return fmt.Errorf("invalid gateway cycle record")
	}
	if unmatched := inboundDelta - inboundTerminalEvents; unmatched > 0 {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_inbound_targets(conversation_id,failures) VALUES(?,?) ON CONFLICT(conversation_id) DO UPDATE SET failures=failures+excluded.failures`, gatewayLegacyTarget, unmatched); err != nil {
			return err
		}
	}
	for _, event := range record.InboundTargetEvents {
		if event.Terminal {
			if event.Staged {
				continue
			}
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_inbound_targets(conversation_id,failures) VALUES(?,1) ON CONFLICT(conversation_id) DO UPDATE SET failures=failures+1`, event.ConversationID); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM gateway_terminal_inbound_targets WHERE conversation_id IN (?,?)`, event.ConversationID, gatewayLegacyTarget); err != nil {
			return err
		}
	}
	if unmatched := outboundDelta - outboundTerminalEvents; unmatched > 0 {
		class := record.Failure
		if class != GatewayFailureDeletedTopic {
			class = GatewayFailureOutboundTelegramPermanent
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_outbound_targets(conversation_id,failures,failure_class) VALUES(?,?,?) ON CONFLICT(conversation_id) DO UPDATE SET failures=failures+excluded.failures,failure_class=CASE WHEN failure_class='deleted_topic' OR excluded.failure_class='deleted_topic' THEN 'deleted_topic' ELSE 'outbound_telegram_permanent' END`, gatewayLegacyTarget, unmatched, string(class)); err != nil {
			return err
		}
	}
	for _, event := range record.OutboundTargetEvents {
		if event.Terminal {
			if event.Staged {
				continue
			}
			class := event.Failure
			if class == GatewayFailureNone {
				class = record.Failure
			}
			if class != GatewayFailureDeletedTopic {
				class = GatewayFailureOutboundTelegramPermanent
			}
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_outbound_targets(conversation_id,failures,failure_class) VALUES(?,1,?) ON CONFLICT(conversation_id) DO UPDATE SET failures=failures+1,failure_class=CASE WHEN failure_class='deleted_topic' OR excluded.failure_class='deleted_topic' THEN 'deleted_topic' ELSE 'outbound_telegram_permanent' END`, event.ConversationID, string(class)); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM gateway_terminal_outbound_targets WHERE conversation_id IN (?,?)`, event.ConversationID, gatewayLegacyTarget); err != nil {
			return err
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM gateway_terminal_outbound_events WHERE conversation_id=?`, event.ConversationID); err != nil {
			return err
		}
	}
	var terminalInbound, terminalOutbound, deletedTopicTargets int
	if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(failures), 0) FROM gateway_terminal_inbound_targets`).Scan(&terminalInbound); err != nil {
		return err
	}
	if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(failures), 0) FROM gateway_terminal_outbound_targets`).Scan(&terminalOutbound); err != nil {
		return err
	}
	if err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM gateway_terminal_outbound_targets WHERE failure_class=?`, string(GatewayFailureDeletedTopic)).Scan(&deletedTopicTargets); err != nil {
		return err
	}
	effectiveFailure := record.Failure
	if effectiveFailure == GatewayFailureNone && (terminalInbound > 0 || terminalOutbound > 0) {
		switch {
		case deletedTopicTargets > 0:
			effectiveFailure = GatewayFailureDeletedTopic
		case terminalOutbound > 0:
			effectiveFailure = GatewayFailureOutboundTelegramPermanent
		default:
			effectiveFailure = GatewayFailureInboundRelayPermanent
		}
	}
	consecutiveFailures := 0
	if record.Failure != GatewayFailureNone {
		consecutiveFailures = previousConsecutive + 1
	} else if effectiveFailure != GatewayFailureNone {
		consecutiveFailures = previousConsecutive
	}
	_, err = tx.ExecContext(context.Background(), `INSERT INTO gateway_health(
		id,last_cycle_at,last_success_at,last_poll_at,last_relay_at,last_telegram_at,last_progress_at,last_outbound_progress_at,offset,outbound_blocked,consecutive_failures,last_failure,terminal_inbound,terminal_outbound
	) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?)
	ON CONFLICT(id) DO UPDATE SET
		last_cycle_at=excluded.last_cycle_at,
		last_success_at=COALESCE(excluded.last_success_at,gateway_health.last_success_at),
		last_poll_at=COALESCE(excluded.last_poll_at,gateway_health.last_poll_at),
		last_relay_at=COALESCE(excluded.last_relay_at,gateway_health.last_relay_at),
		last_telegram_at=COALESCE(excluded.last_telegram_at,gateway_health.last_telegram_at),
		last_progress_at=excluded.last_progress_at,
		last_outbound_progress_at=excluded.last_outbound_progress_at,
		offset=excluded.offset,
		outbound_blocked=excluded.outbound_blocked,
		consecutive_failures=excluded.consecutive_failures,
		last_failure=excluded.last_failure,
		terminal_inbound=excluded.terminal_inbound,
		terminal_outbound=excluded.terminal_outbound`,
		now, successAt, pollAt, relayAt, telegramAt, progressAt, outboundProgressAt, record.Offset, outboundBlocked, consecutiveFailures, string(effectiveFailure), terminalInbound, terminalOutbound)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// InspectGatewayState opens the database read-only and returns bounded
// aggregates. It does not initialize, migrate, checkpoint, or repair state.
func InspectGatewayState(parent context.Context, database string, now time.Time) (GatewayStateSnapshot, error) {
	if parent == nil || !filepath.IsAbs(database) || now.IsZero() {
		return GatewayStateSnapshot{}, fmt.Errorf("invalid gateway state inspection")
	}
	uri := (&url.URL{Scheme: "file", Path: database, RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return GatewayStateSnapshot{}, fmt.Errorf("gateway state unavailable")
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `PRAGMA query_only = ON`); err != nil {
		return GatewayStateSnapshot{}, fmt.Errorf("gateway state unavailable")
	}
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA quick_check(1)`).Scan(&integrity); err != nil {
		return GatewayStateSnapshot{}, fmt.Errorf("gateway state unavailable")
	}
	snapshot := GatewayStateSnapshot{Integrity: integrity == "ok", RoutesConsistent: true}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM topic_routes`).Scan(&snapshot.RouteCount); err != nil {
		return GatewayStateSnapshot{}, fmt.Errorf("gateway state unavailable")
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM claim_executions WHERE phase != ?`, ClaimPhaseComplete).Scan(&snapshot.IncompleteClaims); err != nil {
		return GatewayStateSnapshot{}, fmt.Errorf("gateway state unavailable")
	}
	var inconsistent int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM claim_executions c
		LEFT JOIN topic_routes r ON r.conversation_id = c.conversation_id
		WHERE c.phase IN (?, ?) AND (r.conversation_id IS NULL OR c.thread_id IS NULL OR c.thread_id <= 0 OR r.thread_id != c.thread_id OR c.chat_id IS NOT NULL AND r.chat_id != c.chat_id)`, ClaimPhaseRoutePersisted, ClaimPhaseComplete).Scan(&inconsistent); err != nil {
		return GatewayStateSnapshot{}, fmt.Errorf("gateway state unavailable")
	}
	snapshot.RoutesConsistent = inconsistent == 0
	var cycle, success, poll, relayAt, telegramAt, progress, outboundProgress sql.NullInt64
	var outboundBlocked bool
	var lastFailure string
	err = db.QueryRowContext(ctx, `SELECT last_cycle_at,last_success_at,last_poll_at,last_relay_at,last_telegram_at,last_progress_at,last_outbound_progress_at,outbound_blocked,consecutive_failures,last_failure,terminal_inbound,terminal_outbound FROM gateway_health WHERE id=1`).Scan(
		&cycle, &success, &poll, &relayAt, &telegramAt, &progress, &outboundProgress, &outboundBlocked, &snapshot.ConsecutiveFailures, &lastFailure, &snapshot.TerminalInbound, &snapshot.TerminalOutbound)
	if errors.Is(err, sql.ErrNoRows) {
		if err := inspectGatewayTerminalLedgers(ctx, db, &snapshot, GatewayFailureNone); err != nil {
			return GatewayStateSnapshot{}, fmt.Errorf("gateway state unavailable")
		}
		return snapshot, nil
	}
	if err != nil || !validGatewayFailure(GatewayFailureClass(lastFailure)) {
		return GatewayStateSnapshot{}, fmt.Errorf("gateway state unavailable")
	}
	if err := inspectGatewayTerminalLedgers(ctx, db, &snapshot, GatewayFailureClass(lastFailure)); err != nil {
		return GatewayStateSnapshot{}, fmt.Errorf("gateway state unavailable")
	}
	snapshot.HasHealth = true
	snapshot.HasSuccess = success.Valid
	snapshot.HasPoll = poll.Valid
	snapshot.HasRelay = relayAt.Valid
	snapshot.HasTelegram = telegramAt.Valid
	snapshot.LastFailure = GatewayFailureClass(lastFailure)
	now = now.UTC()
	for _, value := range []sql.NullInt64{cycle, success, poll, relayAt, telegramAt, progress, outboundProgress} {
		if value.Valid && time.UnixMilli(value.Int64).After(now) {
			return GatewayStateSnapshot{}, fmt.Errorf("gateway state unavailable")
		}
	}
	age := func(value sql.NullInt64) time.Duration {
		if !value.Valid {
			return 0
		}
		return now.Sub(time.UnixMilli(value.Int64))
	}
	snapshot.LastCycleAge = age(cycle)
	snapshot.LastSuccessAge = age(success)
	snapshot.LastPollAge = age(poll)
	snapshot.LastRelayAge = age(relayAt)
	snapshot.LastTelegramAge = age(telegramAt)
	stuckProgress := progress
	if outboundBlocked {
		stuckProgress = outboundProgress
	}
	snapshot.StuckHead = snapshot.ConsecutiveFailures >= 3 && stuckProgress.Valid && age(stuckProgress) >= 5*time.Minute
	return snapshot, nil
}

func inspectGatewayTerminalLedgers(ctx context.Context, db *sql.DB, snapshot *GatewayStateSnapshot, lastFailure GatewayFailureClass) error {
	var inboundTables int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='gateway_terminal_inbound_targets'`).Scan(&inboundTables); err != nil {
		return err
	}
	if inboundTables > 0 {
		if err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(failures),0) FROM gateway_terminal_inbound_targets`).Scan(&snapshot.TerminalInbound); err != nil {
			return err
		}
	}
	var outboundTables int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='gateway_terminal_outbound_targets'`).Scan(&outboundTables); err != nil {
		return err
	}
	if outboundTables == 0 {
		if lastFailure == GatewayFailureDeletedTopic && snapshot.TerminalOutbound > 0 {
			snapshot.DeletedTopicTargets = 1
		}
		return nil
	}
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(SUM(failures),0) FROM gateway_terminal_outbound_targets`).Scan(&snapshot.TerminalOutbound); err != nil {
		return err
	}
	var classColumns int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('gateway_terminal_outbound_targets') WHERE name='failure_class'`).Scan(&classColumns); err != nil {
		return err
	}
	if classColumns == 0 {
		if lastFailure == GatewayFailureDeletedTopic && snapshot.TerminalOutbound > 0 {
			snapshot.DeletedTopicTargets = 1
		}
		return nil
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM gateway_terminal_outbound_targets WHERE failure_class=?`, string(GatewayFailureDeletedTopic)).Scan(&snapshot.DeletedTopicTargets); err != nil {
		return err
	}
	var invalidTargetClasses int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM gateway_terminal_outbound_targets WHERE failure_class NOT IN (?,?)`, string(GatewayFailureOutboundTelegramPermanent), string(GatewayFailureDeletedTopic)).Scan(&invalidTargetClasses); err != nil || invalidTargetClasses != 0 {
		return fmt.Errorf("invalid terminal outbound target class")
	}
	return nil
}

func ensureGatewayTerminalTargetLedgers(db *sql.DB) error {
	var classColumns int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('gateway_terminal_outbound_targets') WHERE name='failure_class'`).Scan(&classColumns); err != nil {
		return err
	}
	if classColumns == 0 {
		if _, err := db.ExecContext(context.Background(), `ALTER TABLE gateway_terminal_outbound_targets ADD COLUMN failure_class TEXT NOT NULL DEFAULT 'outbound_telegram_permanent'`); err != nil {
			return err
		}
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var terminalInbound, terminalOutbound int
	var lastFailure string
	err = tx.QueryRowContext(context.Background(), `SELECT terminal_inbound,terminal_outbound,last_failure FROM gateway_health WHERE id=1`).Scan(&terminalInbound, &terminalOutbound, &lastFailure)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	if classColumns == 0 && GatewayFailureClass(lastFailure) == GatewayFailureDeletedTopic {
		if _, err := tx.ExecContext(context.Background(), `UPDATE gateway_terminal_outbound_targets SET failure_class=?`, string(GatewayFailureDeletedTopic)); err != nil {
			return err
		}
	}
	var routes []string
	rows, err := tx.QueryContext(context.Background(), `SELECT conversation_id FROM topic_routes ORDER BY conversation_id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var conversationID string
		if err := rows.Scan(&conversationID); err != nil {
			_ = rows.Close()
			return err
		}
		routes = append(routes, conversationID)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var trackedInbound, trackedOutbound int
	if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(failures),0) FROM gateway_terminal_inbound_targets`).Scan(&trackedInbound); err != nil {
		return err
	}
	if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(failures),0) FROM gateway_terminal_outbound_targets`).Scan(&trackedOutbound); err != nil {
		return err
	}
	if len(routes) > 0 {
		var legacyInbound int
		if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(failures),0) FROM gateway_terminal_inbound_targets WHERE conversation_id=?`, gatewayLegacyTarget).Scan(&legacyInbound); err != nil {
			return err
		}
		if legacyInbound > 0 {
			if _, err := tx.ExecContext(context.Background(), `DELETE FROM gateway_terminal_inbound_targets WHERE conversation_id=?`, gatewayLegacyTarget); err != nil {
				return err
			}
			for _, conversationID := range routes {
				if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_inbound_targets(conversation_id,failures) VALUES(?,1) ON CONFLICT(conversation_id) DO NOTHING`, conversationID); err != nil {
					return err
				}
			}
			if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(failures),0) FROM gateway_terminal_inbound_targets`).Scan(&trackedInbound); err != nil {
				return err
			}
		}
		var legacyOutbound int
		var legacyOutboundClass string
		err := tx.QueryRowContext(context.Background(), `SELECT failures,failure_class FROM gateway_terminal_outbound_targets WHERE conversation_id=?`, gatewayLegacyTarget).Scan(&legacyOutbound, &legacyOutboundClass)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if legacyOutbound > 0 {
			if _, err := tx.ExecContext(context.Background(), `DELETE FROM gateway_terminal_outbound_targets WHERE conversation_id=?`, gatewayLegacyTarget); err != nil {
				return err
			}
			if !validGatewayFailure(GatewayFailureClass(legacyOutboundClass)) || GatewayFailureClass(legacyOutboundClass) != GatewayFailureDeletedTopic {
				legacyOutboundClass = string(GatewayFailureOutboundTelegramPermanent)
			}
			for _, conversationID := range routes {
				if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_outbound_targets(conversation_id,failures,failure_class) VALUES(?,1,?) ON CONFLICT(conversation_id) DO NOTHING`, conversationID, legacyOutboundClass); err != nil {
					return err
				}
			}
			if err := tx.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(failures),0) FROM gateway_terminal_outbound_targets`).Scan(&trackedOutbound); err != nil {
				return err
			}
		}
	}
	if terminalInbound > 0 && trackedInbound == 0 {
		if len(routes) == 0 {
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_inbound_targets(conversation_id,failures) VALUES(?,?)`, gatewayLegacyTarget, terminalInbound); err != nil {
				return err
			}
			trackedInbound = terminalInbound
		} else {
			for _, conversationID := range routes {
				if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_inbound_targets(conversation_id,failures) VALUES(?,1)`, conversationID); err != nil {
					return err
				}
			}
			trackedInbound = len(routes)
		}
	}
	if terminalOutbound > 0 && trackedOutbound == 0 {
		class := GatewayFailureOutboundTelegramPermanent
		if GatewayFailureClass(lastFailure) == GatewayFailureDeletedTopic {
			class = GatewayFailureDeletedTopic
		}
		if len(routes) == 0 {
			if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_outbound_targets(conversation_id,failures,failure_class) VALUES(?,?,?)`, gatewayLegacyTarget, terminalOutbound, string(class)); err != nil {
				return err
			}
			trackedOutbound = terminalOutbound
		} else {
			for _, conversationID := range routes {
				if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_outbound_targets(conversation_id,failures,failure_class) VALUES(?,1,?)`, conversationID, string(class)); err != nil {
					return err
				}
			}
			trackedOutbound = len(routes)
		}
	}
	if _, err := tx.ExecContext(context.Background(), `UPDATE gateway_health SET terminal_inbound=?,terminal_outbound=? WHERE id=1`, trackedInbound, trackedOutbound); err != nil {
		return err
	}
	return tx.Commit()
}

func ensureGatewayHealthOutboundProgress(db *sql.DB) error {
	for _, column := range []struct {
		name      string
		statement string
	}{
		{name: "last_outbound_progress_at", statement: "ALTER TABLE gateway_health ADD COLUMN last_outbound_progress_at INTEGER"},
		{name: "outbound_blocked", statement: "ALTER TABLE gateway_health ADD COLUMN outbound_blocked INTEGER NOT NULL DEFAULT 0"},
	} {
		var count int
		if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('gateway_health') WHERE name = ?`, column.name).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			if _, err := db.ExecContext(context.Background(), column.statement); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureClaimExecutionChatID(db *sql.DB) error {
	var count int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pragma_table_info('claim_executions') WHERE name = 'chat_id'`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err := db.ExecContext(context.Background(), `ALTER TABLE claim_executions ADD COLUMN chat_id INTEGER`)
	return err
}

// Close closes the durable Telegram state database.
func (s *State) Close() error { return s.db.Close() }

// Processed reports whether a Telegram update completed durable relay
// submission. A false result must not be recorded until that submission has
// succeeded, otherwise a transient relay failure would lose the update.
func (s *State) Processed(updateID int64) (bool, error) {
	var found int64
	err := s.db.QueryRowContext(context.Background(), "SELECT update_id FROM processed_updates WHERE update_id = ?", updateID).Scan(&found)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// MarkProcessed records a successful relay submission. A crash after the
// submission but before this write is safe because the relay deduplicates the
// retry using the same Telegram update identity.
func (s *State) MarkProcessed(updateID int64) error {
	_, err := s.db.ExecContext(context.Background(), "INSERT INTO processed_updates(update_id) VALUES (?) ON CONFLICT(update_id) DO NOTHING", updateID)
	return err
}

// MarkProcessedTerminalInbound atomically consumes a terminally rejected
// update and stages its conversation-scoped doctor evidence.
func (s *State) MarkProcessedTerminalInbound(updateID int64, conversationID string) error {
	if updateID < 0 || strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("invalid terminal inbound update")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(context.Background(), `INSERT INTO processed_updates(update_id) VALUES (?) ON CONFLICT(update_id) DO NOTHING`, updateID)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted > 0 {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_inbound_targets(conversation_id,failures) VALUES(?,1) ON CONFLICT(conversation_id) DO UPDATE SET failures=failures+1`, conversationID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MarkProcessedInboundRecovery atomically records a successful submission and
// clears only terminal inbound evidence for that conversation.
func (s *State) MarkProcessedInboundRecovery(updateID int64, conversationID string) error {
	if updateID < 0 || strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("invalid inbound recovery update")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(context.Background(), `INSERT INTO processed_updates(update_id) VALUES (?) ON CONFLICT(update_id) DO NOTHING`, updateID)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted > 0 {
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM gateway_terminal_inbound_targets WHERE conversation_id IN (?,?)`, conversationID, gatewayLegacyTarget); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// StageTerminalOutbound durably and idempotently records a rejected delivery
// before the relay acknowledgement makes that delivery unrecoverable.
func (s *State) StageTerminalOutbound(deliveryID, conversationID string, class GatewayFailureClass) error {
	if strings.TrimSpace(deliveryID) == "" || strings.TrimSpace(conversationID) == "" || class != GatewayFailureOutboundTelegramPermanent && class != GatewayFailureDeletedTopic {
		return fmt.Errorf("invalid terminal outbound delivery")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_outbound_events(delivery_id,conversation_id,failure_class) VALUES(?,?,?) ON CONFLICT(delivery_id) DO NOTHING`, deliveryID, conversationID, string(class))
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted > 0 {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO gateway_terminal_outbound_targets(conversation_id,failures,failure_class) VALUES(?,1,?) ON CONFLICT(conversation_id) DO UPDATE SET failures=failures+1,failure_class=CASE WHEN failure_class='deleted_topic' OR excluded.failure_class='deleted_topic' THEN 'deleted_topic' ELSE 'outbound_telegram_permanent' END`, conversationID, string(class)); err != nil {
			return err
		}
	} else {
		var existingConversation, existingClass string
		if err := tx.QueryRowContext(context.Background(), `SELECT conversation_id,failure_class FROM gateway_terminal_outbound_events WHERE delivery_id=?`, deliveryID).Scan(&existingConversation, &existingClass); err != nil || existingConversation != conversationID || GatewayFailureClass(existingClass) != class {
			return fmt.Errorf("terminal outbound delivery identity conflict")
		}
	}
	return tx.Commit()
}

// RecoverTerminalOutbound clears a repaired conversation before its successful
// delivery acknowledgement crosses the external relay boundary.
func (s *State) RecoverTerminalOutbound(conversationID string) error {
	if strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("invalid terminal outbound recovery")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM gateway_terminal_outbound_targets WHERE conversation_id IN (?,?)`, conversationID, gatewayLegacyTarget); err != nil {
		return err
	}
	if _, err := tx.ExecContext(context.Background(), `DELETE FROM gateway_terminal_outbound_events WHERE conversation_id=?`, conversationID); err != nil {
		return err
	}
	return tx.Commit()
}

// SetRoute binds one exact Telegram topic to one relay conversation. There is
// no main-chat fallback because an absent topic is a routing error, not a hint.
// The claim fence and write share one transaction so a concurrent PersistClaimRoute
// cannot land between RouteBlocked and the INSERT. Unthreaded creating is bound
// to the routed thread in the same transaction so resume cannot create again
// and another conversation cannot steal the recovery route.
func (s *State) SetRoute(chatID, threadID int64, conversationID string) error {
	if strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("conversation ID is required")
	}
	return s.withImmediate(func(conn *sql.Conn) error {
		if err := routeBlockedOn(conn, chatID, threadID, conversationID); err != nil {
			return err
		}
		if _, err := conn.ExecContext(context.Background(), `INSERT INTO topic_routes(chat_id, thread_id, conversation_id) VALUES (?, ?, ?)
			ON CONFLICT(chat_id, thread_id) DO UPDATE SET conversation_id = excluded.conversation_id`, chatID, threadID, conversationID); err != nil {
			return err
		}
		_, err := conn.ExecContext(context.Background(), `UPDATE claim_executions SET thread_id = ?, chat_id = ?, phase = ? WHERE conversation_id = ? AND phase = ? AND (thread_id IS NULL OR thread_id <= 0)`, threadID, chatID, ClaimPhaseTopicCreated, conversationID, ClaimPhaseCreating)
		return err
	})
}

// Route returns the exact conversation bound to a chat and thread.
func (s *State) Route(chatID, threadID int64) (string, bool, error) {
	var conversation string
	err := s.db.QueryRowContext(context.Background(), "SELECT conversation_id FROM topic_routes WHERE chat_id = ? AND thread_id = ?", chatID, threadID).Scan(&conversation)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return conversation, true, nil
}

// RouteForConversation returns the sole Telegram topic bound to a relay
// conversation. The unique durable index prevents an agent reply being fanned
// out into more than one user topic by accident.
func (s *State) RouteForConversation(conversationID string) (int64, int64, bool, error) {
	var chatID, threadID int64
	err := s.db.QueryRowContext(context.Background(), "SELECT chat_id, thread_id FROM topic_routes WHERE conversation_id = ?", conversationID).Scan(&chatID, &threadID)
	if err == sql.ErrNoRows {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	return chatID, threadID, true, nil
}

// IssueCallbackToken stores only the SHA-256 of a 256-bit random token. The
// raw value is returned once for Telegram callback_data and is never logged.
func (s *State) IssueCallbackToken(conversationID string, now time.Time) (string, error) {
	if strings.TrimSpace(conversationID) == "" {
		return "", fmt.Errorf("conversation ID is required")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate telegram callback token")
	}
	token := hex.EncodeToString(raw[:])
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), "DELETE FROM callback_tokens WHERE expires_at <= ?", now.UnixMilli()); err != nil {
		return "", err
	}
	var outstanding int
	if err := tx.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM callback_tokens WHERE consumed_at IS NULL AND expires_at > ?", now.UnixMilli()).Scan(&outstanding); err != nil {
		return "", err
	}
	if outstanding >= maxCallbackTokens {
		rows, err := tx.QueryContext(context.Background(), "SELECT token_hash FROM callback_tokens WHERE consumed_at IS NULL ORDER BY expires_at ASC, rowid ASC LIMIT ?", outstanding-maxCallbackTokens+1)
		if err != nil {
			return "", err
		}
		var evict []string
		for rows.Next() {
			var hash string
			if err := rows.Scan(&hash); err != nil {
				_ = rows.Close()
				return "", err
			}
			evict = append(evict, hash)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return "", err
		}
		if err := rows.Close(); err != nil {
			return "", err
		}
		for _, hash := range evict {
			if _, err := tx.ExecContext(context.Background(), "DELETE FROM callback_tokens WHERE token_hash = ?", hash); err != nil {
				return "", err
			}
		}
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO callback_tokens(token_hash, conversation_id, expires_at) VALUES (?, ?, ?)", callbackTokenHash(token), conversationID, now.Add(callbackTokenTTL).UnixMilli()); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

func callbackTokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// ReserveClaimAndConsumeToken inserts claim_executions reserved, then consumes
// the token in the same transaction. A failed tx leaves the token reusable.
func (s *State) ReserveClaimAndConsumeToken(raw string, now time.Time) (string, bool, error) {
	if strings.TrimSpace(raw) == "" {
		return "", false, nil
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback() }()
	var conversation string
	var expiresAt int64
	var consumedAt sql.NullInt64
	err = tx.QueryRowContext(context.Background(), `SELECT conversation_id, expires_at, consumed_at FROM callback_tokens WHERE token_hash = ?`, callbackTokenHash(raw)).Scan(&conversation, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if consumedAt.Valid || expiresAt <= now.UnixMilli() {
		return "", false, nil
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO claim_executions(conversation_id, phase, skip_reserve) VALUES (?, ?, 0) ON CONFLICT(conversation_id) DO NOTHING`, conversation, ClaimPhaseReserved); err != nil {
		return "", false, err
	}
	result, err := tx.ExecContext(context.Background(), `UPDATE callback_tokens SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?`, now.UnixMilli(), callbackTokenHash(raw), now.UnixMilli())
	if err != nil {
		return "", false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", false, err
	}
	if affected != 1 {
		return "", false, nil
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return conversation, true, nil
}

// InsertPendingExecution records a relay-pending claim that must not reserve again.
func (s *State) InsertPendingExecution(conversationID, displayName string) (bool, error) {
	if strings.TrimSpace(conversationID) == "" {
		return false, fmt.Errorf("conversation ID is required")
	}
	result, err := s.db.ExecContext(context.Background(), `INSERT INTO claim_executions(conversation_id, phase, display_name, skip_reserve) VALUES (?, ?, ?, 1) ON CONFLICT(conversation_id) DO NOTHING`, conversationID, ClaimPhaseReserved, displayName)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

const claimExecutionSelect = "conversation_id, thread_id, chat_id, phase, display_name, skip_reserve"

func scanClaimExecution(scanner interface{ Scan(dest ...any) error }) (ClaimExecution, error) {
	var execution ClaimExecution
	var threadID, chatID sql.NullInt64
	var displayName sql.NullString
	var skip int
	if err := scanner.Scan(&execution.ConversationID, &threadID, &chatID, &execution.Phase, &displayName, &skip); err != nil {
		return ClaimExecution{}, err
	}
	if threadID.Valid {
		execution.ThreadID = threadID.Int64
	}
	if chatID.Valid {
		execution.ChatID = chatID.Int64
	}
	execution.DisplayName = displayName.String
	execution.SkipReserve = skip == 1
	return execution, nil
}

func scanClaimExecutions(rows *sql.Rows) ([]ClaimExecution, error) {
	var executions []ClaimExecution
	for rows.Next() {
		execution, err := scanClaimExecution(rows)
		if err != nil {
			return nil, err
		}
		executions = append(executions, execution)
	}
	return executions, rows.Err()
}

// ClaimExecution returns the local execution row for a conversation.
func (s *State) ClaimExecution(conversationID string) (ClaimExecution, bool, error) {
	execution, err := scanClaimExecution(s.db.QueryRowContext(context.Background(), `SELECT `+claimExecutionSelect+` FROM claim_executions WHERE conversation_id = ?`, conversationID))
	if errors.Is(err, sql.ErrNoRows) {
		return ClaimExecution{}, false, nil
	}
	if err != nil {
		return ClaimExecution{}, false, err
	}
	return execution, true, nil
}

// IncompleteClaimExecutions lists every local row that is not complete.
func (s *State) IncompleteClaimExecutions() ([]ClaimExecution, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT `+claimExecutionSelect+` FROM claim_executions WHERE phase != ? ORDER BY conversation_id`, ClaimPhaseComplete)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanClaimExecutions(rows)
}

// IncompleteClaimExecutionsAfter lists incomplete rows after a conversation cursor.
func (s *State) IncompleteClaimExecutionsAfter(after string, limit int) ([]ClaimExecution, error) {
	if limit < 1 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(context.Background(), `SELECT `+claimExecutionSelect+` FROM claim_executions
		WHERE phase != ? AND (? = '' OR conversation_id > ?) ORDER BY conversation_id LIMIT ?`, ClaimPhaseComplete, after, after, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanClaimExecutions(rows)
}

// CompletedClaimExecutions lists finished local executions for route revalidation.
func (s *State) CompletedClaimExecutions() ([]ClaimExecution, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT `+claimExecutionSelect+` FROM claim_executions WHERE phase = ? ORDER BY conversation_id`, ClaimPhaseComplete)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanClaimExecutions(rows)
}

// CompletedClaimExecutionsAfter lists completed rows after a conversation cursor.
func (s *State) CompletedClaimExecutionsAfter(after string, limit int) ([]ClaimExecution, error) {
	if limit < 1 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(context.Background(), `SELECT `+claimExecutionSelect+` FROM claim_executions
		WHERE phase = ? AND (? = '' OR conversation_id > ?) ORDER BY conversation_id LIMIT ?`, ClaimPhaseComplete, after, after, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanClaimExecutions(rows)
}

// PersistClaimDisplayName stores the snapshotted label used for createForumTopic.
func (s *State) PersistClaimDisplayName(conversationID, displayName string) error {
	_, err := s.db.ExecContext(context.Background(), `UPDATE claim_executions SET display_name = ? WHERE conversation_id = ?`, displayName, conversationID)
	return err
}

// PersistClaimCreating fences createForumTopic so a crash after Bot API success
// cannot start a second topic. Resume with this phase and no thread id does
// not call createForumTopic again; an emergency route may bind a known thread.
func (s *State) PersistClaimCreating(conversationID string) error {
	_, _, creating, err := s.BeginClaimCreating(conversationID, 0)
	if err != nil {
		return err
	}
	if !creating {
		return fmt.Errorf("telegram claim creating fence is unavailable")
	}
	return nil
}

// BeginClaimCreating rechecks topic_routes and transitions reserved to
// creating under BEGIN IMMEDIATE so SetRoute cannot insert a route in the
// window before createForumTopic. After the fence, unthreaded creating may
// still be bound by emergency route. An existing route for the allowed chat is
// persisted as topic_created in the same transaction. A foreign-chat race
// leaves the execution reserved so the operator can correct the route.
func (s *State) BeginClaimCreating(conversationID string, allowedUserID int64) (int64, int64, bool, error) {
	if strings.TrimSpace(conversationID) == "" {
		return 0, 0, false, fmt.Errorf("conversation ID is required")
	}
	var chatID, threadID int64
	var creating bool
	err := s.withImmediate(func(conn *sql.Conn) error {
		err := conn.QueryRowContext(context.Background(), `SELECT chat_id, thread_id FROM topic_routes WHERE conversation_id = ?`, conversationID).Scan(&chatID, &threadID)
		if err == nil && threadID > 0 {
			if allowedUserID != 0 && chatID != allowedUserID {
				return fmt.Errorf("telegram_route_persist_failed")
			}
			if _, err := conn.ExecContext(context.Background(), `UPDATE claim_executions SET thread_id = ?, chat_id = ?, phase = ? WHERE conversation_id = ?`, threadID, chatID, ClaimPhaseTopicCreated, conversationID); err != nil {
				return err
			}
			creating = false
			return nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		chatID, threadID = 0, 0
		result, err := conn.ExecContext(context.Background(), `UPDATE claim_executions SET phase = ? WHERE conversation_id = ? AND phase = ? AND (thread_id IS NULL OR thread_id <= 0)`, ClaimPhaseCreating, conversationID, ClaimPhaseReserved)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected != 1 {
			return fmt.Errorf("telegram claim creating fence is unavailable")
		}
		creating = true
		return nil
	})
	if err != nil {
		return 0, 0, false, err
	}
	return chatID, threadID, creating, nil
}

// ClearClaimCreating returns a still-unthreaded row to reserved after Bot API
// failure so a later attempt may retry createForumTopic.
func (s *State) ClearClaimCreating(conversationID string) error {
	if strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("conversation ID is required")
	}
	_, err := s.db.ExecContext(context.Background(), `UPDATE claim_executions SET phase = ? WHERE conversation_id = ? AND phase = ? AND (thread_id IS NULL OR thread_id <= 0)`, ClaimPhaseReserved, conversationID, ClaimPhaseCreating)
	return err
}

// PersistClaimThread writes the Bot API thread id and creation chat immediately
// after createForumTopic so resume cannot bind that thread to a later chat.
func (s *State) PersistClaimThread(conversationID string, chatID, threadID int64) error {
	if strings.TrimSpace(conversationID) == "" || chatID == 0 || threadID <= 0 {
		return fmt.Errorf("claim thread is required")
	}
	_, err := s.db.ExecContext(context.Background(), `UPDATE claim_executions SET thread_id = ?, chat_id = ?, phase = ? WHERE conversation_id = ?`, threadID, chatID, ClaimPhaseTopicCreated, conversationID)
	return err
}

// PersistClaimRoute binds the stored thread and advances the execution phase.
// An existing route for this conversation is reused. Another conversation's
// thread is never overwritten.
func (s *State) PersistClaimRoute(chatID, threadID int64, conversationID string) error {
	if strings.TrimSpace(conversationID) == "" || chatID == 0 || threadID <= 0 {
		return fmt.Errorf("telegram route persist is required")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var existingChat, existingThread sql.NullInt64
	err = tx.QueryRowContext(context.Background(), `SELECT chat_id, thread_id FROM topic_routes WHERE conversation_id = ?`, conversationID).Scan(&existingChat, &existingThread)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && existingThread.Valid && existingThread.Int64 > 0 {
		if !existingChat.Valid || existingChat.Int64 != chatID {
			return fmt.Errorf("telegram topic is bound to another chat")
		}
		if _, err := tx.ExecContext(context.Background(), `UPDATE claim_executions SET thread_id = ?, phase = ? WHERE conversation_id = ?`, existingThread.Int64, ClaimPhaseRoutePersisted, conversationID); err != nil {
			return err
		}
		return tx.Commit()
	}
	var bound string
	err = tx.QueryRowContext(context.Background(), `SELECT conversation_id FROM topic_routes WHERE chat_id = ? AND thread_id = ?`, chatID, threadID).Scan(&bound)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && bound != conversationID {
		return fmt.Errorf("telegram topic is already bound")
	}
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO topic_routes(chat_id, thread_id, conversation_id) VALUES (?, ?, ?)`, chatID, threadID, conversationID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(context.Background(), `UPDATE claim_executions SET phase = ? WHERE conversation_id = ?`, ClaimPhaseRoutePersisted, conversationID); err != nil {
		return err
	}
	return tx.Commit()
}

// AdoptExecution records an existing topic route at route_persisted.
// A complete row is never downgraded, and its thread_id is kept unless it already matches.
func (s *State) AdoptExecution(conversationID string, threadID int64) error {
	if strings.TrimSpace(conversationID) == "" || threadID <= 0 {
		return fmt.Errorf("adopt route is required")
	}
	_, err := s.db.ExecContext(context.Background(), adoptExecutionSQL, conversationID, threadID, ClaimPhaseRoutePersisted, ClaimPhaseComplete, ClaimPhaseComplete)
	return err
}

const adoptExecutionSQL = `INSERT INTO claim_executions(conversation_id, thread_id, phase, skip_reserve) VALUES (?, ?, ?, 1)
		ON CONFLICT(conversation_id) DO UPDATE SET
			thread_id = CASE WHEN claim_executions.phase = ? THEN claim_executions.thread_id ELSE excluded.thread_id END,
			phase = CASE WHEN claim_executions.phase = ? THEN claim_executions.phase ELSE excluded.phase END,
			skip_reserve = 1`

const adoptExistingRouteSQL = `INSERT INTO claim_executions(conversation_id, thread_id, chat_id, phase, skip_reserve) VALUES (?, ?, ?, ?, 1)
		ON CONFLICT(conversation_id) DO UPDATE SET
			thread_id = CASE WHEN claim_executions.phase = ? THEN claim_executions.thread_id ELSE excluded.thread_id END,
			chat_id = CASE WHEN claim_executions.phase = ? THEN claim_executions.chat_id ELSE excluded.chat_id END,
			phase = CASE WHEN claim_executions.phase = ? THEN claim_executions.phase ELSE excluded.phase END,
			skip_reserve = 1`

const pendingClaimCursorName = "pending_claims"
const resumeClaimCursorName = "resume_claims"
const completedRouteCursorName = "completed_routes"

func (s *State) pendingClaimCursor() (string, error) {
	var value string
	err := s.db.QueryRowContext(context.Background(), `SELECT value FROM gateway_cursors WHERE name = ?`, pendingClaimCursorName).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *State) setPendingClaimCursor(after string) error {
	if after == "" {
		_, err := s.db.ExecContext(context.Background(), `DELETE FROM gateway_cursors WHERE name = ?`, pendingClaimCursorName)
		return err
	}
	_, err := s.db.ExecContext(context.Background(), `INSERT INTO gateway_cursors(name, value) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET value = excluded.value`, pendingClaimCursorName, after)
	return err
}

func (s *State) resumeClaimCursor() (string, error) {
	var value string
	err := s.db.QueryRowContext(context.Background(), `SELECT value FROM gateway_cursors WHERE name = ?`, resumeClaimCursorName).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *State) setResumeClaimCursor(after string) error {
	if after == "" {
		_, err := s.db.ExecContext(context.Background(), `DELETE FROM gateway_cursors WHERE name = ?`, resumeClaimCursorName)
		return err
	}
	_, err := s.db.ExecContext(context.Background(), `INSERT INTO gateway_cursors(name, value) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET value = excluded.value`, resumeClaimCursorName, after)
	return err
}

func (s *State) completedRouteCursor() (string, error) {
	var value string
	err := s.db.QueryRowContext(context.Background(), `SELECT value FROM gateway_cursors WHERE name = ?`, completedRouteCursorName).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func (s *State) setCompletedRouteCursor(after string) error {
	if after == "" {
		_, err := s.db.ExecContext(context.Background(), `DELETE FROM gateway_cursors WHERE name = ?`, completedRouteCursorName)
		return err
	}
	_, err := s.db.ExecContext(context.Background(), `INSERT INTO gateway_cursors(name, value) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET value = excluded.value`, completedRouteCursorName, after)
	return err
}

func (s *State) withImmediate(fn func(*sql.Conn) error) error {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()
	if err := fn(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

// AdoptExistingRoute re-reads topic_routes and writes an adopting
// claim_executions fence under BEGIN IMMEDIATE so an emergency SetRoute
// cannot remap after the lookup and resume can still reserve.
func (s *State) AdoptExistingRoute(conversationID string, allowedUserID int64) (int64, error) {
	if strings.TrimSpace(conversationID) == "" || allowedUserID == 0 {
		return 0, fmt.Errorf("telegram adopt is not configured")
	}
	var threadID int64
	err := s.withImmediate(func(conn *sql.Conn) error {
		var chatID int64
		err := conn.QueryRowContext(context.Background(), `SELECT chat_id, thread_id FROM topic_routes WHERE conversation_id = ?`, conversationID).Scan(&chatID, &threadID)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("telegram adopt requires an existing topic route")
		}
		if err != nil {
			return err
		}
		if threadID <= 0 {
			return fmt.Errorf("telegram adopt requires an existing topic route")
		}
		if chatID != allowedUserID {
			return fmt.Errorf("telegram adopt requires the configured telegram chat")
		}
		_, err = conn.ExecContext(context.Background(), adoptExistingRouteSQL, conversationID, threadID, chatID, ClaimPhaseAdopting, ClaimPhaseComplete, ClaimPhaseComplete, ClaimPhaseComplete)
		return err
	})
	if err != nil {
		return 0, err
	}
	return threadID, nil
}

// PersistClaimAdoptReserved advances a pre-reserve adopt fence after the
// relay reservation exists so resume can complete instead of reserving again.
func (s *State) PersistClaimAdoptReserved(conversationID string) error {
	if strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("conversation ID is required")
	}
	_, err := s.db.ExecContext(context.Background(), `UPDATE claim_executions SET phase = ? WHERE conversation_id = ? AND phase = ?`, ClaimPhaseRoutePersisted, conversationID, ClaimPhaseAdopting)
	return err
}

// MarkClaimComplete records a finished local execution.
func (s *State) MarkClaimComplete(conversationID string) error {
	_, err := s.db.ExecContext(context.Background(), `UPDATE claim_executions SET phase = ? WHERE conversation_id = ?`, ClaimPhaseComplete, conversationID)
	return err
}

// ClaimComplete reports whether the conversation has a completed local claim.
func (s *State) ClaimComplete(conversationID string) (bool, error) {
	protected, err := s.claimProtectsRoute(conversationID)
	if err != nil {
		return false, err
	}
	if !protected {
		return false, nil
	}
	execution, found, err := s.ClaimExecution(conversationID)
	if err != nil || !found {
		return false, err
	}
	return execution.Phase == ClaimPhaseComplete, nil
}

type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *State) claimProtectsRoute(conversationID string) (bool, error) {
	return claimProtectsRouteOn(s.db, conversationID)
}

func claimProtectsRouteOn(q rowQueryer, conversationID string) (bool, error) {
	var phase string
	err := q.QueryRowContext(context.Background(), `SELECT phase FROM claim_executions WHERE conversation_id = ?`, conversationID).Scan(&phase)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return phase == ClaimPhaseCreating || phase == ClaimPhaseTopicCreated || phase == ClaimPhaseAdopting || phase == ClaimPhaseRoutePersisted || phase == ClaimPhaseComplete, nil
}

func claimBlocksRemapOn(q rowQueryer, conversationID string) (bool, error) {
	var phase string
	var threadID sql.NullInt64
	err := q.QueryRowContext(context.Background(), `SELECT phase, thread_id FROM claim_executions WHERE conversation_id = ?`, conversationID).Scan(&phase, &threadID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if phase == ClaimPhaseCreating && (!threadID.Valid || threadID.Int64 <= 0) {
		return false, nil
	}
	return phase == ClaimPhaseCreating || phase == ClaimPhaseTopicCreated || phase == ClaimPhaseAdopting || phase == ClaimPhaseRoutePersisted || phase == ClaimPhaseComplete, nil
}

// RouteBlocked refuses remapping a claimed conversation or stealing its thread.
// Unthreaded creating may be bound by emergency route; a thread already bound
// to creating still cannot be stolen.
func (s *State) RouteBlocked(chatID, threadID int64, conversationID string) error {
	return routeBlockedOn(s.db, chatID, threadID, conversationID)
}

func routeBlockedOn(q rowQueryer, chatID, threadID int64, conversationID string) error {
	blocked, err := claimBlocksRemapOn(q, conversationID)
	if err != nil {
		return err
	}
	if blocked {
		return fmt.Errorf("telegram conversation is already claimed")
	}
	var existing string
	err = q.QueryRowContext(context.Background(), "SELECT conversation_id FROM topic_routes WHERE chat_id = ? AND thread_id = ?", chatID, threadID).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if existing == conversationID {
		return nil
	}
	protected, err := claimProtectsRouteOn(q, existing)
	if err != nil {
		return err
	}
	if protected {
		return fmt.Errorf("telegram topic is already bound to a claimed conversation")
	}
	return nil
}

// RecordOutbound stores one Telegram message_id to Punaro identity mapping.
func (s *State) RecordOutbound(chatID, messageID int64, conversationID, punaroMessageID, fromEndpoint string, now time.Time) error {
	if chatID == 0 || messageID <= 0 || strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("telegram outbound map row is required")
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO telegram_outbound(chat_id, message_id, conversation_id, punaro_message_id, from_endpoint, created_at) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(chat_id, message_id) DO UPDATE SET conversation_id = excluded.conversation_id, punaro_message_id = excluded.punaro_message_id, from_endpoint = excluded.from_endpoint, created_at = excluded.created_at`, chatID, messageID, conversationID, punaroMessageID, fromEndpoint, now.UnixMilli()); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM telegram_outbound`).Scan(&count); err != nil {
		return err
	}
	if count > telegramOutboundLimit {
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM telegram_outbound WHERE rowid IN (SELECT rowid FROM telegram_outbound ORDER BY created_at ASC, rowid ASC LIMIT ?)`, count-telegramOutboundLimit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LookupOutbound resolves a Telegram reply_to_message_id to a Punaro identity.
func (s *State) LookupOutbound(chatID, messageID int64) (OutboundRef, bool, error) {
	var ref OutboundRef
	err := s.db.QueryRowContext(context.Background(), `SELECT conversation_id, punaro_message_id, from_endpoint FROM telegram_outbound WHERE chat_id = ? AND message_id = ?`, chatID, messageID).Scan(&ref.ConversationID, &ref.PunaroMessageID, &ref.FromEndpoint)
	if errors.Is(err, sql.ErrNoRows) {
		return OutboundRef{}, false, nil
	}
	if err != nil {
		return OutboundRef{}, false, err
	}
	return ref, true, nil
}
