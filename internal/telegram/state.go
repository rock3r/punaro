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
	"os"
	"path/filepath"
	"strings"
	"time"

	// sqlite is the content-free Telegram route and replay state driver.
	_ "modernc.org/sqlite"
)

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
	return &State{db: db}, nil
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

// SetRoute binds one exact Telegram topic to one relay conversation. There is
// no main-chat fallback because an absent topic is a routing error, not a hint.
// The claim fence and write share one transaction so a concurrent PersistClaimRoute
// cannot land between RouteBlocked and the INSERT.
func (s *State) SetRoute(chatID, threadID int64, conversationID string) error {
	if strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("conversation ID is required")
	}
	return s.withImmediate(func(conn *sql.Conn) error {
		if err := routeBlockedOn(conn, chatID, threadID, conversationID); err != nil {
			return err
		}
		_, err := conn.ExecContext(context.Background(), `INSERT INTO topic_routes(chat_id, thread_id, conversation_id) VALUES (?, ?, ?)
			ON CONFLICT(chat_id, thread_id) DO UPDATE SET conversation_id = excluded.conversation_id`, chatID, threadID, conversationID)
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
// cannot start a second topic. Resume with this phase and no thread id fails
// closed instead of calling createForumTopic again.
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
// window before createForumTopic. An existing route for the allowed chat is
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

// RouteBlocked refuses remapping a claimed conversation or stealing its thread.
// A route is claimed once createForumTopic is in flight or a topic/route exists.
func (s *State) RouteBlocked(chatID, threadID int64, conversationID string) error {
	return routeBlockedOn(s.db, chatID, threadID, conversationID)
}

func routeBlockedOn(q rowQueryer, chatID, threadID int64, conversationID string) error {
	protected, err := claimProtectsRouteOn(q, conversationID)
	if err != nil {
		return err
	}
	if protected {
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
	protected, err = claimProtectsRouteOn(q, existing)
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
