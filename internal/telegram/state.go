// Package telegram holds durable, content-free control state for the optional
// Telegram gateway. Bot text is never stored here.
package telegram

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize telegram state: %w", err)
		}
	}
	return &State{db: db}, nil
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
func (s *State) SetRoute(chatID, threadID int64, conversationID string) error {
	if strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("conversation ID is required")
	}
	_, err := s.db.ExecContext(context.Background(), `INSERT INTO topic_routes(chat_id, thread_id, conversation_id) VALUES (?, ?, ?)
		ON CONFLICT(chat_id, thread_id) DO UPDATE SET conversation_id = excluded.conversation_id`, chatID, threadID, conversationID)
	return err
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
