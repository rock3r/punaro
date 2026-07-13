// Package telegram holds durable, content-free control state for the optional
// Telegram gateway. Bot text is never stored here.
package telegram

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// sqlite is the content-free Telegram route and replay state driver.
	_ "modernc.org/sqlite"
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

// ClaimUpdate returns false for a replayed Telegram update ID.
func (s *State) ClaimUpdate(updateID int64) (bool, error) {
	result, err := s.db.ExecContext(context.Background(), "INSERT INTO processed_updates(update_id) VALUES (?) ON CONFLICT(update_id) DO NOTHING", updateID)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	return changed == 1, err
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
