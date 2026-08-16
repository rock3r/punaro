package telegram

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

var testCallbackNow = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func TestStateRecordsCompletedUpdatesAndRequiresExplicitTopicRoute(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	processed, err := state.Processed(42)
	if err != nil || processed {
		t.Fatalf("initial processed=%v err=%v", processed, err)
	}
	if err := state.MarkProcessed(42); err != nil {
		t.Fatal(err)
	}
	processed, err = state.Processed(42)
	if err != nil || !processed {
		t.Fatalf("completed processed=%v err=%v", processed, err)
	}
	if _, found, err := state.Route(100, 7); err != nil || found {
		t.Fatalf("unexpected route found=%v err=%v", found, err)
	}
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	conversation, found, err := state.Route(100, 7)
	if err != nil || !found || conversation != "conversation-1" {
		t.Fatalf("route=%q found=%v err=%v", conversation, found, err)
	}
	chat, thread, found, err := state.RouteForConversation("conversation-1")
	if err != nil || !found || chat != 100 || thread != 7 {
		t.Fatalf("reverse route chat=%d thread=%d found=%v err=%v", chat, thread, found, err)
	}
	if err := state.SetRoute(100, 8, "conversation-1"); err == nil {
		t.Fatal("one conversation was mapped to more than one Telegram topic")
	}
}

func TestStateIssuesHashedTTLCallbackTokens(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	now := testCallbackNow
	raw, err := state.IssueCallbackToken("conversation-1", now)
	if err != nil || raw == "" || raw == "conversation-1" || len(raw) != 64 {
		t.Fatalf("token=%q err=%v", raw, err)
	}
	conversation, found, consumed, err := state.lookupCallbackToken(raw, now)
	if err != nil || !found || consumed || conversation != "conversation-1" {
		t.Fatalf("lookup conversation=%q found=%v consumed=%v err=%v", conversation, found, consumed, err)
	}
	if stored, err := state.storedCallbackTokenHashes(); err != nil || len(stored) != 1 || stored[0] == raw || stored[0] == "conversation-1" {
		t.Fatalf("stored hashes=%#v err=%v", stored, err)
	}
	if _, found, _, err := state.lookupCallbackToken(raw, now.Add(callbackTokenTTL+time.Second)); err != nil || found {
		t.Fatal("expired token remained valid")
	}
	if _, err := state.IssueCallbackToken("conversation-2", now.Add(callbackTokenTTL+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if hashes, err := state.storedCallbackTokenHashes(); err != nil || len(hashes) != 1 {
		t.Fatalf("expired token was not deleted on insert: hashes=%#v err=%v", hashes, err)
	}
	for i := 0; i < maxCallbackTokens; i++ {
		if _, err := state.IssueCallbackToken("conversation-bound", now.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	count, err := state.outstandingCallbackTokens(now.Add(2 * time.Hour))
	if err != nil || count != maxCallbackTokens {
		t.Fatalf("outstanding=%d err=%v", count, err)
	}
	var claimExecutions int
	if err := state.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='claim_executions'`).Scan(&claimExecutions); err != nil || claimExecutions != 0 {
		t.Fatalf("6a created claim_executions: count=%d err=%v", claimExecutions, err)
	}
}

func (s *State) lookupCallbackToken(raw string, now time.Time) (string, bool, bool, error) {
	var conversation string
	var expiresAt int64
	var consumedAt sql.NullInt64
	err := s.db.QueryRowContext(context.Background(), `SELECT conversation_id, expires_at, consumed_at FROM callback_tokens WHERE token_hash = ?`, callbackTokenHash(raw)).Scan(&conversation, &expiresAt, &consumedAt)
	if err == sql.ErrNoRows {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	if expiresAt <= now.UnixMilli() {
		return conversation, false, consumedAt.Valid, nil
	}
	return conversation, true, consumedAt.Valid, nil
}

func (s *State) storedCallbackTokenHashes() ([]string, error) {
	rows, err := s.db.QueryContext(context.Background(), `SELECT token_hash FROM callback_tokens ORDER BY expires_at`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	return hashes, rows.Err()
}

func (s *State) outstandingCallbackTokens(now time.Time) (int, error) {
	var count int
	err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM callback_tokens WHERE consumed_at IS NULL AND expires_at > ?`, now.UnixMilli()).Scan(&count)
	return count, err
}
