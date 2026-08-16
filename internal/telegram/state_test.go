package telegram

import (
	"context"
	"database/sql"
	"fmt"
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
	if err := state.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='claim_executions'`).Scan(&claimExecutions); err != nil || claimExecutions != 1 {
		t.Fatalf("claim_executions missing: count=%d err=%v", claimExecutions, err)
	}
}

func TestStateReservesClaimExecutionBeforeConsumingToken(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	now := testCallbackNow
	raw, err := state.IssueCallbackToken("conversation-1", now)
	if err != nil {
		t.Fatal(err)
	}
	conversation, reserved, err := state.ReserveClaimAndConsumeToken(raw, now)
	if err != nil || !reserved || conversation != "conversation-1" {
		t.Fatalf("reserved conversation=%q reserved=%v err=%v", conversation, reserved, err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseReserved || execution.ThreadID != 0 || execution.SkipReserve {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
	if _, found, consumed, err := state.lookupCallbackToken(raw, now); err != nil || !found || !consumed {
		t.Fatalf("token found=%v consumed=%v err=%v", found, consumed, err)
	}
	if _, reserved, err := state.ReserveClaimAndConsumeToken(raw, now); err != nil || reserved {
		t.Fatalf("replay reserved=%v err=%v", reserved, err)
	}
	if _, reserved, err := state.ReserveClaimAndConsumeToken("missing", now); err != nil || reserved {
		t.Fatalf("missing token reserved=%v err=%v", reserved, err)
	}
}

func TestStatePersistsClaimThreadAndOutboundMap(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, err := state.InsertPendingExecution("conversation-1", "How is it going"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-1", 795446); err != nil {
		t.Fatal(err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseTopicCreated || execution.ThreadID != 795446 || !execution.SkipReserve || execution.DisplayName != "How is it going" {
		t.Fatalf("after thread persist %#v found=%v err=%v", execution, found, err)
	}
	if err := state.PersistClaimRoute(55, 795446, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkClaimComplete("conversation-1"); err != nil {
		t.Fatal(err)
	}
	if complete, err := state.ClaimComplete("conversation-1"); err != nil || !complete {
		t.Fatalf("complete=%v err=%v", complete, err)
	}
	if err := state.RecordOutbound(55, 9, "conversation-1", "message-1", "agent/a", testCallbackNow); err != nil {
		t.Fatal(err)
	}
	ref, found, err := state.LookupOutbound(55, 9)
	if err != nil || !found || ref.ConversationID != "conversation-1" || ref.PunaroMessageID != "message-1" || ref.FromEndpoint != "agent/a" {
		t.Fatalf("outbound=%#v found=%v err=%v", ref, found, err)
	}
	if _, found, err := state.LookupOutbound(55, 10); err != nil || found {
		t.Fatal("missing outbound was found")
	}
}

func TestStateEvictsOldestOutboundAtCap(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	previous := telegramOutboundLimit
	telegramOutboundLimit = 2
	t.Cleanup(func() { telegramOutboundLimit = previous })
	now := testCallbackNow
	if err := state.RecordOutbound(55, 1, "conversation-1", "message-1", "agent/a", now); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordOutbound(55, 2, "conversation-1", "message-2", "agent/a", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := state.RecordOutbound(55, 3, "conversation-1", "message-3", "agent/a", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := state.LookupOutbound(55, 1); err != nil || found {
		t.Fatal("oldest outbound was not evicted")
	}
	if _, found, err := state.LookupOutbound(55, 2); err != nil || !found {
		t.Fatal("kept outbound is missing")
	}
	if _, found, err := state.LookupOutbound(55, 3); err != nil || !found {
		t.Fatal("newest outbound is missing")
	}
}

func TestStateRefusesClaimedRouteRemap(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 7, "conversation-claimed"); err != nil {
		t.Fatal(err)
	}
	if err := state.AdoptExecution("conversation-claimed", 7); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkClaimComplete("conversation-claimed"); err != nil {
		t.Fatal(err)
	}
	if err := state.RouteBlocked(55, 8, "conversation-claimed"); err == nil {
		t.Fatal("claimed conversation remapped")
	}
	if err := state.RouteBlocked(55, 7, "conversation-other"); err == nil {
		t.Fatal("claimed thread stolen")
	}
	if err := state.RouteBlocked(55, 9, "conversation-free"); err != nil {
		t.Fatalf("unclaimed remap blocked: %v", err)
	}
}

func TestStateRouteBlockedTreatsRoutePersistedAsClaimed(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-claimed"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-claimed", 7); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimRoute(55, 7, "conversation-claimed"); err != nil {
		t.Fatal(err)
	}
	if err := state.RouteBlocked(55, 8, "conversation-claimed"); err == nil {
		t.Fatal("route_persisted conversation remapped")
	}
	if err := state.RouteBlocked(55, 7, "conversation-other"); err == nil {
		t.Fatal("route_persisted thread stolen")
	}
	if err := state.RouteBlocked(55, 9, "conversation-free"); err != nil {
		t.Fatalf("unclaimed remap blocked: %v", err)
	}
}

func TestStatePersistClaimRouteDoesNotStealAnotherConversationThread(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 7, "conversation-owner"); err != nil {
		t.Fatal(err)
	}
	if err := state.AdoptExecution("conversation-owner", 7); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkClaimComplete("conversation-owner"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-thief"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-thief", 7); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimRoute(55, 7, "conversation-thief"); err == nil {
		t.Fatal("PersistClaimRoute stole another conversation's thread")
	}
	conversation, found, err := state.Route(55, 7)
	if err != nil || !found || conversation != "conversation-owner" {
		t.Fatalf("stolen route conversation=%q found=%v err=%v", conversation, found, err)
	}
}

func TestStatePersistClaimRouteReusesExistingConversationThread(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 795446, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-1", 1); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimRoute(55, 1, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseRoutePersisted || execution.ThreadID != 795446 {
		t.Fatalf("reuse execution=%#v found=%v err=%v", execution, found, err)
	}
	conversation, found, err := state.Route(55, 795446)
	if err != nil || !found || conversation != "conversation-1" {
		t.Fatalf("kept route conversation=%q found=%v err=%v", conversation, found, err)
	}
	if _, found, err := state.Route(55, 1); err != nil || found {
		t.Fatal("second thread was inserted for the same conversation")
	}
}

func TestStateEvictsOldestCallbackTokenAtCap(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	now := testCallbackNow
	tokens := make([]string, maxCallbackTokens)
	for i := range tokens {
		token, err := state.IssueCallbackToken(fmt.Sprintf("conversation-%d", i), now)
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = token
	}
	newest, err := state.IssueCallbackToken("conversation-new", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, _, err := state.lookupCallbackToken(tokens[0], now); err != nil || found {
		t.Fatal("oldest outstanding token was not evicted")
	}
	for i, token := range tokens[1:] {
		if conversation, found, consumed, err := state.lookupCallbackToken(token, now); err != nil || !found || consumed || conversation != fmt.Sprintf("conversation-%d", i+1) {
			t.Fatalf("kept token %d missing: found=%v consumed=%v conversation=%q err=%v", i+1, found, consumed, conversation, err)
		}
	}
	if conversation, found, consumed, err := state.lookupCallbackToken(newest, now); err != nil || !found || consumed || conversation != "conversation-new" {
		t.Fatalf("just-issued token was evicted: found=%v consumed=%v conversation=%q err=%v", found, consumed, conversation, err)
	}
	count, err := state.outstandingCallbackTokens(now)
	if err != nil || count != maxCallbackTokens {
		t.Fatalf("outstanding=%d err=%v", count, err)
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
