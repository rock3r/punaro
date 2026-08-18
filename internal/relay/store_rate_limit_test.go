package relay

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func tightRateLimits() RateLimitConfig {
	return RateLimitConfig{
		SenderBurst:                 2,
		SenderRefillPerMinute:       60,
		ConversationBurst:           2,
		ConversationRefillPerMinute: 60,
		RetryAfterMaxSeconds:        60,
	}
}

func TestDecideRateLimitRefillsAndReportsExactRetryAfter(t *testing.T) {
	cfg := RateLimitConfig{SenderBurst: 2, SenderRefillPerMinute: 60, ConversationBurst: 4, ConversationRefillPerMinute: 60, RetryAfterMaxSeconds: 60}
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	first := DecideRateLimit(cfg, RateBucket{}, RateBucket{}, now)
	if !first.Allowed || first.Sender.Tokens != 1 || first.Conversation.Tokens != 3 {
		t.Fatalf("first decision=%#v", first)
	}
	second := DecideRateLimit(cfg, first.Sender, first.Conversation, now)
	if !second.Allowed || second.Sender.Tokens != 0 {
		t.Fatalf("second decision=%#v", second)
	}
	denied := DecideRateLimit(cfg, second.Sender, second.Conversation, now)
	if denied.Allowed || denied.RetryAfterSeconds != 1 {
		t.Fatalf("denied decision=%#v, want retry-after 1", denied)
	}
	refilled := DecideRateLimit(cfg, second.Sender, second.Conversation, now.Add(time.Second))
	if !refilled.Allowed || refilled.Sender.Tokens != 0 {
		t.Fatalf("refilled decision=%#v", refilled)
	}
}

func TestStoreSenderBucketExhaustionSpansConversations(t *testing.T) {
	t.Parallel()
	store := openRateLimitedStore(t, tightRateLimits())
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a", "agent/a2"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-c", []string{"agent/c"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	first, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateConversation("agent/a2", []Member{
		{Endpoint: "agent/a2", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/c", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(first, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(second, "machine-a", "agent/a2", "two", "send-2", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.AppendMessage(rateAppend(first, "machine-a", "agent/a", "three", "send-3", now))
	assertRateLimited(t, err, 1)
	assertNoAppendSideEffects(t, store, first, 1)
}

func TestStoreConversationBucketExhaustionSpansSenders(t *testing.T) {
	t.Parallel()
	store := openRateLimitedStore(t, tightRateLimits())
	now := time.Date(2026, time.August, 18, 16, 1, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if err := store.AdvertiseEndpoints("machine-c", []string{"agent/c"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/c", Capabilities: CapSend | CapReceive},
		IdempotencyKey: "add-c", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "from-a", "a-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-b", "agent/b", "from-b", "b-1", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(rateAppend(conversation, "machine-c", "agent/c", "from-c", "c-1", now))
	assertRateLimited(t, err, 1)
	assertNoAppendSideEffects(t, store, conversation, 2)
}

func TestStoreExactCommittedRetryDoesNotChargeEmptyBucket(t *testing.T) {
	t.Parallel()
	store := openRateLimitedStore(t, tightRateLimits())
	now := time.Date(2026, time.August, 18, 16, 2, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	input := rateAppend(conversation, "machine-a", "agent/a", "first", "retry-key", now)
	first, _, err := store.AppendMessage(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "second", "other-key", now)); err != nil {
		t.Fatal(err)
	}
	replay, duplicate, err := store.AppendMessage(input)
	if err != nil || !duplicate || replay != first {
		t.Fatalf("replay message=%#v duplicate=%t err=%v", replay, duplicate, err)
	}
	_, _, err = store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "third", "new-key", now))
	assertRateLimited(t, err, 1)
}

func TestStoreChangedBodyConflictIsNotRateLimited(t *testing.T) {
	t.Parallel()
	store := openRateLimitedStore(t, tightRateLimits())
	now := time.Date(2026, time.August, 18, 16, 3, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	input := rateAppend(conversation, "machine-a", "agent/a", "original", "conflict-key", now)
	if _, _, err := store.AppendMessage(input); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "fill", "fill-key", now)); err != nil {
		t.Fatal(err)
	}
	changed := input
	changed.Body = "changed"
	if _, _, err := store.AppendMessage(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed retry err=%v, want conflict", err)
	}
}

func TestStoreRejectedRequestLeavesNoDurableSideEffects(t *testing.T) {
	t.Parallel()
	store := openRateLimitedStore(t, tightRateLimits())
	now := time.Date(2026, time.August, 18, 16, 4, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "one", "one", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "two", "two", now)); err != nil {
		t.Fatal(err)
	}
	before := rateStoreCounts(t, store, conversation.ID)
	_, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "three", "three", now))
	assertRateLimited(t, err, 1)
	after := rateStoreCounts(t, store, conversation.ID)
	if after != before {
		t.Fatalf("rejected request mutated durable state: before=%v after=%v", before, after)
	}
}

func TestStoreConcurrentSendsCannotOverspendBucket(t *testing.T) {
	t.Parallel()
	cfg := tightRateLimits()
	cfg.SenderBurst = 1
	cfg.ConversationBurst = 1
	store := openRateLimitedStore(t, cfg)
	now := time.Date(2026, time.August, 18, 16, 5, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	const workers = 8
	var started sync.WaitGroup
	started.Add(workers)
	errorsSeen := make(chan error, workers)
	var workersGroup sync.WaitGroup
	workersGroup.Add(workers)
	for index := 0; index < workers; index++ {
		go func(index int) {
			defer workersGroup.Done()
			started.Done()
			started.Wait()
			_, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", fmt.Sprintf("concurrent-%d", index), fmt.Sprintf("concurrent-%d", index), now))
			errorsSeen <- err
		}(index)
	}
	workersGroup.Wait()
	close(errorsSeen)
	var accepted, limited int
	for err := range errorsSeen {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrRateLimited):
			limited++
		default:
			t.Fatalf("concurrent err=%v", err)
		}
	}
	if accepted != 1 || limited != workers-1 {
		t.Fatalf("accepted=%d limited=%d", accepted, limited)
	}
	counts := rateStoreCounts(t, store, conversation.ID)
	if counts.messages != 1 || counts.idempotency != 1 || counts.sequence != 1 {
		t.Fatalf("overspend side effects=%v", counts)
	}
}

func TestStoreRestartPreservesDepletion(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	cfg := tightRateLimits()
	now := time.Date(2026, time.August, 18, 16, 6, 0, 0, time.UTC)
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRateLimits(cfg); err != nil {
		t.Fatal(err)
	}
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "one", "one", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "two", "two", now)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.SetRateLimits(cfg); err != nil {
		t.Fatal(err)
	}
	_, _, err = restarted.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "three", "three", now))
	assertRateLimited(t, err, 1)
	assertNoAppendSideEffects(t, restarted, conversation, 2)
}

func TestStoreTokenRefillAllowsLaterSend(t *testing.T) {
	t.Parallel()
	store := openRateLimitedStore(t, tightRateLimits())
	now := time.Date(2026, time.August, 18, 16, 7, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "one", "one", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "two", "two", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "three", "three", now.Add(500*time.Millisecond)))
	assertRateLimited(t, err, 1)
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "three", "three", now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
}

func TestStoreTwoAgentLoopIsBoundedWithoutBodyInspection(t *testing.T) {
	t.Parallel()
	cfg := tightRateLimits()
	cfg.ConversationBurst = 8
	store := openRateLimitedStore(t, cfg)
	now := time.Date(2026, time.August, 18, 16, 8, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	bodies := []struct {
		machine, endpoint, body, key string
	}{
		{"machine-a", "agent/a", "distinct-a-1", "a-1"},
		{"machine-b", "agent/b", "distinct-b-1", "b-1"},
		{"machine-a", "agent/a", "distinct-a-2", "a-2"},
		{"machine-b", "agent/b", "distinct-b-2", "b-2"},
	}
	for _, item := range bodies {
		if _, _, err := store.AppendMessage(rateAppend(conversation, item.machine, item.endpoint, item.body, item.key, now)); err != nil {
			t.Fatalf("loop body %q: %v", item.body, err)
		}
	}
	_, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "distinct-a-3", "a-3", now))
	assertRateLimited(t, err, 1)
}

func TestRateLimitConfigRejectsOutOfBoundsValues(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	cfg.SenderBurst = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero burst accepted")
	}
	cfg = DefaultRateLimitConfig()
	cfg.RetryAfterMaxSeconds = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero retry-after cap accepted")
	}
}

func openRateLimitedStore(t *testing.T, cfg RateLimitConfig) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SetRateLimits(cfg); err != nil {
		t.Fatal(err)
	}
	return store
}

func createRateTestConversation(t *testing.T, store *Store, now time.Time, machineA, machineB, endpointA, endpointB string) Conversation {
	t.Helper()
	if err := store.AdvertiseEndpoints(machineA, []string{endpointA}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints(machineB, []string{endpointB}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation(endpointA, []Member{
		{Endpoint: endpointA, Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: endpointB, Capabilities: CapSend | CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return conversation
}

func rateAppend(conversation Conversation, machine, endpoint, body, key string, now time.Time) AppendInput {
	return AppendInput{ConversationID: conversation.ID, SenderMachineID: machine, FromEndpoint: endpoint, Body: body, IdempotencyKey: key, Now: now}
}

func assertRateLimited(t *testing.T, err error, retryAfter int) {
	t.Helper()
	var limited *RateLimitedError
	if !errors.Is(err, ErrRateLimited) || !errors.As(err, &limited) || limited.RetryAfterSeconds != retryAfter {
		t.Fatalf("err=%v, want rate limited retry-after %d", err, retryAfter)
	}
}

type rateCounts struct {
	messages, deliveries, idempotency, buckets int
	sequence                                   int64
}

func rateStoreCounts(t *testing.T, store *Store, conversationID string) rateCounts {
	t.Helper()
	var counts rateCounts
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM messages WHERE conversation_id = ?", conversationID).Scan(&counts.messages); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM deliveries d JOIN messages m ON m.id = d.message_id WHERE m.conversation_id = ?", conversationID).Scan(&counts.deliveries); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM idempotency i JOIN messages m ON m.id = i.message_id WHERE m.conversation_id = ?", conversationID).Scan(&counts.idempotency); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), "SELECT next_sequence FROM conversations WHERE id = ?", conversationID).Scan(&counts.sequence); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='rate_buckets'").Scan(&counts.buckets); err != nil {
		t.Fatal(err)
	}
	if counts.buckets == 1 {
		if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM rate_buckets").Scan(&counts.buckets); err != nil {
			t.Fatal(err)
		}
	}
	return counts
}

func assertNoAppendSideEffects(t *testing.T, store *Store, conversation Conversation, messages int) {
	t.Helper()
	counts := rateStoreCounts(t, store, conversation.ID)
	if counts.messages != messages || counts.idempotency != messages || counts.sequence != int64(messages) {
		t.Fatalf("side effects=%v want messages=%d", counts, messages)
	}
}
