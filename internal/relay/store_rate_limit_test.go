package relay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStoreSenderBucketExhaustionAcrossConversations(t *testing.T) {
	t.Parallel()
	store, now := openRateLimitedStore(t, RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 10, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60})
	first := createRateLimitConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	second := createRateLimitConversation(t, store, now, "machine-a", "machine-c", "agent/a", "agent/c")
	if _, _, err := store.AppendMessage(rateLimitAppend(first.ID, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateLimitAppend(second.ID, "machine-a", "agent/a", "two", "send-2", now)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("cross-conversation sender exhaustion err=%v", err)
	}
}

func TestStoreConversationBucketExhaustionAcrossSenders(t *testing.T) {
	t.Parallel()
	store, now := openRateLimitedStore(t, RateLimitPolicy{SenderBurst: 10, SenderRefillPerMinute: 60, ConversationBurst: 1, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60})
	conversation := createRateLimitConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "one", "send-a", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-b", "agent/b", "two", "send-b", now)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("cross-sender conversation exhaustion err=%v", err)
	}
}

func TestStoreTokenRefillAndExactRetryAfter(t *testing.T) {
	t.Parallel()
	store, now := openRateLimitedStore(t, RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 30, ConversationBurst: 10, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60})
	conversation := createRateLimitConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "two", "send-2", now))
	var limited *RateLimitedError
	if !errors.As(err, &limited) || limited.RetryAfterSeconds() != 2 {
		t.Fatalf("retry-after err=%v limited=%#v", err, limited)
	}
	if _, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "two", "send-2", now.Add(time.Second))); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("partial refill err=%v", err)
	}
	if _, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "two", "send-2", now.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
}

func TestStoreExactCommittedRetryWhileBucketEmpty(t *testing.T) {
	t.Parallel()
	store, now := openRateLimitedStore(t, RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 1, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60})
	conversation := createRateLimitConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	input := rateLimitAppend(conversation.ID, "machine-a", "agent/a", "original", "send-1", now)
	first, _, err := store.AppendMessage(input)
	if err != nil {
		t.Fatal(err)
	}
	repeated, duplicate, err := store.AppendMessage(input)
	if err != nil || !duplicate || repeated != first {
		t.Fatalf("committed retry message=%#v duplicate=%t err=%v", repeated, duplicate, err)
	}
	if _, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "other", "send-2", now)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("empty-bucket new send err=%v", err)
	}
}

func TestStoreChangedBodyKeyConflictIsNotRateLimited(t *testing.T) {
	t.Parallel()
	store, now := openRateLimitedStore(t, RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 1, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60})
	conversation := createRateLimitConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	input := rateLimitAppend(conversation.ID, "machine-a", "agent/a", "original", "send-1", now)
	if _, _, err := store.AppendMessage(input); err != nil {
		t.Fatal(err)
	}
	changed := input
	changed.Body = "changed"
	if _, _, err := store.AppendMessage(changed); !errors.Is(err, ErrConflict) || errors.Is(err, ErrRateLimited) {
		t.Fatalf("changed-body err=%v", err)
	}
}

func TestStoreRejectedRequestHasZeroDurableSideEffects(t *testing.T) {
	t.Parallel()
	store, now := openRateLimitedStore(t, RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 10, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60})
	conversation := createRateLimitConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	before := durableAppendSnapshot(t, store, conversation.ID)
	if _, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "two", "send-2", now)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rejected send err=%v", err)
	}
	after := durableAppendSnapshot(t, store, conversation.ID)
	if after != before {
		t.Fatalf("rate-limit rejection mutated durable state before=%#v after=%#v", before, after)
	}
	if _, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "two", "send-2", now.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
}

func TestStoreConcurrentSendsCannotOverspendBucket(t *testing.T) {
	t.Parallel()
	store, now := openRateLimitedStore(t, RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 8, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60})
	conversation := createRateLimitConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	const workers = 8
	results := make(chan error, workers)
	var started sync.WaitGroup
	started.Add(workers)
	release := make(chan struct{})
	for index := 0; index < workers; index++ {
		go func(index int) {
			started.Done()
			<-release
			_, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", fmt.Sprintf("body-%d", index), fmt.Sprintf("send-%d", index), now))
			results <- err
		}(index)
	}
	started.Wait()
	close(release)
	accepted, rejected := 0, 0
	for index := 0; index < workers; index++ {
		err := <-results
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrRateLimited):
			rejected++
		default:
			t.Fatalf("concurrent send err=%v", err)
		}
	}
	if accepted != 1 || rejected != workers-1 {
		t.Fatalf("accepted=%d rejected=%d", accepted, rejected)
	}
	snapshot := durableAppendSnapshot(t, store, conversation.ID)
	if snapshot.Messages != 1 || snapshot.Sequence != 1 || snapshot.Idempotency != 1 {
		t.Fatalf("overspend snapshot=%#v", snapshot)
	}
}

func TestStoreRestartPreservesDepletion(t *testing.T) {
	t.Parallel()
	policy := RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 10, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60}
	database := filepath.Join(t.TempDir(), "relay.db")
	now := time.Date(2026, time.August, 18, 15, 0, 0, 0, time.UTC)
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRateLimitPolicy(policy); err != nil {
		t.Fatal(err)
	}
	conversation := createRateLimitConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
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
	if err := restarted.SetRateLimitPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.AppendMessage(rateLimitAppend(conversation.ID, "machine-a", "agent/a", "two", "send-2", now)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("restarted depletion err=%v", err)
	}
}

func TestStoreInvalidRateLimitPolicyIsRejected(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SetRateLimitPolicy(RateLimitPolicy{}); err == nil {
		t.Fatal("empty rate-limit policy was accepted")
	}
}

func TestStoreTargetedRoleSendStillChargesSenderAndConversation(t *testing.T) {
	t.Parallel()
	store, now := openRateLimitedStore(t, RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 10, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60})
	if err := store.AdvertiseEndpoints("machine-sender", []string{"agent/sender/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-reviewer", []string{"agent/reviewer/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/sender/session", []Member{
		{Endpoint: "agent/sender/session", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: "role/reviewer", RoleMachineID: "machine-reviewer", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-reviewer", "role/reviewer", "agent/reviewer/session", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	input := AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-sender", FromEndpoint: "agent/sender/session", TargetRole: "role/reviewer", Body: "targeted", IdempotencyKey: "targeted-1", Now: now}
	if _, _, err := store.AppendMessage(input); err != nil {
		t.Fatal(err)
	}
	broadcast := input
	broadcast.TargetRole = ""
	broadcast.IdempotencyKey = "broadcast-2"
	broadcast.Body = "broadcast"
	if _, _, err := store.AppendMessage(broadcast); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("targeted send did not charge the sender bucket err=%v", err)
	}
}

type durableRelaySnapshot struct {
	Sequence     int64
	Messages     int64
	Deliveries   int64
	Idempotency  int64
	RateBuckets  int64
	BucketTokens int64
}

func durableAppendSnapshot(t *testing.T, store *Store, conversationID string) durableRelaySnapshot {
	t.Helper()
	var snapshot durableRelaySnapshot
	if err := store.db.QueryRowContext(context.Background(), `SELECT next_sequence FROM conversations WHERE id=?`, conversationID).Scan(&snapshot.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), `SELECT count(*) FROM messages WHERE conversation_id=?`, conversationID).Scan(&snapshot.Messages); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), `SELECT count(*) FROM deliveries`).Scan(&snapshot.Deliveries); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), `SELECT count(*) FROM idempotency`).Scan(&snapshot.Idempotency); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), `SELECT count(*), COALESCE(sum(tokens_milli),0) FROM rate_buckets`).Scan(&snapshot.RateBuckets, &snapshot.BucketTokens); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	return snapshot
}

func openRateLimitedStore(t *testing.T, policy RateLimitPolicy) (*Store, time.Time) {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SetRateLimitPolicy(policy); err != nil {
		t.Fatal(err)
	}
	return store, time.Date(2026, time.August, 18, 15, 0, 0, 0, time.UTC)
}

func createRateLimitConversation(t *testing.T, store *Store, now time.Time, machineA, machineB, endpointA, endpointB string) Conversation {
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

func rateLimitAppend(conversationID, machineID, endpoint, body, key string, now time.Time) AppendInput {
	return AppendInput{ConversationID: conversationID, SenderMachineID: machineID, FromEndpoint: endpoint, Body: body, IdempotencyKey: key, Now: now}
}
