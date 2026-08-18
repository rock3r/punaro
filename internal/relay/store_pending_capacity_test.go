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

func tightPendingCapacity() PendingCapacityConfig {
	return PendingCapacityConfig{
		RecipientCount:    2,
		RecipientBytes:    1024,
		InstallationCount: 3,
		InstallationBytes: 2048,
		RetryAfterSeconds: 60,
	}
}

func TestDecidePendingCapacityEnforcesRecipientAndInstallationCeilings(t *testing.T) {
	cfg := PendingCapacityConfig{RecipientCount: 2, RecipientBytes: 100, InstallationCount: 3, InstallationBytes: 150, RetryAfterSeconds: 9}
	current := map[string]struct{ Count, Bytes int64 }{"agent/b": {Count: 1, Bytes: 40}}
	allowed := DecidePendingCapacity(cfg, 1, 40, current, []PendingCharge{{Recipient: "agent/b", Count: 1, Bytes: 40}})
	if !allowed.Allowed {
		t.Fatalf("expected allow, got %#v", allowed)
	}
	deniedRecipientCount := DecidePendingCapacity(cfg, 1, 40, current, []PendingCharge{{Recipient: "agent/b", Count: 2, Bytes: 10}})
	if deniedRecipientCount.Allowed || deniedRecipientCount.RetryAfterSeconds != 9 {
		t.Fatalf("recipient count %#v", deniedRecipientCount)
	}
	deniedRecipientBytes := DecidePendingCapacity(cfg, 1, 40, current, []PendingCharge{{Recipient: "agent/b", Count: 1, Bytes: 70}})
	if deniedRecipientBytes.Allowed {
		t.Fatalf("recipient bytes %#v", deniedRecipientBytes)
	}
	deniedInstall := DecidePendingCapacity(cfg, 3, 40, current, []PendingCharge{{Recipient: "agent/c", Count: 1, Bytes: 10}})
	if deniedInstall.Allowed {
		t.Fatalf("installation count %#v", deniedInstall)
	}
}

func TestPendingCapacityConfigRejectsOutOfBoundsValues(t *testing.T) {
	cfg := DefaultPendingCapacityConfig()
	cfg.RecipientCount = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero recipient count accepted")
	}
	cfg = DefaultPendingCapacityConfig()
	cfg.RecipientBytes = PendingBytesMin - 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("undersized recipient bytes accepted")
	}
	cfg = DefaultPendingCapacityConfig()
	cfg.RetryAfterSeconds = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero retry-after accepted")
	}
}

func TestStoreRecipientCountCeiling(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 1, RecipientBytes: 1024, InstallationCount: 8, InstallationBytes: 8192, RetryAfterSeconds: 60,
	})
	now := time.Date(2026, time.August, 18, 19, 0, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "one", "one", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "two", "two", now))
	assertAtCapacity(t, err, 60)
	assertNoAppendSideEffects(t, store, conversation, 1)
}

func TestStoreRecipientByteCeiling(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 8, RecipientBytes: 8, InstallationCount: 8, InstallationBytes: 1024, RetryAfterSeconds: 15,
	})
	now := time.Date(2026, time.August, 18, 19, 1, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "1234", "one", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "12345", "two", now))
	assertAtCapacity(t, err, 15)
	assertNoAppendSideEffects(t, store, conversation, 1)
}

func TestStoreInstallationCountCeiling(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 8, RecipientBytes: 1024, InstallationCount: 1, InstallationBytes: 1024, RetryAfterSeconds: 60,
	})
	now := time.Date(2026, time.August, 18, 19, 2, 0, 0, time.UTC)
	first := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if err := store.AdvertiseEndpoints("machine-c", []string{"agent/c"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/c", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(first, "machine-a", "agent/a", "one", "one", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.AppendMessage(rateAppend(second, "machine-a", "agent/a", "two", "two", now))
	assertAtCapacity(t, err, 60)
	assertNoAppendSideEffects(t, store, second, 0)
}

func TestStoreInstallationByteCeiling(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 8, RecipientBytes: 1024, InstallationCount: 8, InstallationBytes: 8, RetryAfterSeconds: 30,
	})
	now := time.Date(2026, time.August, 18, 19, 3, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "1234", "one", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "12345", "two", now))
	assertAtCapacity(t, err, 30)
	assertNoAppendSideEffects(t, store, conversation, 1)
}

func TestStoreBroadcastDeniesAtomicallyWhenAnyRecipientIsFull(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 1, RecipientBytes: 1024, InstallationCount: 8, InstallationBytes: 8192, RetryAfterSeconds: 60,
	})
	now := time.Date(2026, time.August, 18, 19, 4, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-c", []string{"agent/c"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
		{Endpoint: "agent/c", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(direct, "machine-a", "agent/a", "fill-b", "fill", now)); err != nil {
		t.Fatal(err)
	}
	before := rateStoreCounts(t, store, conversation.ID)
	_, _, err = store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "broadcast", "broadcast", now))
	assertAtCapacity(t, err, 60)
	after := rateStoreCounts(t, store, conversation.ID)
	if after != before {
		t.Fatalf("partial broadcast state before=%v after=%v", before, after)
	}
}

func TestStoreTargetedRoleChargesOnlyTheRoleRecipient(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 1, RecipientBytes: 1024, InstallationCount: 1, InstallationBytes: 1024, RetryAfterSeconds: 60,
	})
	now := time.Date(2026, time.August, 18, 19, 5, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	role := "role/capacity/reviewer"
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
		{Role: role, RoleMachineID: "machine-b", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-b", role, "agent/b", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a",
		TargetRole: role, Body: "targeted", IdempotencyKey: "targeted", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a",
		TargetRole: role, Body: "again", IdempotencyKey: "again", Now: now,
	})
	assertAtCapacity(t, err, 60)
	assertNoAppendSideEffects(t, store, conversation, 1)
}

func TestStoreAckReleasesOnceAndRepeatedAckDoesNotUnderflow(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 1, RecipientBytes: 1024, InstallationCount: 1, InstallationBytes: 1024, RetryAfterSeconds: 60,
	})
	now := time.Date(2026, time.August, 18, 19, 6, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "one", "one", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "two", "two", now))
	assertAtCapacity(t, err, 60)
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "two", "two", now)); err != nil {
		t.Fatal(err)
	}
	counts := pendingCapacityCounts(t, store)
	if counts.installationCount != 1 || counts.installationBytes != 3 {
		t.Fatalf("underflow after repeated ack: %#v", counts)
	}
}

func TestStoreRevocationRetirementReleasesOnce(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 1, RecipientBytes: 1024, InstallationCount: 1, InstallationBytes: 1024, RetryAfterSeconds: 60,
	})
	now := time.Date(2026, time.August, 18, 19, 7, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "one", "one", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "blocked", "blocked", now))
	assertAtCapacity(t, err, 60)
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlRemoveMember, Member: Member{Endpoint: "agent/b"},
		IdempotencyKey: "remove-b", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlRemoveMember, Member: Member{Endpoint: "agent/b"},
		IdempotencyKey: "remove-b", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-c", []string{"agent/c"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/c", Capabilities: CapReceive},
		IdempotencyKey: "add-c", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "after-revoke", "after", now)); err != nil {
		t.Fatal(err)
	}
	counts := pendingCapacityCounts(t, store)
	if counts.installationCount != 1 || counts.installationBytes != int64(len("after-revoke")) {
		t.Fatalf("revocation release %#v", counts)
	}
}

func TestStoreExpiredLeaseDoesNotReleaseOrDoubleCharge(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 1, RecipientBytes: 1024, InstallationCount: 1, InstallationBytes: 1024, RetryAfterSeconds: 60,
	})
	now := time.Date(2026, time.August, 18, 19, 8, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "one", "one", now)); err != nil {
		t.Fatal(err)
	}
	before := pendingCapacityCounts(t, store)
	first, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Minute, 10)
	if err != nil || len(first.Deliveries) != 1 {
		t.Fatalf("first lease=%#v err=%v", first, err)
	}
	expired := now.Add(time.Minute + time.Second)
	second, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, expired, time.Minute, 10)
	if err != nil || len(second.Deliveries) != 1 {
		t.Fatalf("redelivery=%#v err=%v", second, err)
	}
	after := pendingCapacityCounts(t, store)
	if after != before {
		t.Fatalf("lease mutated capacity before=%#v after=%#v", before, after)
	}
	_, _, err = store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "two", "two", expired))
	assertAtCapacity(t, err, 60)
}

func TestStoreExactIdempotentRetryAtCapacityDoesNotReserveAgain(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 1, RecipientBytes: 1024, InstallationCount: 1, InstallationBytes: 1024, RetryAfterSeconds: 60,
	})
	now := time.Date(2026, time.August, 18, 19, 9, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	input := rateAppend(conversation, "machine-a", "agent/a", "one", "retry-key", now)
	first, _, err := store.AppendMessage(input)
	if err != nil {
		t.Fatal(err)
	}
	replay, duplicate, err := store.AppendMessage(input)
	if err != nil || !duplicate || replay != first {
		t.Fatalf("replay message=%#v duplicate=%t err=%v", replay, duplicate, err)
	}
	_, _, err = store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "two", "new-key", now))
	assertAtCapacity(t, err, 60)
	counts := pendingCapacityCounts(t, store)
	if counts.installationCount != 1 {
		t.Fatalf("idempotent retry reserved again: %#v", counts)
	}
}

func TestStoreConcurrentAppendAndAckCannotOversubscribeOrUnderflow(t *testing.T) {
	t.Parallel()
	store := openCapacityStore(t, PendingCapacityConfig{
		RecipientCount: 1, RecipientBytes: 1024, InstallationCount: 1, InstallationBytes: 1024, RetryAfterSeconds: 60,
	})
	now := time.Date(2026, time.August, 18, 19, 10, 0, 0, time.UTC)
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	const workers = 8
	var started sync.WaitGroup
	started.Add(workers)
	errorsSeen := make(chan error, workers)
	var running sync.WaitGroup
	running.Add(workers)
	for index := 0; index < workers; index++ {
		go func(index int) {
			defer running.Done()
			started.Done()
			started.Wait()
			_, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", fmt.Sprintf("c-%d", index), fmt.Sprintf("c-%d", index), now))
			errorsSeen <- err
		}(index)
	}
	running.Wait()
	close(errorsSeen)
	var accepted, limited int
	for err := range errorsSeen {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrAtCapacity):
			limited++
		default:
			t.Fatalf("concurrent err=%v", err)
		}
	}
	if accepted != 1 || limited != workers-1 {
		t.Fatalf("accepted=%d limited=%d", accepted, limited)
	}
	counts := pendingCapacityCounts(t, store)
	if counts.installationCount != 1 || counts.recipientCount != 1 {
		t.Fatalf("oversubscribe %#v", counts)
	}
}

func TestStoreRestartPreservesPendingCapacityAndReadiness(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	cfg := PendingCapacityConfig{
		RecipientCount: 1, RecipientBytes: 1024, InstallationCount: 1, InstallationBytes: 1024, RetryAfterSeconds: 60,
	}
	now := time.Date(2026, time.August, 18, 19, 11, 0, 0, time.UTC)
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPendingCapacity(cfg); err != nil {
		t.Fatal(err)
	}
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "one", "one", now)); err != nil {
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
	if err := restarted.SetPendingCapacity(cfg); err != nil {
		t.Fatal(err)
	}
	_, _, err = restarted.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "two", "two", now))
	assertAtCapacity(t, err, 60)
}

func TestStoreReadinessFailsClosedOnCounterDriftAndReconcileRepairs(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	cfg := tightPendingCapacity()
	now := time.Date(2026, time.August, 18, 19, 12, 0, 0, time.UTC)
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPendingCapacity(cfg); err != nil {
		t.Fatal(err)
	}
	conversation := createRateTestConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(rateAppend(conversation, "machine-a", "agent/a", "one", "one", now)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `UPDATE pending_capacity SET pending_count=99 WHERE scope='installation'`); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyPendingCapacity(); err == nil {
		t.Fatal("drifted counters were accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(database); err == nil {
		_ = reopened.Close()
		t.Fatal("Open accepted drifted pending-capacity counters")
	}
	if err := ReconcilePendingCapacityFile(database); err != nil {
		t.Fatal(err)
	}
	repaired, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repaired.Close() })
	counts := pendingCapacityCounts(t, repaired)
	if counts.installationCount != 1 || counts.installationBytes != 3 {
		t.Fatalf("reconcile %#v", counts)
	}
}

func openCapacityStore(t *testing.T, cfg PendingCapacityConfig) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SetPendingCapacity(cfg); err != nil {
		t.Fatal(err)
	}
	return store
}

func assertAtCapacity(t *testing.T, err error, retryAfter int) {
	t.Helper()
	var limited *CapacityError
	if !errors.Is(err, ErrAtCapacity) || !errors.As(err, &limited) || limited.RetryAfterSeconds != retryAfter {
		t.Fatalf("err=%v, want at capacity retry-after %d", err, retryAfter)
	}
}

type pendingCounts struct {
	installationCount, installationBytes int64
	recipientCount, recipientBytes       int64
}

func pendingCapacityCounts(t *testing.T, store *Store) pendingCounts {
	t.Helper()
	var counts pendingCounts
	err := store.db.QueryRowContext(context.Background(), `SELECT pending_count, pending_bytes FROM pending_capacity WHERE scope='installation' AND scope_key=''`).Scan(&counts.installationCount, &counts.installationBytes)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.db.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(pending_count),0), COALESCE(SUM(pending_bytes),0) FROM pending_capacity WHERE scope='recipient'`).Scan(&counts.recipientCount, &counts.recipientBytes)
	return counts
}
