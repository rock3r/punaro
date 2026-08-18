package relay

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func tightQuota(recipientCount int, recipientBytes int64, installCount int, installBytes int64) QuotaConfig {
	return QuotaConfig{
		RecipientCount:    recipientCount,
		RecipientBytes:    recipientBytes,
		InstallationCount: installCount,
		InstallationBytes: installBytes,
		RetryAfterSeconds: 9,
	}
}

func TestDecideQuotaRejectsCompleteFanOutWhenAnyCeilingIsHit(t *testing.T) {
	cfg := tightQuota(2, 10, 3, 15)
	recipients := map[string]QuotaCounters{"agent/b": {Count: 1, Bytes: 4}}
	install := QuotaCounters{Count: 1, Bytes: 4}
	allowed := DecideQuota(cfg, recipients, install, []QuotaCharge{{Recipient: "agent/b", Bytes: 4}, {Recipient: "agent/c", Bytes: 4}})
	if !allowed.Allowed || allowed.RetryAfterSeconds != 9 {
		t.Fatalf("expected allow=%#v", allowed)
	}
	deniedRecipient := DecideQuota(cfg, recipients, install, []QuotaCharge{{Recipient: "agent/b", Bytes: 7}})
	if deniedRecipient.Allowed || deniedRecipient.RetryAfterSeconds != 9 {
		t.Fatalf("recipient bytes=%#v", deniedRecipient)
	}
	deniedInstall := DecideQuota(cfg, recipients, install, []QuotaCharge{{Recipient: "agent/c", Bytes: 4}, {Recipient: "agent/d", Bytes: 8}})
	if deniedInstall.Allowed {
		t.Fatalf("installation bytes=%#v", deniedInstall)
	}
}

func TestQuotaConfigRejectsOutOfBoundsValues(t *testing.T) {
	cfg := DefaultQuotaConfig()
	cfg.RecipientCount = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero recipient count was accepted")
	}
	cfg = DefaultQuotaConfig()
	cfg.InstallationBytes = QuotaBytesMax + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("oversized installation bytes were accepted")
	}
}

func TestStoreRecipientPendingCountCeiling(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(1, 1024, 8, 4096))
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", now))
	assertCapacityExceeded(t, err, 9)
	assertNoAppendSideEffects(t, store, conversation, 1)
}

func TestStoreRecipientPendingByteCeiling(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(8, 5, 8, 4096))
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "hello", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "world", "send-2", now))
	assertCapacityExceeded(t, err, 9)
	assertNoAppendSideEffects(t, store, conversation, 1)
}

func TestStoreInstallationPendingCountCeiling(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(8, 1024, 1, 4096))
	now := quotaNow()
	first := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
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
	if _, _, err := store.AppendMessage(quotaAppend(first, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.AppendMessage(quotaAppend(second, "machine-a", "agent/a", "two", "send-2", now))
	assertCapacityExceeded(t, err, 9)
	assertNoAppendSideEffects(t, store, second, 0)
}

func TestStoreInstallationPendingByteCeiling(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(8, 1024, 8, 5))
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "hello", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "world", "send-2", now))
	assertCapacityExceeded(t, err, 9)
	assertNoAppendSideEffects(t, store, conversation, 1)
}

func TestStoreBroadcastDeniesAtomicallyWhenAnyRecipientIsFull(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(1, 1024, 8, 4096))
	now := quotaNow()
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
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", now))
	assertCapacityExceeded(t, err, 9)
	assertNoAppendSideEffects(t, store, conversation, 1)
}

func TestStoreTargetedRoleChargesOnlyTheNamedRole(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(1, 1024, 8, 4096))
	now := quotaNow()
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
		{Role: "role/reviewer", RoleMachineID: "machine-b", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a",
		TargetRole: "role/reviewer", Body: "review", IdempotencyKey: "role-1", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if got := quotaRecipientCounters(t, store, "agent/b"); got != (QuotaCounters{}) {
		t.Fatalf("session recipient charged for targeted role send: %#v", got)
	}
	if got := quotaRecipientCounters(t, store, roleRecipient("role/reviewer")); got != (QuotaCounters{Count: 1, Bytes: 6}) {
		t.Fatalf("role recipient counters=%#v", got)
	}
	_, _, err = store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a",
		TargetRole: "role/reviewer", Body: "again", IdempotencyKey: "role-2", Now: now,
	})
	assertCapacityExceeded(t, err, 9)
	assertNoAppendSideEffects(t, store, conversation, 1)
}

func TestStoreAckReleasesCapacityOnce(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(1, 1024, 8, 4096))
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
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
	if counters := quotaInstallCounters(t, store); counters != (QuotaCounters{}) {
		t.Fatalf("install counters after repeated ack=%#v", counters)
	}
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", now)); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRevocationReleasesCapacityOnce(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(1, 1024, 8, 4096))
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/b", Capabilities: CapSend},
		IdempotencyKey: "revoke-receive", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if counters := quotaInstallCounters(t, store); counters != (QuotaCounters{}) {
		t.Fatalf("install counters after revoke=%#v", counters)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlRemoveMember, Member: Member{Endpoint: "agent/b"},
		IdempotencyKey: "remove-member", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if counters := quotaInstallCounters(t, store); counters != (QuotaCounters{}) {
		t.Fatalf("install counters after remove=%#v", counters)
	}
}

func TestStoreLeaseAndRedeliveryDoNotChangeCapacity(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(1, 1024, 8, 4096))
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	before := quotaInstallCounters(t, store)
	first, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Minute, 10)
	if err != nil || len(first.Deliveries) != 1 {
		t.Fatalf("first lease=%#v err=%v", first, err)
	}
	expired := now.Add(2 * time.Minute)
	second, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, expired, time.Minute, 10)
	if err != nil || len(second.Deliveries) != 1 || second.Deliveries[0].LeaseGeneration <= first.Deliveries[0].LeaseGeneration {
		t.Fatalf("reclaimed lease=%#v original=%#v err=%v", second, first, err)
	}
	if got := quotaInstallCounters(t, store); got != before {
		t.Fatalf("lease changed capacity from %#v to %#v", before, got)
	}
	_, _, err = store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", expired))
	assertCapacityExceeded(t, err, 9)
}

func TestStoreExactIdempotentRetryAtCapacity(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(1, 1024, 8, 4096))
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	input := quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)
	message, _, err := store.AppendMessage(input)
	if err != nil {
		t.Fatal(err)
	}
	repeated, duplicate, err := store.AppendMessage(input)
	if err != nil || !duplicate || repeated.ID != message.ID {
		t.Fatalf("retry=%#v duplicate=%t err=%v", repeated, duplicate, err)
	}
	changed := input
	changed.Body = "other"
	if _, _, err := store.AppendMessage(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed-body err=%v", err)
	}
}

func TestStoreConcurrentAppendCannotOversubscribe(t *testing.T) {
	store := openQuotaStore(t, tightQuota(1, 1024, 1, 4096))
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	const workers = 8
	var accepted, denied atomicCounter
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			_, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "body", "send-"+itoa(i), now))
			switch {
			case err == nil:
				accepted.add(1)
			case errors.Is(err, ErrCapacityExceeded):
				denied.add(1)
			default:
				t.Errorf("append err=%v", err)
			}
		}(i)
	}
	wg.Wait()
	if accepted.value() != 1 || denied.value() != workers-1 {
		t.Fatalf("accepted=%d denied=%d", accepted.value(), denied.value())
	}
	if counters := quotaInstallCounters(t, store); counters.Count != 1 {
		t.Fatalf("install counters=%#v", counters)
	}
}

func TestStoreQuotaSurvivesRestartAndReadiness(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	cfg := tightQuota(1, 1024, 8, 4096)
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetQuotaLimits(cfg); err != nil {
		t.Fatal(err)
	}
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyPendingQuota(); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	restarted, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.SetQuotaLimits(cfg); err != nil {
		t.Fatal(err)
	}
	if err := restarted.VerifyPendingQuota(); err != nil {
		t.Fatal(err)
	}
	_, _, err = restarted.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", now))
	assertCapacityExceeded(t, err, 9)
	if _, err := restarted.db.ExecContext(context.Background(), "UPDATE pending_quota_install SET pending_count = 99"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.VerifyPendingQuota(); err == nil {
		t.Fatal("drifted counters were accepted")
	}
	if _, err := ReconcilePendingQuota(restarted); err != nil {
		t.Fatal(err)
	}
	if err := restarted.VerifyPendingQuota(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreConcurrentAckCannotUnderflow(t *testing.T) {
	store := openQuotaStore(t, tightQuota(8, 1024, 8, 4096))
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	const workers = 8
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			if err := store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now); err != nil {
				t.Errorf("ack err=%v", err)
			}
		}()
	}
	wg.Wait()
	if counters := quotaInstallCounters(t, store); counters != (QuotaCounters{}) {
		t.Fatalf("install counters=%#v", counters)
	}
}

func openQuotaStore(t *testing.T, cfg QuotaConfig) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SetQuotaLimits(cfg); err != nil {
		t.Fatal(err)
	}
	return store
}

func createQuotaConversation(t *testing.T, store *Store, now time.Time, machineA, machineB, endpointA, endpointB string) Conversation {
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

func quotaAppend(conversation Conversation, machine, endpoint, body, key string, now time.Time) AppendInput {
	return AppendInput{ConversationID: conversation.ID, SenderMachineID: machine, FromEndpoint: endpoint, Body: body, IdempotencyKey: key, Now: now}
}

func quotaNow() time.Time {
	return time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
}

func assertCapacityExceeded(t *testing.T, err error, retryAfter int) {
	t.Helper()
	var limited *CapacityError
	if !errors.Is(err, ErrCapacityExceeded) || !errors.As(err, &limited) || limited.RetryAfterSeconds != retryAfter {
		t.Fatalf("err=%v, want capacity exceeded retry-after %d", err, retryAfter)
	}
}

func quotaRecipientCounters(t *testing.T, store *Store, recipient string) QuotaCounters {
	t.Helper()
	var count, bytes int64
	err := store.db.QueryRowContext(context.Background(), `SELECT pending_count, pending_bytes FROM pending_quota_recipients WHERE recipient_endpoint = ?`, recipient).Scan(&count, &bytes)
	if err != nil {
		return QuotaCounters{}
	}
	return QuotaCounters{Count: count, Bytes: bytes}
}

func quotaInstallCounters(t *testing.T, store *Store) QuotaCounters {
	t.Helper()
	var count, bytes int64
	err := store.db.QueryRowContext(context.Background(), `SELECT pending_count, pending_bytes FROM pending_quota_install WHERE singleton = 1`).Scan(&count, &bytes)
	if errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err != nil {
		return QuotaCounters{}
	}
	return QuotaCounters{Count: count, Bytes: bytes}
}

type atomicCounter struct {
	mu sync.Mutex
	n  int
}

func (c *atomicCounter) add(n int) {
	c.mu.Lock()
	c.n += n
	c.mu.Unlock()
}

func (c *atomicCounter) value() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
