package relay

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tightRetention(maxAge, keep time.Duration, batch int) RetentionConfig {
	return RetentionConfig{PendingMaxAge: maxAge, TerminalRetention: keep, MaintenanceBatch: batch}
}

func TestRetentionConfigRejectsOutOfBoundsValues(t *testing.T) {
	cfg := DefaultRetentionConfig()
	cfg.PendingMaxAge = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero pending max age was accepted")
	}
	cfg = DefaultRetentionConfig()
	cfg.TerminalRetention = RetentionTerminalMax + time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("oversized terminal retention was accepted")
	}
	cfg = DefaultRetentionConfig()
	cfg.MaintenanceBatch = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero maintenance batch was accepted")
	}
}

func TestStoreExpiryBoundaryJustBeforeAtAndAfter(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Hour, 24*time.Hour, 100))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "secret-body", "send-1", now)); err != nil {
		t.Fatal(err)
	}

	before := now.Add(time.Hour - time.Millisecond)
	if result, err := store.ExpirePendingDeliveries(before); err != nil || result.Expired != 0 {
		t.Fatalf("just before expiry result=%#v err=%v", result, err)
	}
	if pending := quotaInstallCounters(t, store); pending.Count != 1 {
		t.Fatalf("pending before boundary=%#v", pending)
	}

	at := now.Add(time.Hour)
	if result, err := store.ExpirePendingDeliveries(at); err != nil || result.Expired != 1 {
		t.Fatalf("at expiry result=%#v err=%v", result, err)
	}
	if pending := quotaInstallCounters(t, store); pending != (QuotaCounters{}) {
		t.Fatalf("pending at boundary=%#v", pending)
	}

	after := now.Add(time.Hour + time.Millisecond)
	if result, err := store.ExpirePendingDeliveries(after); err != nil || result.Expired != 0 {
		t.Fatalf("repeat expiry result=%#v err=%v", result, err)
	}
}

func TestStoreExpiryReleasesCapacityExactlyOnce(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Hour, 24*time.Hour, 100))
	if err := store.SetQuotaLimits(tightQuota(8, 1024, 8, 4096)); err != nil {
		t.Fatal(err)
	}
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "hello", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if counters := quotaInstallCounters(t, store); counters.Count != 1 || counters.Bytes != 5 {
		t.Fatalf("reserved=%#v", counters)
	}
	if result, err := store.ExpirePendingDeliveries(now.Add(time.Hour)); err != nil || result.Expired != 1 {
		t.Fatalf("expire result=%#v err=%v", result, err)
	}
	if counters := quotaInstallCounters(t, store); counters != (QuotaCounters{}) {
		t.Fatalf("after expire=%#v", counters)
	}
	if result, err := store.ExpirePendingDeliveries(now.Add(2 * time.Hour)); err != nil || result.Expired != 0 {
		t.Fatalf("second expire result=%#v err=%v", result, err)
	}
	if counters := quotaInstallCounters(t, store); counters != (QuotaCounters{}) {
		t.Fatalf("after second expire=%#v", counters)
	}
	if err := store.VerifyPendingQuota(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreExpiryBoundedBatchContinuesStably(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Hour, 24*time.Hour, 2))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	for i := 1; i <= 3; i++ {
		if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "n", "send-"+itoa(i), now.Add(time.Duration(i)*time.Millisecond))); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.ExpirePendingDeliveries(now.Add(time.Hour + time.Second))
	if err != nil || first.Expired != 2 {
		t.Fatalf("first batch=%#v err=%v", first, err)
	}
	if pending := quotaInstallCounters(t, store); pending.Count != 1 {
		t.Fatalf("after first batch pending=%#v", pending)
	}
	second, err := store.ExpirePendingDeliveries(now.Add(time.Hour + time.Second))
	if err != nil || second.Expired != 1 {
		t.Fatalf("second batch=%#v err=%v", second, err)
	}
	if pending := quotaInstallCounters(t, store); pending.Count != 0 {
		t.Fatalf("after second batch pending=%#v", pending)
	}
}

func TestStoreExpiredLeaseCannotAck(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Hour, 24*time.Hour, 100))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "body", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	if _, err := store.ExpirePendingDeliveries(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now.Add(time.Hour)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired ack err=%v", err)
	}
}

func TestStoreExpiryAdvancesOnlyExpiredRecipientCursor(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(2*time.Hour, 24*time.Hour, 100))
	now := retentionNow()
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
	first, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "old", "send-1", now))
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, later, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, later, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-c", []string{"agent/c"}, later, time.Hour); err != nil {
		t.Fatal(err)
	}
	second, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "young", "send-2", later))
	if err != nil {
		t.Fatal(err)
	}
	expireAt := now.Add(2 * time.Hour)
	if result, err := store.ExpirePendingDeliveries(expireAt); err != nil || result.Expired != 2 {
		t.Fatalf("expire old fan-out result=%#v err=%v", result, err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, expireAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-c", []string{"agent/c"}, expireAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	cursorB, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt)
	if err != nil || cursorB != first.Sequence {
		t.Fatalf("expired recipient cursor=%d err=%v want %d", cursorB, err, first.Sequence)
	}
	page, err := store.LeaseDeliveries("machine-c", "consumer-c", "agent/c", conversation.ID, expireAt, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 || page.Deliveries[0].Message.Sequence != second.Sequence {
		t.Fatalf("independent recipient lease=%#v err=%v", page, err)
	}
	if err := store.AckDelivery("machine-c", "agent/c", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, expireAt); err != nil {
		t.Fatal(err)
	}
	cursorC, err := store.RecipientCursor("machine-c", "agent/c", conversation.ID, expireAt)
	if err != nil || cursorC != second.Sequence {
		t.Fatalf("acked recipient cursor=%d err=%v want %d", cursorC, err, second.Sequence)
	}
}

func TestStoreExpiredGapThenAckAdvancesContiguousCursor(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(2*time.Hour, 24*time.Hour, 100))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "old", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, later, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, later, time.Hour); err != nil {
		t.Fatal(err)
	}
	second, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "young", "send-2", later))
	if err != nil {
		t.Fatal(err)
	}
	expireAt := now.Add(2 * time.Hour)
	if result, err := store.ExpirePendingDeliveries(expireAt); err != nil || result.Expired != 1 {
		t.Fatalf("expire gap result=%#v err=%v", result, err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, expireAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt)
	if err != nil || cursor != 1 {
		t.Fatalf("cursor after expired gap=%d err=%v", cursor, err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, expireAt, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 || page.Deliveries[0].Message.ID != second.ID {
		t.Fatalf("lease after gap=%#v err=%v", page, err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, expireAt); err != nil {
		t.Fatal(err)
	}
	cursor, err = store.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt)
	if err != nil || cursor != 2 {
		t.Fatalf("cursor after ack across expired gap=%d err=%v", cursor, err)
	}
}

func TestStoreTerminalRetentionAndBoundedPrune(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Hour, 2*time.Hour, 1))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", now.Add(time.Millisecond))); err != nil {
		t.Fatal(err)
	}
	closedAt := now.Add(time.Hour + time.Millisecond)
	if result, err := store.ExpirePendingDeliveries(closedAt); err != nil || result.Expired != 1 {
		t.Fatalf("first expire result=%#v err=%v", result, err)
	}
	if result, err := store.ExpirePendingDeliveries(closedAt); err != nil || result.Expired != 1 {
		t.Fatalf("second expire result=%#v err=%v", result, err)
	}
	beforeKeep := closedAt.Add(2*time.Hour - time.Millisecond)
	if result, err := store.PruneTerminalDeliveries(beforeKeep); err != nil || result.Pruned != 0 {
		t.Fatalf("before retention prune=%#v err=%v", result, err)
	}
	page, err := store.ListTerminalDeliveries(10, "")
	if err != nil || len(page.Records) != 2 {
		t.Fatalf("retained page=%#v err=%v", page, err)
	}
	pruneAt := closedAt.Add(2 * time.Hour)
	first, err := store.PruneTerminalDeliveries(pruneAt)
	if err != nil || first.Pruned != 1 {
		t.Fatalf("first prune=%#v err=%v", first, err)
	}
	second, err := store.PruneTerminalDeliveries(pruneAt)
	if err != nil || second.Pruned != 1 {
		t.Fatalf("second prune=%#v err=%v", second, err)
	}
	empty, err := store.ListTerminalDeliveries(10, "")
	if err != nil || len(empty.Records) != 0 {
		t.Fatalf("after prune page=%#v err=%v", empty, err)
	}
}

func TestStoreOperatorTerminalListOmitsBodies(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Hour, 24*time.Hour, 100))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	const body = "untrusted-secret-body"
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", body, "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExpirePendingDeliveries(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	page, err := store.ListTerminalDeliveries(10, "")
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	record := page.Records[0]
	if record.ClosedReason != ClosedReasonExpired || record.Sequence != 1 || record.ConversationID != conversation.ID || record.RecipientID != "agent/b" {
		t.Fatalf("record=%#v", record)
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), body) || strings.Contains(string(encoded), `"body"`) {
		t.Fatalf("operator page leaked body: %s", encoded)
	}
}

func TestStoreRetentionMetricsAreBoundedAndContentFree(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Hour, 24*time.Hour, 100))
	metrics := &Metrics{}
	store.SetMetrics(metrics)
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "payload", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	redeliverAt := now.Add(2 * time.Minute)
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, redeliverAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, redeliverAt, time.Minute, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExpirePendingDeliveries(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	snapshot := metrics.Snapshot()
	if snapshot.RelayTerminalTransitionsExpired != 1 || snapshot.RelayLeaseRedeliveries != 1 || snapshot.RelayTerminalRetained != 1 {
		t.Fatalf("snapshot=%#v", snapshot)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"agent/b", "payload", "machine-b", conversation.ID} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("metrics leaked %q: %s", leaked, encoded)
		}
	}
}

func TestStoreExpirySurvivesRestart(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	cfg := tightRetention(time.Hour, 24*time.Hour, 100)
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRetentionPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	restarted, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.SetRetentionPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	if result, err := restarted.ExpirePendingDeliveries(now.Add(time.Hour)); err != nil || result.Expired != 1 {
		t.Fatalf("restart expire=%#v err=%v", result, err)
	}
	if err := restarted.VerifyPendingQuota(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreConcurrentExpiryAndAck(t *testing.T) {
	store := openRetentionStore(t, tightRetention(time.Hour, 24*time.Hour, 100))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "race", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Hour, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	expireAt := now.Add(time.Hour)
	var wg sync.WaitGroup
	wg.Add(2)
	var ackErr, expireErr error
	var expired int
	go func() {
		defer wg.Done()
		ackErr = store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, expireAt)
	}()
	go func() {
		defer wg.Done()
		var result MaintenanceResult
		result, expireErr = store.ExpirePendingDeliveries(expireAt)
		expired = result.Expired
	}()
	wg.Wait()
	if expireErr != nil {
		t.Fatalf("expire err=%v", expireErr)
	}
	acked := ackErr == nil
	forbidden := errors.Is(ackErr, ErrForbidden)
	if !acked && !forbidden {
		t.Fatalf("ack err=%v", ackErr)
	}
	if acked && expired != 0 {
		t.Fatalf("ack succeeded and expiry also transitioned expired=%d", expired)
	}
	if forbidden && expired != 1 {
		t.Fatalf("ack forbidden but expiry expired=%d", expired)
	}
	if counters := quotaInstallCounters(t, store); counters != (QuotaCounters{}) {
		t.Fatalf("capacity after race=%#v", counters)
	}
	if err := store.VerifyPendingQuota(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreExpiryDoesNotChangeAnotherRecipient(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Hour, 24*time.Hour, 100))
	now := retentionNow()
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
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "fan", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-c", "consumer-c", "agent/c", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease C=%#v err=%v", page, err)
	}
	if err := store.AckDelivery("machine-c", "agent/c", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ExpirePendingDeliveries(now.Add(time.Hour)); err != nil || result.Expired != 1 {
		t.Fatalf("expire remaining=%#v err=%v", result, err)
	}
	if err := store.AdvertiseEndpoints("machine-c", []string{"agent/c"}, now.Add(time.Hour), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AckDelivery("machine-c", "agent/c", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRoleDeliveryExpiryIsIndependent(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Hour, 24*time.Hour, 100))
	now := retentionNow()
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "role-create", CreatorEndpoint: "agent/a", Now: now,
		Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
			{Role: "role/reviewer", RoleMachineID: "machine-b", Capabilities: CapReceive},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "role-body", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if result, err := store.ExpirePendingDeliveries(now.Add(time.Hour)); err != nil || result.Expired != 1 {
		t.Fatalf("role expire=%#v err=%v", result, err)
	}
	page, err := store.ListTerminalDeliveries(10, "")
	if err != nil || len(page.Records) != 1 || page.Records[0].RecipientID != roleRecipient("role/reviewer") {
		t.Fatalf("role terminal=%#v err=%v", page, err)
	}
}

func retentionNow() time.Time {
	return time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
}

func openRetentionStore(t *testing.T, cfg RetentionConfig) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SetRetentionPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestStoreTwoAgentLoopIsBoundedByRateQuotaAndExpiry(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	cfg := tightRetention(time.Hour, 24*time.Hour, 100)
	if err := store.SetRetentionPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRateLimits(RateLimitConfig{SenderBurst: 2, SenderRefillPerMinute: 60, ConversationBurst: 2, ConversationRefillPerMinute: 60, RetryAfterMaxSeconds: 9}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetQuotaLimits(tightQuota(2, 1024, 4, 4096)); err != nil {
		t.Fatal(err)
	}
	now := retentionNow()
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapSend | CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "a1", "a-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-b", "agent/b", "b1", "b-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "a2", "a-2", now)); !errors.Is(err, ErrCapacityExceeded) && !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third distinct loop message err=%v", err)
	}
	replay, duplicate, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "a1", "a-1", now))
	if err != nil || !duplicate || replay.Sequence != 1 {
		t.Fatalf("idempotent retry message=%#v duplicate=%t err=%v", replay, duplicate, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.SetRetentionPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	if err := restarted.SetRateLimits(RateLimitConfig{SenderBurst: 2, SenderRefillPerMinute: 60, ConversationBurst: 2, ConversationRefillPerMinute: 60, RetryAfterMaxSeconds: 9}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.SetQuotaLimits(tightQuota(2, 1024, 4, 4096)); err != nil {
		t.Fatal(err)
	}
	if err := restarted.VerifyPendingQuota(); err != nil {
		t.Fatal(err)
	}
	if result, err := restarted.ExpirePendingDeliveries(now.Add(time.Hour)); err != nil || result.Expired != 2 {
		t.Fatalf("loop expiry=%#v err=%v", result, err)
	}
	if counters := quotaInstallCounters(t, restarted); counters != (QuotaCounters{}) {
		t.Fatalf("capacity after expiry=%#v", counters)
	}
	if err := restarted.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now.Add(time.Hour), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := restarted.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now.Add(time.Hour), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "a3", "a-3", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := restarted.VerifyPendingQuota(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreAckIdempotenceStillSucceedsForAckedDeliveries(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, DefaultRetentionConfig())
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "keep", "send-1", now)); err != nil {
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
	listed, err := store.ListTerminalDeliveries(10, "")
	if err != nil || len(listed.Records) != 0 {
		t.Fatalf("acked deliveries were listed as dead letters: %#v err=%v", listed, err)
	}
}
