package relay

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func tightRetention(maxAge, retention, batch int) RetentionConfig {
	return RetentionConfig{PendingMaxAgeSeconds: maxAge, TerminalRetentionSeconds: retention, MaintenanceBatch: batch}
}

func TestRetentionConfigRejectsOutOfBoundsValues(t *testing.T) {
	cfg := DefaultRetentionConfig()
	cfg.PendingMaxAgeSeconds = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero pending max age was accepted")
	}
	cfg = DefaultRetentionConfig()
	cfg.TerminalRetentionSeconds = RetentionAgeMaxSeconds + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("oversized terminal retention was accepted")
	}
	cfg = DefaultRetentionConfig()
	cfg.MaintenanceBatch = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero maintenance batch was accepted")
	}
}

func TestStoreExpiresAtPendingAgeBoundary(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	first, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now))
	if err != nil {
		t.Fatal(err)
	}
	justBefore := now.Add(60*time.Second - time.Millisecond)
	before, err := store.MaintainDeliveries(justBefore)
	if err != nil || before.Expired != 0 {
		t.Fatalf("just before expiry result=%#v err=%v", before, err)
	}
	if pending := quotaInstallCounters(t, store); pending.Count != 1 {
		t.Fatalf("pending before expiry=%#v", pending)
	}
	atBoundary, err := store.MaintainDeliveries(now.Add(60 * time.Second))
	if err != nil || atBoundary.Expired != 1 {
		t.Fatalf("at expiry result=%#v err=%v", atBoundary, err)
	}
	if pending := quotaInstallCounters(t, store); pending != (QuotaCounters{}) {
		t.Fatalf("pending after expiry=%#v", pending)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now.Add(61*time.Second), time.Minute, 10)
	if err != nil || len(page.Deliveries) != 0 {
		t.Fatalf("expired delivery was leased page=%#v err=%v", page, err)
	}
	cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, now.Add(61*time.Second))
	if err != nil || cursor != first.Sequence {
		t.Fatalf("expired cursor=%d want=%d err=%v", cursor, first.Sequence, err)
	}
	after, err := store.MaintainDeliveries(now.Add(61 * time.Second))
	if err != nil || after.Expired != 0 {
		t.Fatalf("after expiry result=%#v err=%v", after, err)
	}
}

func TestStoreMaintainDeliveriesPagesWithStableContinuation(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 2))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	for i, key := range []string{"send-1", "send-2", "send-3"} {
		if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", key, key, now.Add(time.Duration(i)*time.Millisecond))); err != nil {
			t.Fatal(err)
		}
	}
	later := now.Add(61 * time.Second)
	first, err := store.MaintainDeliveries(later)
	if err != nil || first.Expired != 2 || first.Scanned < 2 {
		t.Fatalf("first page=%#v err=%v", first, err)
	}
	if pending := quotaInstallCounters(t, store); pending.Count != 1 {
		t.Fatalf("pending after first page=%#v", pending)
	}
	second, err := store.MaintainDeliveries(later)
	if err != nil || second.Expired != 1 {
		t.Fatalf("second page=%#v err=%v", second, err)
	}
	if pending := quotaInstallCounters(t, store); pending != (QuotaCounters{}) {
		t.Fatalf("pending after second page=%#v", pending)
	}
	third, err := store.MaintainDeliveries(later)
	if err != nil || third.Expired != 0 {
		t.Fatalf("empty continuation=%#v err=%v", third, err)
	}
}

func TestStoreMaintainDeliveriesPersistsPartialPageAcrossRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRetentionPolicy(tightRetention(60, 3600, 2)); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	for i, key := range []string{"send-1", "send-2", "send-3"} {
		if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", key, key, now.Add(time.Duration(i)*time.Millisecond))); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
	}
	later := now.Add(61 * time.Second)
	first, err := store.MaintainDeliveries(later)
	if err != nil || first.Expired != 2 {
		_ = store.Close()
		t.Fatalf("first page=%#v err=%v", first, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.SetRetentionPolicy(tightRetention(60, 3600, 2)); err != nil {
		t.Fatal(err)
	}
	if pending := quotaInstallCounters(t, restarted); pending.Count != 1 {
		t.Fatalf("pending after restart=%#v", pending)
	}
	listed, err := restarted.ListTerminalDeliveries("", 10)
	if err != nil || len(listed.Terminals) != 2 {
		t.Fatalf("terminals after restart=%#v err=%v", listed, err)
	}
	second, err := restarted.MaintainDeliveries(later)
	if err != nil || second.Expired != 1 {
		t.Fatalf("second page after restart=%#v err=%v", second, err)
	}
}

func TestStoreExpiryReleasesCapacityOnce(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	later := now.Add(61 * time.Second)
	first, err := store.MaintainDeliveries(later)
	if err != nil || first.Expired != 1 {
		t.Fatalf("first expire=%#v err=%v", first, err)
	}
	second, err := store.MaintainDeliveries(later)
	if err != nil || second.Expired != 0 {
		t.Fatalf("repeat expire=%#v err=%v", second, err)
	}
	if pending := quotaInstallCounters(t, store); pending != (QuotaCounters{}) {
		t.Fatalf("quota after repeat expire=%#v", pending)
	}
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", later)); err != nil {
		t.Fatal(err)
	}
	if pending := quotaInstallCounters(t, store); pending.Count != 1 {
		t.Fatalf("quota after reuse=%#v", pending)
	}
}

func TestStoreExpiredActiveLeaseCannotAck(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	if _, err := store.MaintainDeliveries(now.Add(61 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now.Add(61*time.Second)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired lease ack err=%v", err)
	}
	if pending := quotaInstallCounters(t, store); pending != (QuotaCounters{}) {
		t.Fatalf("quota after forbidden ack=%#v", pending)
	}
}

func TestStoreExpiredGapThenAckAdvancesContiguousCursor(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	first, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now))
	if err != nil {
		t.Fatal(err)
	}
	secondAt := now.Add(30 * time.Second)
	second, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", secondAt))
	if err != nil {
		t.Fatal(err)
	}
	expireAt := now.Add(60 * time.Second)
	result, err := store.MaintainDeliveries(expireAt)
	if err != nil || result.Expired != 1 {
		t.Fatalf("expire older only result=%#v err=%v", result, err)
	}
	cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt)
	if err != nil || cursor != first.Sequence {
		t.Fatalf("cursor after expired gap=%d want=%d err=%v", cursor, first.Sequence, err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, expireAt, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 || page.Deliveries[0].Message.ID != second.ID {
		t.Fatalf("remaining lease=%#v err=%v", page, err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, expireAt); err != nil {
		t.Fatal(err)
	}
	cursor, err = store.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt)
	if err != nil || cursor != second.Sequence {
		t.Fatalf("cursor after ack across expired gap=%d want=%d err=%v", cursor, second.Sequence, err)
	}
}

func TestStoreExpiryDoesNotAdvanceAnotherRecipient(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
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
		{Endpoint: "agent/b", Capabilities: CapSend | CapReceive},
		{Endpoint: "agent/c", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now))
	if err != nil {
		t.Fatal(err)
	}
	secondAt := now.Add(30 * time.Second)
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", secondAt)); err != nil {
		t.Fatal(err)
	}
	expireAt := now.Add(60 * time.Second)
	if _, err := store.MaintainDeliveries(expireAt); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-c", "consumer-c", "agent/c", conversation.ID, expireAt, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("recipient c remaining lease=%#v err=%v", page, err)
	}
	if err := store.AckDelivery("machine-c", "agent/c", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, expireAt); err != nil {
		t.Fatal(err)
	}
	cursorB, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt)
	if err != nil || cursorB != first.Sequence {
		t.Fatalf("recipient b cursor=%d want=%d err=%v", cursorB, first.Sequence, err)
	}
	cursorC, err := store.RecipientCursor("machine-c", "agent/c", conversation.ID, expireAt)
	if err != nil || cursorC != 2 {
		t.Fatalf("recipient c cursor=%d err=%v", cursorC, err)
	}
	pageB, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, expireAt, time.Minute, 10)
	if err != nil || len(pageB.Deliveries) != 1 || pageB.Deliveries[0].Message.Sequence != 2 {
		t.Fatalf("recipient b remaining=%#v err=%v", pageB, err)
	}
}

func TestStoreTargetedRoleExpiryDoesNotAffectSessionRecipient(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
	now := retentionNow()
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
	if err := store.BindRoleToSession("machine-b", "role/reviewer", "agent/b", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	first, _, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a",
		TargetRole: "role/reviewer", Body: "review", IdempotencyKey: "role-1", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := quotaRecipientCounters(t, store, "agent/b"); got != (QuotaCounters{}) {
		t.Fatalf("session recipient charged for targeted role send: %#v", got)
	}
	expireAt := now.Add(60 * time.Second)
	result, err := store.MaintainDeliveries(expireAt)
	if err != nil || result.Expired != 1 {
		t.Fatalf("role expiry=%#v err=%v", result, err)
	}
	if pending := quotaRecipientCounters(t, store, roleRecipient("role/reviewer")); pending != (QuotaCounters{}) {
		t.Fatalf("role quota after expiry=%#v", pending)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, expireAt, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 0 {
		t.Fatalf("expired role delivery was leased page=%#v err=%v", page, err)
	}
	cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt)
	if err != nil || cursor != first.Sequence {
		t.Fatalf("role cursor=%d want=%d err=%v", cursor, first.Sequence, err)
	}
}

func TestStoreRevocationWritesTerminalAndReleasesOnce(t *testing.T) {
	t.Parallel()
	metrics := &Metrics{}
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
	store.SetMetrics(metrics)
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlRemoveMember, Member: Member{Endpoint: "agent/b"}, IdempotencyKey: "revoke-1", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if pending := quotaInstallCounters(t, store); pending != (QuotaCounters{}) {
		t.Fatalf("quota after revoke=%#v", pending)
	}
	snap := metrics.Snapshot()
	if snap.RelayTerminalTransitionsRevoked != 1 || snap.RelayPendingDeliveries != 0 {
		t.Fatalf("revoked metrics=%#v", snap)
	}
	page, err := store.ListTerminalDeliveries("", 10)
	if err != nil || len(page.Terminals) != 1 || page.Terminals[0].ClosedReason != ClosedRevoked {
		t.Fatalf("revoked terminals=%#v err=%v", page, err)
	}
	if _, err := store.MaintainDeliveries(now.Add(61 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if pending := quotaInstallCounters(t, store); pending != (QuotaCounters{}) {
		t.Fatalf("quota after expire of revoked=%#v", pending)
	}
}

func TestStorePrunesTerminalsAfterRetention(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 120, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "secret-body", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	expireAt := now.Add(61 * time.Second)
	if _, err := store.MaintainDeliveries(expireAt); err != nil {
		t.Fatal(err)
	}
	listed, err := store.ListTerminalDeliveries("", 10)
	if err != nil || len(listed.Terminals) != 1 || listed.Terminals[0].ClosedReason != ClosedExpired {
		t.Fatalf("retained terminals=%#v err=%v", listed, err)
	}
	encoded, err := json.Marshal(listed)
	if err != nil || strings.Contains(string(encoded), "secret-body") || strings.Contains(string(encoded), `"body"`) {
		t.Fatalf("operator listing leaked body encoded=%s err=%v", encoded, err)
	}
	beforePrune, err := store.MaintainDeliveries(expireAt.Add(119 * time.Second))
	if err != nil || beforePrune.Pruned != 0 {
		t.Fatalf("before retention prune=%#v err=%v", beforePrune, err)
	}
	pruned, err := store.MaintainDeliveries(expireAt.Add(120 * time.Second))
	if err != nil || pruned.Pruned != 1 {
		t.Fatalf("at retention prune=%#v err=%v", pruned, err)
	}
	empty, err := store.ListTerminalDeliveries("", 10)
	if err != nil || len(empty.Terminals) != 0 {
		t.Fatalf("pruned listing=%#v err=%v", empty, err)
	}
}

func TestStoreListTerminalsPagesWithoutBodies(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	for i, key := range []string{"alpha-body", "beta-body"} {
		if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", key, key, now.Add(time.Duration(i)*time.Millisecond))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.MaintainDeliveries(now.Add(61 * time.Second)); err != nil {
		t.Fatal(err)
	}
	first, err := store.ListTerminalDeliveries("", 1)
	if err != nil || len(first.Terminals) != 1 || first.NextCursor == "" {
		t.Fatalf("first page=%#v err=%v", first, err)
	}
	second, err := store.ListTerminalDeliveries(first.NextCursor, 1)
	if err != nil || len(second.Terminals) != 1 || first.Terminals[0].DeliveryID == second.Terminals[0].DeliveryID {
		t.Fatalf("second page=%#v first=%#v err=%v", second, first, err)
	}
	for _, record := range append(first.Terminals, second.Terminals...) {
		if record.ClosedReason != ClosedExpired || record.MessageID == "" || record.ConversationID == "" || record.RecipientID == "" || record.Sequence < 1 {
			t.Fatalf("terminal metadata=%#v", record)
		}
	}
}

func TestStoreConcurrentExpireAndLeaseLeavesAtMostOneCloser(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	later := now.Add(61 * time.Second)
	var wg sync.WaitGroup
	var leased atomic.Int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = store.MaintainDeliveries(later)
	}()
	go func() {
		defer wg.Done()
		page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, later, time.Minute, 10)
		if err == nil {
			leased.Store(int64(len(page.Deliveries)))
		}
	}()
	wg.Wait()
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, later.Add(time.Second), time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	if leased.Load()+int64(len(page.Deliveries)) > 1 {
		t.Fatalf("expired work was leased after close leased=%d later=%d", leased.Load(), len(page.Deliveries))
	}
	if pending := quotaInstallCounters(t, store); pending.Count > 1 {
		t.Fatalf("quota after concurrent expire/lease=%#v", pending)
	}
}

func TestStoreConcurrentExpireAndAckCannotDoubleRelease(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	later := now.Add(61 * time.Second)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = store.MaintainDeliveries(later)
	}()
	go func() {
		defer wg.Done()
		_ = store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, later)
	}()
	wg.Wait()
	if pending := quotaInstallCounters(t, store); pending != (QuotaCounters{}) {
		t.Fatalf("quota after concurrent close=%#v", pending)
	}
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", later)); err != nil {
		t.Fatal(err)
	}
	if pending := quotaInstallCounters(t, store); pending.Count != 1 {
		t.Fatalf("quota after reuse=%#v", pending)
	}
}

func TestStoreRetentionSurvivesRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := tightRetention(60, 120, 10)
	if err := store.SetRetentionPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.SetRetentionPolicy(cfg); err != nil {
		t.Fatal(err)
	}
	result, err := restarted.MaintainDeliveries(now.Add(61 * time.Second))
	if err != nil || result.Expired != 1 {
		t.Fatalf("restart expire=%#v err=%v", result, err)
	}
	listed, err := restarted.ListTerminalDeliveries("", 10)
	if err != nil || len(listed.Terminals) != 1 || listed.Terminals[0].ClosedReason != ClosedExpired {
		t.Fatalf("restart terminals=%#v err=%v", listed, err)
	}
}

func TestStoreMetricsAreContentFreeAndBounded(t *testing.T) {
	t.Parallel()
	metrics := &Metrics{}
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
	store.SetMetrics(metrics)
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "secret-body", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Second, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	if _, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now.Add(2*time.Second), time.Second, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MaintainDeliveries(now.Add(61 * time.Second)); err != nil {
		t.Fatal(err)
	}
	snap := metrics.Snapshot()
	if snap.RelayPendingDeliveries != 0 || snap.RelayPendingOldestAgeSeconds != 0 || snap.RelayTerminalTransitionsExpired != 1 || snap.RelayTerminalsRetained != 1 || snap.RelayLeaseRedeliveries != 1 {
		t.Fatalf("metrics=%#v", snap)
	}
	encoded, err := json.Marshal(snap)
	if err != nil || strings.Contains(string(encoded), "secret-body") || strings.Contains(string(encoded), "agent/b") || strings.Contains(string(encoded), conversation.ID) {
		t.Fatalf("metric snapshot leaked identifiers encoded=%s err=%v", encoded, err)
	}
}

func TestStoreTwoAgentDistinctLoopIsBoundedAcrossRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rate := RateLimitConfig{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 2, ConversationRefillPerMinute: 60, RetryAfterMaxSeconds: 9}
	quota := tightQuota(1, 1024, 2, 4096)
	retention := tightRetention(60, 3600, 10)
	if err := store.SetRateLimits(rate); err != nil {
		t.Fatal(err)
	}
	if err := store.SetQuotaLimits(quota); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRetentionPolicy(retention); err != nil {
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
	first, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "ping-1", "a-1", now))
	if err != nil {
		t.Fatal(err)
	}
	reply, _, err := store.AppendMessage(quotaAppend(conversation, "machine-b", "agent/b", "pong-1", "b-1", now))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "ping-2", "a-2", now))
	assertRateLimited(t, err, 1)
	retry, duplicate, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "ping-1", "a-1", now))
	if err != nil || !duplicate || retry.ID != first.ID {
		t.Fatalf("idempotent retry=%#v duplicate=%t err=%v", retry, duplicate, err)
	}
	refilled := now.Add(time.Second)
	_, _, err = store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "ping-2", "a-2", refilled))
	assertCapacityExceeded(t, err, 9)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.SetRateLimits(rate); err != nil {
		t.Fatal(err)
	}
	if err := restarted.SetQuotaLimits(quota); err != nil {
		t.Fatal(err)
	}
	if err := restarted.SetRetentionPolicy(retention); err != nil {
		t.Fatal(err)
	}
	_, _, err = restarted.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "ping-2", "a-2", refilled))
	assertCapacityExceeded(t, err, 9)
	expireAt := now.Add(60 * time.Second)
	result, err := restarted.MaintainDeliveries(expireAt)
	if err != nil || result.Expired != 2 {
		t.Fatalf("loop expiry=%#v err=%v", result, err)
	}
	if pending := quotaInstallCounters(t, restarted); pending != (QuotaCounters{}) {
		t.Fatalf("quota after loop expiry=%#v", pending)
	}
	cursorA, err := restarted.RecipientCursor("machine-a", "agent/a", conversation.ID, expireAt)
	if err != nil || cursorA != reply.Sequence {
		t.Fatalf("after expiry agent a cursor=%d want=%d err=%v", cursorA, reply.Sequence, err)
	}
	cursorB, err := restarted.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt)
	if err != nil || cursorB != reply.Sequence {
		t.Fatalf("after expiry agent b cursor=%d want=%d err=%v", cursorB, reply.Sequence, err)
	}
	third, _, err := restarted.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "ping-3", "a-3", expireAt))
	if err != nil {
		t.Fatal(err)
	}
	cursorA, err = restarted.RecipientCursor("machine-a", "agent/a", conversation.ID, expireAt)
	if err != nil || cursorA != third.Sequence {
		t.Fatalf("sender cursor=%d want=%d err=%v", cursorA, third.Sequence, err)
	}
	cursorB, err = restarted.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt)
	if err != nil || cursorB != reply.Sequence {
		t.Fatalf("pending recipient cursor=%d want=%d err=%v", cursorB, reply.Sequence, err)
	}
	if third.Sequence != 3 {
		t.Fatalf("sequence after bounded loop=%d", third.Sequence)
	}
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

func retentionNow() time.Time {
	return time.Date(2026, time.August, 18, 20, 0, 0, 0, time.UTC)
}
