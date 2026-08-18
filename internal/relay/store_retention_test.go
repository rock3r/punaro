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

func TestStoreRevocationWritesTerminalAndReleasesOnce(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(60, 3600, 10))
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
	wg.Add(2)
	var leased int
	go func() {
		defer wg.Done()
		_, _ = store.MaintainDeliveries(later)
	}()
	go func() {
		defer wg.Done()
		page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, later, time.Minute, 10)
		if err == nil {
			leased = len(page.Deliveries)
		}
	}()
	wg.Wait()
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, later.Add(time.Second), time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	if leased+len(page.Deliveries) > 1 {
		t.Fatalf("expired work was leased after close leased=%d later=%d", leased, len(page.Deliveries))
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
	if snap.RelayPendingDeliveries != 0 || snap.RelayTerminalTransitionsExpired != 1 || snap.RelayTerminalsRetained != 1 || snap.RelayLeaseRedeliveries != 1 {
		t.Fatalf("metrics=%#v", snap)
	}
	encoded, err := json.Marshal(snap)
	if err != nil || strings.Contains(string(encoded), "secret-body") || strings.Contains(string(encoded), "agent/b") || strings.Contains(string(encoded), conversation.ID) {
		t.Fatalf("metric snapshot leaked identifiers encoded=%s err=%v", encoded, err)
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
