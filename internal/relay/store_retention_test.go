package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tightRetention(maxAge, keep time.Duration, batch int) RetentionConfig {
	return RetentionConfig{
		PendingMaxAgeSeconds:     int(maxAge / time.Second),
		TerminalRetentionSeconds: int(keep / time.Second),
		MaintenanceBatch:         batch,
	}
}

func TestRetentionConfigRejectsOutOfBoundsValues(t *testing.T) {
	cfg := DefaultRetentionConfig()
	cfg.PendingMaxAgeSeconds = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero pending max age was accepted")
	}
	cfg = DefaultRetentionConfig()
	cfg.TerminalRetentionSeconds = RetentionKeepMaxSeconds + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("oversized terminal retention was accepted")
	}
	cfg = DefaultRetentionConfig()
	cfg.MaintenanceBatch = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero maintenance batch was accepted")
	}
}

func TestStoreExpiryBoundaryJustBeforeAtAfter(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Minute, time.Hour, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	message, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "pending-age", "send-1", now))
	if err != nil {
		t.Fatal(err)
	}
	before := now.Add(time.Minute - time.Millisecond)
	if result, err := store.MaintainDeliveries(before); err != nil || result.Expired != 0 {
		t.Fatalf("just before expiry result=%#v err=%v", result, err)
	}
	if pending := quotaInstallCounters(t, store); pending.Count != 1 {
		t.Fatalf("pending before boundary=%#v", pending)
	}
	at := now.Add(time.Minute)
	if result, err := store.MaintainDeliveries(at); err != nil || result.Expired != 1 {
		t.Fatalf("at expiry result=%#v err=%v", result, err)
	}
	if pending := quotaInstallCounters(t, store); pending != (QuotaCounters{}) {
		t.Fatalf("pending at boundary=%#v", pending)
	}
	page, err := store.ListDeliveryTerminals(TerminalListInput{Limit: 10})
	if err != nil || len(page.Terminals) != 1 || page.Terminals[0].ClosedReason != ClosedReasonExpired || page.Terminals[0].MessageID != message.ID || page.Terminals[0].Sequence != message.Sequence {
		t.Fatalf("expired terminal=%#v err=%v", page, err)
	}
	after := now.Add(time.Minute + time.Millisecond)
	if result, err := store.MaintainDeliveries(after); err != nil || result.Expired != 0 {
		t.Fatalf("after expiry result=%#v err=%v", result, err)
	}
}

func TestStoreMaintainBoundedBatchAndStableContinuation(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Minute, time.Hour, 2))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	for _, body := range []string{"one", "two", "three", "four", "five"} {
		if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", body, "send-"+body, now)); err != nil {
			t.Fatal(err)
		}
	}
	if pending := quotaInstallCounters(t, store); pending.Count != 5 {
		t.Fatalf("pending after appends=%#v", pending)
	}
	later := now.Add(time.Minute)
	first, err := store.MaintainDeliveries(later)
	if err != nil || first.Expired != 2 || !first.Continuation {
		t.Fatalf("first page=%#v err=%v", first, err)
	}
	second, err := store.MaintainDeliveries(later)
	if err != nil || second.Expired != 2 || !second.Continuation {
		t.Fatalf("second page=%#v err=%v", second, err)
	}
	third, err := store.MaintainDeliveries(later)
	if err != nil || third.Expired != 1 || third.Continuation {
		t.Fatalf("third page=%#v err=%v", third, err)
	}
	if pending := quotaInstallCounters(t, store); pending != (QuotaCounters{}) {
		t.Fatalf("pending after continuation=%#v", pending)
	}
}

func TestStoreExpiryReleasesCapacityOnce(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Minute, time.Hour, 10))
	if err := store.SetQuotaLimits(tightQuota(1, 1024, 8, 4096)); err != nil {
		t.Fatal(err)
	}
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	if result, err := store.MaintainDeliveries(later); err != nil || result.Expired != 1 {
		t.Fatalf("expire=%#v err=%v", result, err)
	}
	if result, err := store.MaintainDeliveries(later); err != nil || result.Expired != 0 {
		t.Fatalf("repeat expire=%#v err=%v", result, err)
	}
	if counters := quotaInstallCounters(t, store); counters != (QuotaCounters{}) {
		t.Fatalf("install counters after expiry=%#v", counters)
	}
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "two", "send-2", later)); err != nil {
		t.Fatal(err)
	}
}

func TestStoreExpiredActiveLeaseCannotAck(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Minute, time.Hour, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "leased", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Hour, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	later := now.Add(time.Minute)
	if result, err := store.MaintainDeliveries(later); err != nil || result.Expired != 1 {
		t.Fatalf("expire=%#v err=%v", result, err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, later); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired lease ack err=%v", err)
	}
}

func TestStoreCursorContiguousExpiryAdvancesRecipient(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Minute, time.Hour, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "first", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	second, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "second", "send-2", now.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	later := second.CreatedAt.Add(time.Minute)
	if result, err := store.MaintainDeliveries(later); err != nil || result.Expired != 2 {
		t.Fatalf("expire both=%#v err=%v", result, err)
	}
	if cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, later); err != nil || cursor != second.Sequence {
		t.Fatalf("cursor after contiguous expiry=%d err=%v want %d", cursor, err, second.Sequence)
	}
}

func TestStoreCursorExpiredLaterDoesNotSkipEarlierPending(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Minute, time.Hour, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	first, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "newer-first", "send-1", now.Add(30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "older-second", "send-2", now))
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now.Add(30*time.Second), time.Hour, 10)
	if err != nil || len(page.Deliveries) != 2 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	expireAt := now.Add(time.Minute)
	if result, err := store.MaintainDeliveries(expireAt); err != nil || result.Expired != 1 {
		t.Fatalf("expire older only=%#v err=%v", result, err)
	}
	if cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt); err != nil || cursor != 0 {
		t.Fatalf("cursor with earlier pending=%d err=%v", cursor, err)
	}
	var live Delivery
	for _, delivery := range page.Deliveries {
		if delivery.Message.ID == first.ID {
			live = delivery
		}
	}
	if live.ID == "" {
		t.Fatal("missing live delivery")
	}
	if err := store.AckDelivery("machine-b", "agent/b", live.ID, live.LeaseToken, live.LeaseGeneration, expireAt); err != nil {
		t.Fatal(err)
	}
	if cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, expireAt); err != nil || cursor != second.Sequence {
		t.Fatalf("cursor after pending ack plus expired gap=%d err=%v want %d", cursor, err, second.Sequence)
	}
}

func TestStoreExpiryIndependentRecipients(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Minute, time.Hour, 10))
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
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "fan-out", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	pageB, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Hour, 10)
	if err != nil || len(pageB.Deliveries) != 1 {
		t.Fatalf("lease b=%#v err=%v", pageB, err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", pageB.Deliveries[0].ID, pageB.Deliveries[0].LeaseToken, pageB.Deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	if result, err := store.MaintainDeliveries(later); err != nil || result.Expired != 1 {
		t.Fatalf("expire remaining=%#v err=%v", result, err)
	}
	if cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, later); err != nil || cursor != 1 {
		t.Fatalf("acked recipient cursor=%d err=%v", cursor, err)
	}
	if cursor, err := store.RecipientCursor("machine-c", "agent/c", conversation.ID, later); err != nil || cursor != 1 {
		t.Fatalf("expired recipient cursor=%d err=%v", cursor, err)
	}
	pageC, err := store.LeaseDeliveries("machine-c", "consumer-c", "agent/c", conversation.ID, later, time.Hour, 10)
	if err != nil || len(pageC.Deliveries) != 0 {
		t.Fatalf("expired recipient still pending=%#v err=%v", pageC, err)
	}
}

func TestStoreTerminalRetentionAndBoundedPrune(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Minute, 2*time.Minute, 2))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	for _, body := range []string{"one", "two", "three"} {
		if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", body, "send-"+body, now)); err != nil {
			t.Fatal(err)
		}
	}
	expiredAt := now.Add(time.Minute)
	for {
		result, err := store.MaintainDeliveries(expiredAt)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Continuation {
			break
		}
	}
	page, err := store.ListDeliveryTerminals(TerminalListInput{Limit: 10})
	if err != nil || len(page.Terminals) != 3 {
		t.Fatalf("retained before prune=%#v err=%v", page, err)
	}
	pruneAt := expiredAt.Add(2 * time.Minute)
	first, err := store.MaintainDeliveries(pruneAt)
	if err != nil || first.Pruned != 2 || !first.Continuation {
		t.Fatalf("first prune=%#v err=%v", first, err)
	}
	second, err := store.MaintainDeliveries(pruneAt)
	if err != nil || second.Pruned != 1 || second.Continuation {
		t.Fatalf("second prune=%#v err=%v", second, err)
	}
	empty, err := store.ListDeliveryTerminals(TerminalListInput{Limit: 10})
	if err != nil || len(empty.Terminals) != 0 {
		t.Fatalf("retained after prune=%#v err=%v", empty, err)
	}
}

func TestStoreRestartPreservesExpiryAndTerminals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRetentionPolicy(tightRetention(time.Minute, time.Hour, 10)); err != nil {
		t.Fatal(err)
	}
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "durable", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Minute)
	if result, err := store.MaintainDeliveries(later); err != nil || result.Expired != 1 {
		t.Fatalf("expire=%#v err=%v", result, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.SetRetentionPolicy(tightRetention(time.Minute, time.Hour, 10)); err != nil {
		t.Fatal(err)
	}
	if pending := quotaInstallCounters(t, restarted); pending != (QuotaCounters{}) {
		t.Fatalf("pending after restart=%#v", pending)
	}
	page, err := restarted.ListDeliveryTerminals(TerminalListInput{Limit: 10})
	if err != nil || len(page.Terminals) != 1 || page.Terminals[0].ClosedReason != ClosedReasonExpired {
		t.Fatalf("terminals after restart=%#v err=%v", page, err)
	}
}

func TestStoreConcurrentExpiryAckAndLease(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Minute, time.Hour, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "race", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Hour, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	later := now.Add(time.Minute)
	var wait sync.WaitGroup
	errs := make(chan error, 3)
	wait.Add(3)
	go func() {
		defer wait.Done()
		_, err := store.MaintainDeliveries(later)
		errs <- err
	}()
	go func() {
		defer wait.Done()
		err := store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, later)
		if err != nil && !errors.Is(err, ErrForbidden) {
			errs <- err
			return
		}
		errs <- nil
	}()
	go func() {
		defer wait.Done()
		_, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, later, time.Hour, 10)
		errs <- err
	}()
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if counters := quotaInstallCounters(t, store); counters != (QuotaCounters{}) {
		t.Fatalf("pending after race=%#v", counters)
	}
	terminals, err := store.ListDeliveryTerminals(TerminalListInput{Limit: 10})
	if err != nil || len(terminals.Terminals) != 1 {
		t.Fatalf("terminals after race=%#v err=%v", terminals, err)
	}
	if reason := terminals.Terminals[0].ClosedReason; reason != ClosedReasonAcked && reason != ClosedReasonExpired {
		t.Fatalf("closed reason=%q", reason)
	}
}

func TestStoreAckAndRevokeRecordTerminalsWithoutBodies(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Hour, time.Hour, 10))
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "secret-body", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Hour, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("lease=%#v err=%v", page, err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	listed, err := store.ListDeliveryTerminals(TerminalListInput{Limit: 10})
	if err != nil || len(listed.Terminals) != 1 || listed.Terminals[0].ClosedReason != ClosedReasonAcked {
		t.Fatalf("acked terminal=%#v err=%v", listed, err)
	}
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "revoke-me", "send-2", now)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/b", Capabilities: CapSend},
		IdempotencyKey: "revoke-receive", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	listed, err = store.ListDeliveryTerminals(TerminalListInput{Limit: 10})
	if err != nil || len(listed.Terminals) != 2 {
		t.Fatalf("terminals after revoke=%#v err=%v", listed, err)
	}
	reasons := map[string]int{}
	for _, terminal := range listed.Terminals {
		reasons[terminal.ClosedReason]++
		if terminal.RecipientID == "" || terminal.MessageID == "" || terminal.ConversationID == "" {
			t.Fatalf("terminal missing opaque ids: %#v", terminal)
		}
	}
	if reasons[ClosedReasonAcked] != 1 || reasons[ClosedReasonRevoked] != 1 {
		t.Fatalf("reasons=%v", reasons)
	}
	encoded, err := json.Marshal(listed.Terminals)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-body") || strings.Contains(string(encoded), "revoke-me") || strings.Contains(string(encoded), `"body"`) {
		t.Fatalf("terminal metadata leaked bodies: %s", encoded)
	}
}

func TestStoreLeaseRedeliveryAndQueueMetricsAreContentFree(t *testing.T) {
	t.Parallel()
	store := openRetentionStore(t, tightRetention(time.Minute, time.Hour, 10))
	metrics := &Metrics{}
	store.SetMetrics(metrics)
	now := retentionNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "metric-body", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Minute, 10); err != nil {
		t.Fatal(err)
	}
	if snapshot := metrics.Snapshot(); snapshot.RelayLeaseRedeliveries != 0 || snapshot.RelayPendingDeliveries != 1 || snapshot.RelayPendingOldestAgeSeconds != 0 {
		t.Fatalf("initial metrics=%#v", snapshot)
	}
	redeliverAt := now.Add(2 * time.Minute)
	if _, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, redeliverAt, time.Minute, 10); err != nil {
		t.Fatal(err)
	}
	store.refreshDeliveryMetrics(redeliverAt)
	snapshot := metrics.Snapshot()
	if snapshot.RelayLeaseRedeliveries != 1 || snapshot.RelayPendingOldestAgeSeconds != 120 {
		t.Fatalf("redelivery metrics=%#v", snapshot)
	}
	if result, err := store.MaintainDeliveries(redeliverAt); err != nil || result.Expired != 1 {
		t.Fatalf("expire=%#v err=%v", result, err)
	}
	snapshot = metrics.Snapshot()
	if snapshot.RelayTerminalTransitionsExpired != 1 || snapshot.RelayTerminalsRetained != 1 || snapshot.RelayPendingDeliveries != 0 || snapshot.RelayPendingOldestAgeSeconds != 0 {
		t.Fatalf("expiry metrics=%#v", snapshot)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, key := range []string{
		`"relay_pending_deliveries"`,
		`"relay_pending_bytes"`,
		`"relay_pending_oldest_age_seconds"`,
		`"relay_terminal_transitions_acked"`,
		`"relay_terminal_transitions_expired"`,
		`"relay_terminal_transitions_revoked"`,
		`"relay_terminals_retained"`,
		`"relay_lease_redeliveries"`,
	} {
		if !strings.Contains(body, key) {
			t.Fatalf("metrics JSON missing %s: %s", key, body)
		}
	}
	if strings.Contains(body, "metric-body") || strings.Contains(body, "agent/") || strings.Contains(body, conversation.ID) {
		t.Fatalf("metrics JSON leaked content: %s", body)
	}
}

func TestHTTPDoesNotExposeTerminalInventory(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: public, EndpointPrefixes: []string{"agent/a/"}}})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(store, auth, HandlerOptions{Now: func() time.Time {
		return time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	}, EndpointLeaseTTL: time.Minute, DeliveryLeaseTTL: time.Minute})
	for _, path := range []string{"/v1/terminals", "/v1/deliveries/receipts"} {
		response := serveSigned(t, handler, private, "machine-a", http.MethodGet, path, `{}`, "terminal-"+path, "")
		if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "route not found") {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
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
