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

func TestStoreDirectMessageChargesTargetRoleAndDeniesAtCeiling(t *testing.T) {
	t.Parallel()
	store := openQuotaStore(t, tightQuota(1, 1024, 8, 4096))
	now := quotaNow()
	fromRole, toRole := prepareDirectPair(t, store, now, true)
	first, duplicate, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "please review", IdempotencyKey: "dm-cap-1", Now: now,
	})
	if err != nil || duplicate {
		t.Fatalf("first send=%#v duplicate=%t err=%v", first, duplicate, err)
	}
	if got := quotaRecipientCounters(t, store, roleRecipient(toRole)); got != (QuotaCounters{Count: 1, Bytes: int64(len("please review"))}) {
		t.Fatalf("target role counters=%#v", got)
	}
	if got := quotaRecipientCounters(t, store, "agent/b"); got != (QuotaCounters{}) {
		t.Fatalf("session recipient charged for direct send: %#v", got)
	}
	_, _, err = store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "again", IdempotencyKey: "dm-cap-2", Now: now.Add(time.Second),
	})
	assertCapacityExceeded(t, err, 9)
	if first.Sequence != 1 {
		t.Fatalf("sequence=%d", first.Sequence)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", first.ConversationID, now.Add(time.Second), time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 || page.Deliveries[0].Message.ID != first.ID {
		t.Fatalf("denied send left extra delivery page=%#v err=%v", page, err)
	}
}

func TestStoreOpenRejectsDriftedQuotaAndRepairOpenerCanReconcile(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	if _, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", "one", "send-1", now)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), "UPDATE pending_quota_install SET pending_count = 99"); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if _, err := Open(database); err == nil {
		t.Fatal("ordinary open accepted drifted counters")
	}
	repair, err := OpenForCapacityRepair(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := repair.VerifyPendingQuota(); err == nil {
		t.Fatal("repair opener skipped verification by also skipping the drifted counters")
	}
	if _, err := ReconcilePendingQuota(repair); err != nil {
		t.Fatal(err)
	}
	if err := repair.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.VerifyPendingQuota(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreVerifyPendingQuotaIgnoresConcurrentCommits(t *testing.T) {
	store := openQuotaStore(t, tightQuota(32, 4096, 32, 8192))
	now := quotaNow()
	conversation := createQuotaConversation(t, store, now, "machine-a", "machine-b", "agent/a", "agent/b")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			body := "b"
			_, _, err := store.AppendMessage(quotaAppend(conversation, "machine-a", "agent/a", body, "send-"+itoa(i), now.Add(time.Duration(i)*time.Millisecond)))
			if err != nil {
				continue
			}
			page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now.Add(time.Duration(i)*time.Millisecond), time.Minute, 10)
			if err != nil || len(page.Deliveries) == 0 {
				continue
			}
			_ = store.AckDelivery("machine-b", "agent/b", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now.Add(time.Duration(i)*time.Millisecond))
		}
	}()
	for i := 0; i < 40; i++ {
		if err := store.VerifyPendingQuota(); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("verify under concurrent traffic: %v", err)
		}
	}
	close(stop)
	wg.Wait()
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

func TestStoreGatewayUserTelegramSendDoesNotChargeSelfQuota(t *testing.T) {
	store := openQuotaStore(t, tightQuota(1, 1024, 8, 4096))
	now := quotaNow()
	conversation := createClaimedTelegramConversation(t, store, now)
	first, duplicate, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		TargetRole: TelegramUserParticipant, Body: "self", IdempotencyKey: "gateway-to-user-1", Now: now,
	})
	if err != nil || duplicate {
		t.Fatalf("gateway user-telegram send=%#v duplicate=%t err=%v", first, duplicate, err)
	}
	var deliveries int
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM deliveries WHERE message_id=?", first.ID).Scan(&deliveries); err != nil || deliveries != 0 {
		t.Fatalf("gateway self-send deliveries=%d err=%v", deliveries, err)
	}
	if counters := quotaRecipientCounters(t, store, TelegramGatewayEndpoint); counters != (QuotaCounters{}) {
		t.Fatalf("gateway self-send charged recipient quota=%#v", counters)
	}
	if counters := quotaInstallCounters(t, store); counters != (QuotaCounters{}) {
		t.Fatalf("gateway self-send charged install quota=%#v", counters)
	}
	if err := store.VerifyPendingQuota(); err != nil {
		t.Fatalf("quota after gateway self-send: %v", err)
	}
	if _, _, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a",
		TargetRole: TelegramUserParticipant, Body: "ping", IdempotencyKey: "agent-to-user-1", Now: now,
	}); err != nil {
		t.Fatalf("agent user-telegram send after gateway self-send: %v", err)
	}
	if counters := quotaRecipientCounters(t, store, TelegramGatewayEndpoint); counters.Count != 1 || counters.Bytes != int64(len("ping")) {
		t.Fatalf("agent send quota=%#v", counters)
	}
}

func TestStoreUserTelegramSendChargesAndReleasesGatewayQuota(t *testing.T) {
	store := openQuotaStore(t, tightQuota(1, 1024, 8, 4096))
	now := quotaNow()
	conversation := createClaimedTelegramConversation(t, store, now)
	first, duplicate, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a",
		TargetRole: TelegramUserParticipant, Body: "ping", IdempotencyKey: "to-user-1", Now: now,
	})
	if err != nil || duplicate {
		t.Fatalf("first user-telegram send=%#v duplicate=%t err=%v", first, duplicate, err)
	}
	if counters := quotaRecipientCounters(t, store, TelegramGatewayEndpoint); counters.Count != 1 || counters.Bytes != int64(len("ping")) {
		t.Fatalf("gateway quota after send=%#v", counters)
	}
	if _, _, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a",
		TargetRole: TelegramUserParticipant, Body: "again", IdempotencyKey: "to-user-2", Now: now,
	}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("second user-telegram send err=%v, want capacity exceeded", err)
	}
	if counters := quotaRecipientCounters(t, store, TelegramGatewayEndpoint); counters.Count != 1 {
		t.Fatalf("denied send changed gateway quota=%#v", counters)
	}
	page, err := store.LeaseDeliveries("machine-telegram", "tg-consumer", TelegramGatewayEndpoint, conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("gateway lease=%#v err=%v", page, err)
	}
	if err := store.AckDelivery("machine-telegram", TelegramGatewayEndpoint, page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatalf("gateway ack: %v", err)
	}
	if counters := quotaRecipientCounters(t, store, TelegramGatewayEndpoint); counters.Count != 0 {
		t.Fatalf("gateway quota after ack=%#v", counters)
	}
	if _, _, err := store.AppendMessage(AppendInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a",
		TargetRole: TelegramUserParticipant, Body: "after-ack", IdempotencyKey: "to-user-3", Now: now,
	}); err != nil {
		t.Fatalf("send after ack: %v", err)
	}
}

func createClaimedTelegramConversation(t *testing.T, store *Store, now time.Time) Conversation {
	t.Helper()
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named-quota", CreatorEndpoint: "agent/a",
		DisplayName: "Ops", Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: conversation.ID, MachineID: "machine-a", Endpoint: "agent/a",
		IdempotencyKey: "claim-" + conversation.ID, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{ConversationID: conversation.ID, MachineID: "machine-telegram", Now: now}); err != nil {
		t.Fatal(err)
	}
	return conversation
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
