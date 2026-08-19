package relay

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStoreRejectsNonPortableRequestAndMessageText(t *testing.T) {
	t.Parallel()
	invalidUTF8 := string([]byte{0xff})
	if ValidRequestToken(invalidUTF8) || ValidRequestToken("token\x00value") {
		t.Fatal("non-portable request token was accepted")
	}
	store := &Store{}
	base := AppendInput{ConversationID: "019f7f07-4b88-7c12-a394-b663274a6555", SenderMachineID: "machine-a", FromEndpoint: "agent/a", IdempotencyKey: "portable-key"}
	for _, body := range []string{invalidUTF8, "body\x00value"} {
		input := base
		input.Body = body
		if _, _, err := store.AppendMessage(input); err == nil || !strings.Contains(err.Error(), "portable UTF-8") {
			t.Fatalf("non-portable body %q err=%v", body, err)
		}
	}
}

func TestAppendRequestHashPreservesBroadcastUpgradeCompatibility(t *testing.T) {
	input := AppendInput{ConversationID: "conversation-1", FromEndpoint: "agent/a", Body: "broadcast"}
	legacy := stableHash(input.ConversationID, input.FromEndpoint, input.Body)
	if got := AppendRequestHash(input); got != legacy {
		t.Fatalf("broadcast request hash changed across targeting upgrade: got %s want %s", got, legacy)
	}
	input.TargetRole = "role/reviewer"
	if got := AppendRequestHash(input); got == legacy {
		t.Fatal("targeted request did not bind its target role into idempotency")
	}
}

func TestStoreParallelFreshOpensCompletePromptly(t *testing.T) {
	t.Parallel()
	const workers = 16
	dir := t.TempDir()
	started := make(chan struct{})
	var startOnce sync.Once
	errorsSeen := make(chan error, workers)
	var done sync.WaitGroup
	done.Add(workers)
	for index := 0; index < workers; index++ {
		go func(index int) {
			defer done.Done()
			<-started
			store, err := Open(filepath.Join(dir, fmt.Sprintf("relay-%d.db", index)))
			if err == nil {
				err = store.Close()
			}
			errorsSeen <- err
		}(index)
	}
	startOnce.Do(func() { close(started) })
	finished := make(chan struct{})
	go func() {
		done.Wait()
		close(errorsSeen)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(15 * time.Second):
		t.Fatal("parallel fresh Open still blocked after 15s")
	}
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestStoreProvidesDurableAtLeastOnceDelivery(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, clock, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, clock, time.Minute); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapSend | CapReceive},
	}, clock)
	if err != nil {
		t.Fatal(err)
	}

	first, duplicate, err := store.AppendMessage(AppendInput{
		ConversationID:  conversation.ID,
		SenderMachineID: "machine-a",
		FromEndpoint:    "agent/a",
		Body:            "ready for review",
		IdempotencyKey:  "send-1",
		Now:             clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if duplicate {
		t.Fatal("first append unexpectedly reported duplicate")
	}
	again, duplicate, err := store.AppendMessage(AppendInput{
		ConversationID:  conversation.ID,
		SenderMachineID: "machine-a",
		FromEndpoint:    "agent/a",
		Body:            "ready for review",
		IdempotencyKey:  "send-1",
		Now:             clock.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate || again.ID != first.ID || again.Sequence != first.Sequence {
		t.Fatalf("idempotent append = %#v duplicate=%v, want original %#v", again, duplicate, first)
	}
	recipients, err := store.RecipientMachines(first.ID, clock)
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 || recipients[0] != "machine-b" {
		t.Fatalf("recipient machines = %#v", recipients)
	}

	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", "", clock, time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	leased := page.Deliveries
	if len(leased) != 1 || leased[0].Message.ID != first.ID || leased[0].Message.Body != "ready for review" {
		t.Fatalf("leased = %#v", leased)
	}
	if err := store.AckDelivery("machine-a", "agent/b", leased[0].ID, leased[0].LeaseToken, leased[0].LeaseGeneration, clock); err == nil {
		t.Fatal("wrong machine acknowledged delivery")
	}
	if err := store.AckDelivery("machine-b", "agent/b", leased[0].ID, leased[0].LeaseToken, leased[0].LeaseGeneration, clock); err != nil {
		t.Fatal(err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", leased[0].ID, leased[0].LeaseToken, leased[0].LeaseGeneration, clock); err != nil {
		t.Fatalf("ack must be idempotent: %v", err)
	}
}

func TestStoreControlRequiresLiveAdminAndIsDurablyIdempotent(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	for machine, endpoint := range map[string]string{"machine-a": "agent/a", "machine-b": "agent/b", "machine-c": "agent/c"} {
		if err := store.AdvertiseEndpoints(machine, []string{endpoint}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive | CapAdmin},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	input := ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/c", Capabilities: CapReceive}, IdempotencyKey: "control-1", Now: now}
	first, duplicate, err := store.ApplyControl(input)
	if err != nil || duplicate {
		t.Fatalf("first control=%#v duplicate=%v err=%v", first, duplicate, err)
	}
	again, duplicate, err := store.ApplyControl(input)
	if err != nil || !duplicate || again.ID != first.ID {
		t.Fatalf("retry control=%#v duplicate=%v err=%v", again, duplicate, err)
	}
	second, duplicate, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlRemoveMember, Member: Member{Endpoint: "agent/c"}, IdempotencyKey: "control-order", Now: now})
	if err != nil || duplicate || !second.CreatedAt.After(first.CreatedAt) {
		t.Fatalf("same-timestamp control=%#v duplicate=%v first=%#v err=%v", second, duplicate, first, err)
	}
	if _, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-c", ActorEndpoint: "agent/c", Operation: ControlRemoveMember, Member: Member{Endpoint: "agent/b"}, IdempotencyKey: "control-2", Now: now}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin control err=%v, want forbidden", err)
	}
	events, err := store.ControlAudit(conversation.ID, "machine-a", "agent/a", now)
	if err != nil || len(events) != 2 || events[0].ID != second.ID || events[1].ID != first.ID {
		t.Fatalf("audit=%#v err=%v", events, err)
	}
	var messages int
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM messages").Scan(&messages); err != nil || messages != 0 {
		t.Fatalf("control entered message plane: messages=%d err=%v", messages, err)
	}
	if _, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-b", ActorEndpoint: "agent/b", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/a", Capabilities: CapSend | CapReceive}, IdempotencyKey: "revoke-admin-a", Now: now}); err != nil {
		t.Fatalf("revoke admin control: %v", err)
	}
	if _, _, err := store.ApplyControl(input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked admin replay err=%v, want forbidden", err)
	}
}

func TestStoreControlRevokesDetachedExistingMember(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}, {Endpoint: "agent/b", Capabilities: CapSend | CapReceive}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/b", Capabilities: CapSend}, IdempotencyKey: "revoke-detached", Now: now.Add(2 * time.Minute)}); err != nil {
		t.Fatalf("revoke detached member: %v", err)
	}
}

func TestStoreControlCanRetainInvokeCapability(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 30, 0, 0, time.UTC)
	for machine, endpoint := range map[string]string{"machine-a": "agent/a", "machine-b": "agent/b"} {
		if err := store.AdvertiseEndpoints(machine, []string{endpoint}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	conversation, err := store.CreateConversation("agent/a", []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}, {Endpoint: "agent/b", Capabilities: CapReceive | CapInvoke}}, now)
	if err != nil {
		t.Fatal(err)
	}
	event, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/b", Capabilities: CapSend | CapInvoke}, IdempotencyKey: "retain-invoke", Now: now})
	if err != nil || event.Member.Capabilities != CapSend|CapInvoke {
		t.Fatalf("invoke control=%#v err=%v", event, err)
	}
}

func TestStoreControlRejectsNewMemberBeyondConversationLimit(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 35, 0, 0, time.UTC)
	members := make([]Member, 0, 256)
	endpoints := make([]string, 0, 2)
	members = append(members, Member{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin})
	endpoints = append(endpoints, "agent/a")
	for index := 1; index < 256; index++ {
		members = append(members, Member{Role: fmt.Sprintf("role/member-%03d", index), RoleMachineID: fmt.Sprintf("machine-member-%03d", index), Capabilities: CapReceive})
	}
	endpoints = append(endpoints, "agent/overflow")
	if err := store.AdvertiseEndpoints("machine-a", endpoints, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", members, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/overflow", Capabilities: CapReceive}, IdempotencyKey: "member-limit", Now: now}); !errors.Is(err, ErrConflict) {
		t.Fatalf("overflow upsert error=%v, want conflict", err)
	}
}

func TestStoreControlAcceptsBoundRoleAdministrator(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 40, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b", "agent/c"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: "role/admin", RoleMachineID: "machine-b", Capabilities: CapAdmin},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-b", "role/admin", "agent/b", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	event, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-b", ActorEndpoint: "agent/b", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/c", Capabilities: CapReceive}, IdempotencyKey: "role-admin-control", Now: now})
	if err != nil {
		t.Fatalf("bound role admin control: %v", err)
	}
	audit, err := store.ControlAudit(conversation.ID, "machine-b", "agent/b", now)
	if err != nil || len(audit) != 1 || audit[0].ID != event.ID {
		t.Fatalf("bound role admin audit=%#v err=%v", audit, err)
	}
}

func TestStoreControlGrantReceiveStartsAtCurrentConversationCursor(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 45, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, now)
	if err != nil {
		t.Fatal(err)
	}
	message, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "before membership", IdempotencyKey: "before-membership", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/b", Capabilities: CapReceive}, IdempotencyKey: "grant-receive", Now: now}); err != nil {
		t.Fatal(err)
	}
	if cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, now); err != nil || cursor != message.Sequence {
		t.Fatalf("cursor=%d err=%v, want current sequence %d", cursor, err, message.Sequence)
	}
}

func TestStoreControlRetirementAdvancesRecipientCursor(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 13, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}, {Endpoint: "agent/b", Capabilities: CapReceive}}, now)
	if err != nil {
		t.Fatal(err)
	}
	message, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "retired delivery", IdempotencyKey: "retired-delivery", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/b", Capabilities: CapSend}, IdempotencyKey: "revoke-receive", Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/b", Capabilities: CapReceive}, IdempotencyKey: "restore-receive", Now: now}); err != nil {
		t.Fatal(err)
	}
	if cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, now); err != nil || cursor != message.Sequence {
		t.Fatalf("cursor=%d err=%v, want retired sequence %d", cursor, err, message.Sequence)
	}
}

func TestStoreRejectsStaleLeaseAfterRedeliveryAndSurvivesRestart(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, clock, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, clock, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "one", IdempotencyKey: "send-1", Now: clock}); err != nil {
		t.Fatal(err)
	}
	firstPage, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", "", clock, time.Minute, 10)
	firstLease := firstPage.Deliveries
	if err != nil || len(firstLease) != 1 {
		t.Fatalf("first lease = %#v, %v", firstLease, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	secondPage, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", "", clock.Add(time.Minute+time.Second), time.Minute, 10)
	secondLease := secondPage.Deliveries
	if err != nil || len(secondLease) != 1 {
		t.Fatalf("second lease = %#v, %v", secondLease, err)
	}
	if secondLease[0].LeaseGeneration <= firstLease[0].LeaseGeneration {
		t.Fatalf("lease generation did not advance: first=%d second=%d", firstLease[0].LeaseGeneration, secondLease[0].LeaseGeneration)
	}
	if err := store.AckDelivery("machine-b", "agent/b", firstLease[0].ID, firstLease[0].LeaseToken, firstLease[0].LeaseGeneration, clock.Add(time.Minute+time.Second)); err == nil {
		t.Fatal("stale lease acknowledgement succeeded")
	}
	if err := store.AckDelivery("machine-b", "agent/b", secondLease[0].ID, secondLease[0].LeaseToken, secondLease[0].LeaseGeneration, clock.Add(time.Minute+time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRecipientCursorNeverSkipsAcknowledgementGap(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	for index, body := range []string{"first", "second"} {
		if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: body, IdempotencyKey: fmt.Sprintf("send-%d", index), Now: now}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", conversation.ID, now, time.Minute, 10)
	deliveries := page.Deliveries
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("deliveries=%#v err=%v", deliveries, err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", deliveries[1].ID, deliveries[1].LeaseToken, deliveries[1].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	if cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, now); err != nil || cursor != 0 {
		t.Fatalf("cursor=%d err=%v, want gap-preserving zero", cursor, err)
	}
	if err := store.AckDelivery("machine-b", "agent/b", deliveries[0].ID, deliveries[0].LeaseToken, deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	if cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, now); err != nil || cursor != 2 {
		t.Fatalf("cursor=%d err=%v, want contiguous two", cursor, err)
	}
}

func TestStoreRejectsUnauthorizedSenderAndExpiredEndpoint(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	clock := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, clock, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, clock, time.Minute); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-b", FromEndpoint: "agent/a", Body: "forged", IdempotencyKey: "send-1", Now: clock}); err == nil {
		t.Fatal("machine sent from an endpoint it does not own")
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "late", IdempotencyKey: "send-2", Now: clock.Add(2 * time.Second)}); err == nil {
		t.Fatal("expired endpoint sent a message")
	}
}

func TestStoreListsOnlyConversationsForActiveMachineEndpoints(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.July, 13, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}, {Endpoint: "agent/b", Capabilities: CapReceive}}, now)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := store.ConversationsForMachine("machine-b", now)
	if err != nil || len(listed) != 1 || listed[0].ID != conversation.ID {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
	listed, err = store.ConversationsForMachine("machine-a", now.Add(2*time.Minute))
	if err != nil || len(listed) != 0 {
		t.Fatalf("expired listed=%#v err=%v", listed, err)
	}
}

func TestStoreDurableRoleRebindsAcrossSessionReconnect(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-sender", []string{"agent/sender/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-reviewer", []string{"agent/reviewer/first-session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/sender/session", []Member{
		{Endpoint: "agent/sender/session", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: "role/plan-reviewer", RoleMachineID: "machine-reviewer", Capabilities: CapSend | CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-reviewer", "role/plan-reviewer", "agent/reviewer/first-session", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	message, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-sender", FromEndpoint: "agent/sender/session", Body: "review this", IdempotencyKey: "send-role-reconnect", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := store.RecipientMachines(message.ID, now)
	if err != nil || len(recipients) != 1 || recipients[0] != "machine-reviewer" {
		t.Fatalf("durable role wake recipients=%#v err=%v", recipients, err)
	}
	if err := store.AdvertiseEndpoints("machine-reviewer", []string{"agent/reviewer/second-session"}, now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-reviewer", "role/plan-reviewer", "agent/reviewer/second-session", now.Add(time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-reviewer", "reviewer-reconnected", "agent/reviewer/second-session", conversation.ID, now.Add(2*time.Second), time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 || page.Deliveries[0].Message.Body != "review this" {
		t.Fatalf("role delivery after session replacement page=%#v err=%v", page, err)
	}
	if err := store.AckDelivery("machine-reviewer", "agent/reviewer/second-session", page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.AuthorizeSender(conversation.ID, "machine-reviewer", "agent/reviewer/second-session", now.Add(2*time.Second)); err != nil {
		t.Fatalf("rebound role sender authorization: %v", err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-reviewer", FromEndpoint: "agent/reviewer/second-session", Body: "role response", IdempotencyKey: "role-reconnect-response", Now: now.Add(3 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	if cursor, err := store.RecipientCursor("machine-reviewer", "agent/reviewer/second-session", conversation.ID, now.Add(3*time.Second)); err != nil || cursor != 1 {
		t.Fatalf("durable role sender cursor=%d err=%v, want one until the self-role delivery is acknowledged", cursor, err)
	}
}

func TestStoreCreatesRoleBindingSessionIndex(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var count int
	if err := store.db.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_master WHERE type='index' AND name='role_bindings_session'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("role binding session index is missing")
	}
}

func TestStoreBoundsActiveRolesPerSession(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-creator", []string{"agent/creator/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-owner", []string{"agent/owner/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	members := []Member{{Endpoint: "agent/creator/session", Capabilities: CapSend | CapReceive | CapAdmin}}
	for slot := 0; slot <= MaxActiveRolesPerSession; slot++ {
		members = append(members, Member{
			Role:          fmt.Sprintf("role/bound-%03d", slot),
			RoleMachineID: "machine-owner",
			Capabilities:  CapReceive,
		})
	}
	if _, err := store.CreateConversation("agent/creator/session", members, now); err != nil {
		t.Fatal(err)
	}
	for slot := 0; slot < MaxActiveRolesPerSession; slot++ {
		if err := store.BindRoleToSession("machine-owner", fmt.Sprintf("role/bound-%03d", slot), "agent/owner/session", now, time.Minute); err != nil {
			t.Fatalf("bind role %d: %v", slot, err)
		}
	}
	if err := store.BindRoleToSession("machine-owner", fmt.Sprintf("role/bound-%03d", MaxActiveRolesPerSession), "agent/owner/session", now, time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatalf("over-bound session err=%v, want ErrConflict", err)
	}
	if err := store.AdvertiseEndpoints("machine-owner", nil, now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-owner", []string{"agent/owner/session"}, now.Add(2*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-owner", fmt.Sprintf("role/bound-%03d", MaxActiveRolesPerSession), "agent/owner/session", now.Add(2*time.Second), time.Minute); err != nil {
		t.Fatalf("fenced roles exhausted replacement session cap: %v", err)
	}
}

func TestStoreKeepsRoleDeliveryKeysDistinctFromEndpointNames(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-sender", []string{"agent/sender/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-reviewer", []string{"role:reviewer"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/sender/session", []Member{
		{Endpoint: "agent/sender/session", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "role:reviewer", Capabilities: CapReceive},
		{Role: "reviewer", RoleMachineID: "machine-reviewer", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-reviewer", "reviewer", "role:reviewer", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	message, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-sender", FromEndpoint: "agent/sender/session", Body: "two identities", IdempotencyKey: "endpoint-role-collision", Now: now})
	if err != nil {
		t.Fatalf("endpoint and role recipients collided: %v", err)
	}
	page, err := store.LeaseDeliveries("machine-reviewer", "reviewer-collision", "role:reviewer", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 2 {
		t.Fatalf("distinct endpoint and role deliveries page=%#v err=%v", page, err)
	}
	var endpointDeliveryID string
	if err := store.db.QueryRowContext(context.Background(), "SELECT id FROM deliveries WHERE message_id = ? AND recipient_endpoint = ?", message.ID, "role:reviewer").Scan(&endpointDeliveryID); err != nil {
		t.Fatal(err)
	}
	for _, delivery := range page.Deliveries {
		if delivery.ID == endpointDeliveryID {
			if err := store.AckDelivery("machine-reviewer", "role:reviewer", delivery.ID, delivery.LeaseToken, delivery.LeaseGeneration, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	if cursor, err := store.RecipientCursor("machine-reviewer", "role:reviewer", conversation.ID, now); err != nil || cursor != 0 {
		t.Fatalf("shared session cursor=%d err=%v, want pending-role zero", cursor, err)
	}
}

func TestStoreTargetedRoleDeliveryExcludesOtherMembersAndBindsRetry(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-sender", []string{"agent/sender"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-observer", []string{"agent/observer"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/sender", []Member{
		{Endpoint: "agent/sender", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/observer", Capabilities: CapReceive},
		{Role: "role/reviewer", RoleMachineID: "machine-reviewer", Capabilities: CapReceive},
		{Role: "role/implementer", RoleMachineID: "machine-implementer", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	input := AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-sender", FromEndpoint: "agent/sender", TargetRole: "role/reviewer", Body: "targeted", IdempotencyKey: "targeted-1", Now: now}
	message, duplicate, err := store.AppendMessage(input)
	if err != nil || duplicate {
		t.Fatalf("targeted append message=%#v duplicate=%t err=%v", message, duplicate, err)
	}
	var recipients []string
	rows, err := store.db.QueryContext(context.Background(), "SELECT recipient_endpoint FROM deliveries WHERE message_id = ? ORDER BY recipient_endpoint", message.ID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var recipient string
		if err := rows.Scan(&recipient); err != nil {
			t.Fatal(err)
		}
		recipients = append(recipients, recipient)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 || recipients[0] != roleRecipient("role/reviewer") {
		t.Fatalf("targeted recipients=%q", recipients)
	}
	changed := input
	changed.TargetRole = "role/implementer"
	if _, _, err := store.AppendMessage(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed target retry err=%v", err)
	}
	unknown := input
	unknown.IdempotencyKey = "targeted-unknown"
	unknown.TargetRole = "role/missing"
	if _, _, err := store.AppendMessage(unknown); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unknown target role err=%v", err)
	}
	var messageCount, idempotencyCount int
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM messages").Scan(&messageCount); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM idempotency").Scan(&idempotencyCount); err != nil {
		t.Fatal(err)
	}
	if messageCount != 1 || idempotencyCount != 1 {
		t.Fatalf("unknown target mutated state: messages=%d idempotency=%d", messageCount, idempotencyCount)
	}
}

func TestStoreDurableRoleSurvivesRestartButRequiresFreshBinding(t *testing.T) {
	database := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-sender", []string{"agent/sender/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/sender/session", []Member{
		{Endpoint: "agent/sender/session", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: "role/windows-validator", RoleMachineID: "machine-validator", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-sender", FromEndpoint: "agent/sender/session", Body: "validate", IdempotencyKey: "send-restart", Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.AdvertiseEndpoints("machine-validator", []string{"agent/validator/restarted-session"}, now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LeaseDeliveries("machine-validator", "validator-after-restart", "agent/validator/restarted-session", conversation.ID, now.Add(time.Second), time.Minute, 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unbound role lease after restart err=%v", err)
	}
	if err := store.BindRoleToSession("machine-validator", "role/windows-validator", "agent/validator/restarted-session", now.Add(time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-validator", "validator-after-restart", "agent/validator/restarted-session", conversation.ID, now.Add(2*time.Second), time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 || page.Deliveries[0].Message.Body != "validate" {
		t.Fatalf("role delivery after restart page=%#v err=%v", page, err)
	}
}

func TestStoreRejectsUnauthorizedOrExpiredRoleBindings(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-owner", []string{"agent/owner/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-attacker", []string{"agent/attacker/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/owner/session", []Member{
		{Endpoint: "agent/owner/session", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: "role/owner-only", RoleMachineID: "machine-owner", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-attacker", "role/owner-only", "agent/attacker/session", now, time.Minute); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-machine role binding err=%v", err)
	}
	if err := store.BindRoleToSession("machine-owner", "role/owner-only", "agent/attacker/session", now, time.Minute); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign session role binding err=%v", err)
	}
	if err := store.BindRoleToSession("machine-owner", "role/owner-only", "agent/owner/session", now, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-owner", FromEndpoint: "agent/owner/session", Body: "role expiry", IdempotencyKey: "role-expiry", Now: now}); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-owner", "owner-expired-role", "agent/owner/session", conversation.ID, now.Add(2*time.Second), time.Minute, 10)
	if err != nil || len(page.Deliveries) != 0 {
		t.Fatalf("expired binding lease page=%#v err=%v", page, err)
	}
}

func TestStoreRebindingExpiredRoleRevokesOutstandingLeases(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	const (
		ownerMachine  = "machine-expired-rebind-owner"
		senderMachine = "machine-expired-rebind-sender"
		ownerSession  = "agent/expired-rebind/owner"
		senderSession = "agent/expired-rebind/sender"
		role          = "role/expired-rebind"
	)
	if err := store.AdvertiseEndpoints(ownerMachine, []string{ownerSession}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints(senderMachine, []string{senderSession}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation(senderSession, []Member{
		{Endpoint: senderSession, Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: role, RoleMachineID: ownerMachine, Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession(ownerMachine, role, ownerSession, now, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: senderMachine, FromEndpoint: senderSession, Body: "lease fence", IdempotencyKey: "expired-rebind-message", Now: now}); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries(ownerMachine, "expired-rebind-consumer", ownerSession, conversation.ID, now, time.Minute, 1)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("initial role lease page=%#v err=%v", page, err)
	}
	stale := page.Deliveries[0]
	if err := store.BindRoleToSession(ownerMachine, role, ownerSession, now.Add(2*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AckDelivery(ownerMachine, ownerSession, stale.ID, stale.LeaseToken, stale.LeaseGeneration, now.Add(2*time.Second)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired binding rebind acknowledged stale lease: %v", err)
	}
}

func TestStoreRenewsRoleBindingOnlyForTheSameLiveSession(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-owner", []string{"agent/owner/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-creator", []string{"agent/creator/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/creator/session", []Member{
		{Endpoint: "agent/creator/session", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: "role/renewed", RoleMachineID: "machine-owner", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-owner", "role/renewed", "agent/owner/session", now, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-creator", FromEndpoint: "agent/creator/session", Body: "renew me", IdempotencyKey: "renew-role", Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-owner", []string{"agent/owner/session"}, now.Add(500*time.Millisecond), time.Hour); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-owner", "owner-renewed-role", "agent/owner/session", conversation.ID, now.Add(2*time.Second), time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 || page.Deliveries[0].Message.Body != "renew me" {
		t.Fatalf("renewed role lease page=%#v err=%v", page, err)
	}
	if err := store.AdvertiseEndpoints("machine-owner", nil, now.Add(3*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-owner", []string{"agent/owner/session"}, now.Add(4*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	page, err = store.LeaseDeliveries("machine-owner", "owner-reclaimed-role", "agent/owner/session", conversation.ID, now.Add(4*time.Second), time.Minute, 10)
	if !errors.Is(err, ErrForbidden) || len(page.Deliveries) != 0 {
		t.Fatalf("reclaimed session revived role binding page=%#v err=%v", page, err)
	}
}

func TestCreateConversationRequestHashPreservesLegacyUnnamedDigest(t *testing.T) {
	members := []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
	}
	membersDigest := createConversationHash("agent/a", members)
	unnamed := CreateConversationRequestHash("agent/a", members, "")
	named := CreateConversationRequestHash("agent/a", members, "Review room")
	if unnamed != membersDigest {
		t.Fatal("unnamed create hash must match the pre-upgrade membership digest")
	}
	if unnamed == named {
		t.Fatal("display name was not bound into the create hash")
	}
	if got := CreateConversationRequestHash("agent/a", members, ""); got != unnamed {
		t.Fatal("empty display name hash was not stable")
	}
	legacyProject := stableHash(membersDigest, "project-1")
	withProject := CreateConversationRequestHash("agent/a", members, "", "project-1")
	if withProject != legacyProject {
		t.Fatal("unnamed create with project must wrap the pre-upgrade membership digest")
	}
	namedProject := CreateConversationRequestHash("agent/a", members, "Review room", "project-1")
	if namedProject == named || namedProject == unnamed || namedProject == withProject {
		t.Fatal("named project digest did not wrap the display-name hash")
	}
}

func TestStorePersistsConversationDisplayNameAndAllowsUnnamed(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	members := []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
	}
	named, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named-room", CreatorEndpoint: "agent/a",
		DisplayName: "  Review room  ", Members: members, Now: now,
	})
	if err != nil || named.ID == "" || named.DisplayName != "Review room" {
		t.Fatalf("named conversation=%#v err=%v", named, err)
	}
	unnamed, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "unnamed-room", CreatorEndpoint: "agent/a",
		Members: members, Now: now,
	})
	if err != nil || unnamed.ID == "" || unnamed.DisplayName != "" {
		t.Fatalf("unnamed conversation=%#v err=%v", unnamed, err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named-room", CreatorEndpoint: "agent/a",
		DisplayName: "Other room", Members: members, Now: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed display name retry err=%v", err)
	}
	retry, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named-room", CreatorEndpoint: "agent/a",
		DisplayName: "Review room", Members: members, Now: now,
	})
	if err != nil || retry != named {
		t.Fatalf("named retry=%#v err=%v", retry, err)
	}
	for _, invalid := range []string{"\x00room", "room\nname", string([]byte{0xff}), "   "} {
		if _, err := store.CreateConversationIdempotent(CreateConversationInput{
			MachineID: "machine-a", IdempotencyKey: "invalid-" + invalid, CreatorEndpoint: "agent/a",
			DisplayName: invalid, Members: members, Now: now,
		}); err == nil {
			t.Fatalf("invalid display name %q was accepted", invalid)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	listed, err := reopened.ConversationsForMachine("machine-a", now)
	if err != nil || len(listed) != 2 {
		t.Fatalf("reopened list=%#v err=%v", listed, err)
	}
	foundNamed, foundUnnamed := false, false
	for _, conversation := range listed {
		switch conversation.ID {
		case named.ID:
			foundNamed = conversation.DisplayName == "Review room"
		case unnamed.ID:
			foundUnnamed = conversation.DisplayName == ""
		}
	}
	if !foundNamed || !foundUnnamed {
		t.Fatalf("restart did not preserve display names: %#v", listed)
	}
}

func TestSanitizeConversationDisplayNameClampsAndRejectsControls(t *testing.T) {
	if got, err := SanitizeConversationDisplayName(""); err != nil || got != "" {
		t.Fatalf("empty create name=%q err=%v", got, err)
	}
	if got, err := SanitizeConversationDisplayName("  Review room  "); err != nil || got != "Review room" {
		t.Fatalf("trimmed name=%q err=%v", got, err)
	}
	longRunes := strings.Repeat("å", 130)
	got, err := SanitizeConversationDisplayName(longRunes)
	if err != nil || got != strings.Repeat("å", 128) {
		t.Fatalf("clamped runes=%q err=%v", got, err)
	}
	longBytes := strings.Repeat("a", 600)
	got, err = SanitizeConversationDisplayName(longBytes)
	if err != nil || got != strings.Repeat("a", 128) {
		t.Fatalf("clamped ascii runes=%q err=%v", got, err)
	}
	for _, invalid := range []string{"\x00room", "room\tname", string([]byte{0xff}), "   "} {
		if _, err := SanitizeConversationDisplayName(invalid); err == nil {
			t.Fatalf("invalid name %q was accepted", invalid)
		}
	}
}

func TestStoreSetConversationDisplayNameRequiresLiveAdminAndIsIdempotent(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "create", CreatorEndpoint: "agent/a",
		Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}, {Endpoint: "agent/b", Capabilities: CapReceive}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, duplicate, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		DisplayName: "Ops room", IdempotencyKey: "rename-1", Now: now,
	})
	if err != nil || duplicate || first.ID != conversation.ID || first.DisplayName != "Ops room" {
		t.Fatalf("rename=%#v duplicate=%v err=%v", first, duplicate, err)
	}
	retry, duplicate, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		DisplayName: "Ops room", IdempotencyKey: "rename-1", Now: now.Add(time.Second),
	})
	if err != nil || !duplicate || retry != first {
		t.Fatalf("rename retry=%#v duplicate=%v err=%v", retry, duplicate, err)
	}
	if _, _, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-b", ActorEndpoint: "agent/b",
		DisplayName: "Hijacked", IdempotencyKey: "rename-2", Now: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin rename err=%v", err)
	}
	for _, invalid := range []string{"", "   "} {
		if _, _, err := store.SetConversationDisplayName(SetDisplayNameInput{
			ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
			DisplayName: invalid, IdempotencyKey: "rename-empty", Now: now,
		}); err == nil {
			t.Fatalf("empty rename %q was accepted", invalid)
		}
	}
	if _, _, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		DisplayName: "Expired", IdempotencyKey: "rename-expired", Now: now.Add(2 * time.Hour),
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired admin rename err=%v", err)
	}
	listed, err := store.ConversationsForMachine("machine-a", now)
	if err != nil || len(listed) != 1 || listed[0].DisplayName != "Ops room" {
		t.Fatalf("listed after rename=%#v err=%v", listed, err)
	}
}

func TestStoreSetConversationDisplayNameBindsIdempotencyKeyToOriginalRequest(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 19, 13, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "create-rename-bind", CreatorEndpoint: "agent/a",
		Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}, {Endpoint: "agent/b", Capabilities: CapReceive}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, duplicate, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		DisplayName: "Alpha", IdempotencyKey: "rename-a", Now: now,
	})
	if err != nil || duplicate || first.DisplayName != "Alpha" {
		t.Fatalf("rename A=%#v duplicate=%v err=%v", first, duplicate, err)
	}
	if _, _, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		DisplayName: "Changed", IdempotencyKey: "rename-a", Now: now.Add(time.Second),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed-label retry err=%v", err)
	}
	current, err := conversationByIDViaStore(store, conversation.ID)
	if err != nil || current.DisplayName != "Alpha" {
		t.Fatalf("after changed-label retry=%#v err=%v", current, err)
	}
	second, duplicate, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		DisplayName: "Beta", IdempotencyKey: "rename-b", Now: now.Add(2 * time.Second),
	})
	if err != nil || duplicate || second.DisplayName != "Beta" {
		t.Fatalf("rename B=%#v duplicate=%v err=%v", second, duplicate, err)
	}
	replay, duplicate, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		DisplayName: "Alpha", IdempotencyKey: "rename-a", Now: now.Add(3 * time.Second),
	})
	if err != nil || !duplicate || replay.DisplayName != "Beta" {
		t.Fatalf("intervening replay=%#v duplicate=%v err=%v", replay, duplicate, err)
	}
}

func TestStoreUnnamedConversationsRemainManyToMany(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 14, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	members := []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
	}
	first, err := store.CreateConversation("agent/a", members, now)
	if err != nil || first.DisplayName != "" {
		t.Fatalf("first unnamed=%#v err=%v", first, err)
	}
	second, err := store.CreateConversation("agent/a", members, now)
	if err != nil || second.ID == first.ID || second.DisplayName != "" {
		t.Fatalf("second unnamed=%#v first=%#v err=%v", second, first, err)
	}
}

func TestStoreFencesOneSessionToOneNamedConversation(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 14, 0, 0, 0, time.UTC)
	for machine, endpoint := range map[string]string{"machine-a": "agent/a", "machine-b": "agent/b", "machine-c": "agent/c"} {
		if err := store.AdvertiseEndpoints(machine, []string{endpoint}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	shared, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "shared-named", CreatorEndpoint: "agent/a",
		DisplayName: "Shared room", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
			{Endpoint: "agent/b", Capabilities: CapSend | CapReceive},
		}, Now: now,
	})
	if err != nil || shared.DisplayName != "Shared room" {
		t.Fatalf("shared named=%#v err=%v", shared, err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "second-named-a", CreatorEndpoint: "agent/a",
		DisplayName: "Second room", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		}, Now: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("second named join for agent/a err=%v", err)
	}
	unnamed, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/c", Capabilities: CapReceive},
	}, now)
	if err != nil || unnamed.DisplayName != "" {
		t.Fatalf("unnamed alongside named=%#v err=%v", unnamed, err)
	}
	other, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-c", IdempotencyKey: "other-named", CreatorEndpoint: "agent/c",
		DisplayName: "Other room", Members: []Member{
			{Endpoint: "agent/c", Capabilities: CapSend | CapReceive | CapAdmin},
		}, Now: now,
	})
	if err != nil || other.DisplayName != "Other room" {
		t.Fatalf("distinct session named=%#v err=%v", other, err)
	}
	retry, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "shared-named", CreatorEndpoint: "agent/a",
		DisplayName: "Shared room", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
			{Endpoint: "agent/b", Capabilities: CapSend | CapReceive},
		}, Now: now,
	})
	if err != nil || retry != shared {
		t.Fatalf("named retry=%#v err=%v", retry, err)
	}
}

func TestStoreTelegramPrimaryIsExemptFromNamedOccupancy(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 14, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{"telegram/primary"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	first, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named-a", CreatorEndpoint: "agent/a",
		DisplayName: "Alpha", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-b", IdempotencyKey: "named-b", CreatorEndpoint: "agent/b",
		DisplayName: "Beta", Members: []Member{
			{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin},
		}, Now: now,
	})
	if err != nil || second.ID == first.ID {
		t.Fatalf("second named=%#v first=%#v err=%v", second, first, err)
	}
	mustReserveAndCompleteTelegramClaim(t, store, first.ID, "machine-a", "agent/a", now)
	mustReserveAndCompleteTelegramClaim(t, store, second.ID, "machine-b", "agent/b", now.Add(time.Second))
}

func TestStoreRenameToNameChecksOccupancy(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 14, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	named, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "already-named", CreatorEndpoint: "agent/a",
		DisplayName: "Occupied", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	unnamed, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		{Endpoint: "agent/b", Capabilities: CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: unnamed.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		DisplayName: "Second name", IdempotencyKey: "rename-conflict", Now: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("rename while occupying another named room err=%v", err)
	}
	if _, _, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: named.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		DisplayName: "Occupied still", IdempotencyKey: "rename-already-named", Now: now,
	}); err != nil {
		t.Fatalf("rename of already-named room err=%v", err)
	}
	free, err := store.CreateConversation("agent/b", []Member{
		{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	renamed, duplicate, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: free.ID, ActorMachineID: "machine-b", ActorEndpoint: "agent/b",
		DisplayName: "Free room", IdempotencyKey: "rename-free", Now: now,
	})
	if err != nil || duplicate || renamed.DisplayName != "Free room" {
		t.Fatalf("rename of unoccupied room=%#v duplicate=%v err=%v", renamed, duplicate, err)
	}
}

func TestStoreControlUpsertFencesNamedOccupancy(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 14, 0, 0, 0, time.UTC)
	for machine, endpoint := range map[string]string{
		"machine-a":        "agent/a",
		"machine-b":        "agent/b",
		"machine-c":        "agent/c",
		"machine-telegram": "telegram/primary",
	} {
		if err := store.AdvertiseEndpoints(machine, []string{endpoint}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	namedA, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named-a", CreatorEndpoint: "agent/a",
		DisplayName: "Room A", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	namedB, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-b", IdempotencyKey: "named-b", CreatorEndpoint: "agent/b",
		DisplayName: "Room B", Members: []Member{
			{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin},
		}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: namedB.ID, ActorMachineID: "machine-b", ActorEndpoint: "agent/b",
		Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/a", Capabilities: CapReceive},
		IdempotencyKey: "upsert-occupied", Now: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("upsert into second named room err=%v", err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: namedA.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		IdempotencyKey: "upsert-same-room", Now: now,
	}); err != nil {
		t.Fatalf("upsert existing named member err=%v", err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: namedA.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlUpsertMember, Member: Member{Endpoint: "agent/c", Capabilities: CapReceive},
		IdempotencyKey: "upsert-free", Now: now,
	}); err != nil {
		t.Fatalf("upsert unoccupied session err=%v", err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: namedA.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlUpsertMember, Member: Member{Endpoint: TelegramGatewayEndpoint, Capabilities: CapReceive},
		IdempotencyKey: "upsert-telegram-a", Now: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member set telegram/primary err=%v", err)
	}
	mustReserveAndCompleteTelegramClaim(t, store, namedA.ID, "machine-a", "agent/a", now)
	mustReserveAndCompleteTelegramClaim(t, store, namedB.ID, "machine-b", "agent/b", now.Add(time.Second))
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: namedA.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlRemoveMember, Member: Member{Endpoint: TelegramGatewayEndpoint},
		IdempotencyKey: "remove-telegram-a", Now: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("remove telegram/primary after complete err=%v", err)
	}
}

func TestStoreBindRoleAndRoleMembershipFenceNamedOccupancy(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 14, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a", "agent/a2"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-creator", []string{"agent/creator"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-creator", IdempotencyKey: "named-role-a", CreatorEndpoint: "agent/creator",
		DisplayName: "Role room A", Members: []Member{
			{Endpoint: "agent/creator", Capabilities: CapSend | CapReceive | CapAdmin},
			{Role: "role/reviewer", RoleMachineID: "machine-a", Capabilities: CapReceive},
		}, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named-a2", CreatorEndpoint: "agent/a2",
		DisplayName: "Session room A2", Members: []Member{
			{Endpoint: "agent/a2", Capabilities: CapSend | CapReceive | CapAdmin},
		}, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-a", "role/reviewer", "agent/a", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-a", "role/reviewer", "agent/a", now.Add(time.Second), time.Hour); err != nil {
		t.Fatalf("renew bind onto the same named room err=%v", err)
	}
	if err := store.BindRoleToSession("machine-a", "role/reviewer", "agent/a2", now.Add(2*time.Second), time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatalf("bind named role onto session occupying another named room err=%v", err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-b", IdempotencyKey: "named-role-conflict", CreatorEndpoint: "agent/b",
		DisplayName: "Role room B", Members: []Member{
			{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin},
			{Role: "role/reviewer", RoleMachineID: "machine-a", Capabilities: CapReceive},
		}, Now: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("named role membership for occupied session err=%v", err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-b", IdempotencyKey: "named-other-role", CreatorEndpoint: "agent/b",
		DisplayName: "Other role room", Members: []Member{
			{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin},
			{Role: "role/other", RoleMachineID: "machine-a", Capabilities: CapReceive},
		}, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-a", "role/other", "agent/a", now.Add(3*time.Second), time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatalf("bind role into second named room err=%v", err)
	}
	unnamed, err := store.CreateConversation("agent/creator", []Member{
		{Endpoint: "agent/creator", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: "role/unnamed", RoleMachineID: "machine-a", Capabilities: CapReceive},
	}, now)
	if err != nil || unnamed.DisplayName != "" {
		t.Fatalf("unnamed role room=%#v err=%v", unnamed, err)
	}
	if err := store.BindRoleToSession("machine-a", "role/unnamed", "agent/a", now.Add(4*time.Second), time.Hour); err != nil {
		t.Fatalf("bind unnamed role while occupying one named room err=%v", err)
	}
}

func TestStoreRejectsUserTelegramAsDurableRoleAndMember(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 16, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "create-role", CreatorEndpoint: "agent/a",
		DisplayName: "Named", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
			{Role: TelegramUserParticipant, RoleMachineID: "machine-a", Capabilities: CapReceive},
		}, Now: now,
	}); err == nil {
		t.Fatal("created durable role user-telegram")
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "create-ok", CreatorEndpoint: "agent/a",
		DisplayName: "Named", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ApplyControl(ControlInput{
		ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a",
		Operation: ControlUpsertMember, Member: Member{Endpoint: TelegramUserParticipant, Capabilities: CapReceive},
		IdempotencyKey: "member-set", Now: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("member set user-telegram err=%v", err)
	}
	if err := store.BindRoleToSession("machine-a", TelegramUserParticipant, "agent/a", now, time.Hour); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bind reserved participant err=%v", err)
	}
	if _, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "create-gateway", CreatorEndpoint: "agent/a",
		DisplayName: "Gateway member", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
			{Endpoint: TelegramGatewayEndpoint, Capabilities: CapSend | CapReceive},
		}, Now: now,
	}); err == nil {
		t.Fatal("created conversation with telegram/primary member")
	}
}

func mustReserveAndCompleteTelegramClaim(t *testing.T, store *Store, conversationID, actorMachine, actorEndpoint string, now time.Time) {
	t.Helper()
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: conversationID, MachineID: actorMachine, Endpoint: actorEndpoint,
		IdempotencyKey: "claim-" + conversationID, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{ConversationID: conversationID, MachineID: "machine-telegram", Now: now}); err != nil {
		t.Fatal(err)
	}
}

func TestStoreCompleteClampsTelegramPrimaryCapabilities(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 16, 7, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named", CreatorEndpoint: "agent/a",
		DisplayName: "Ops", Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), "INSERT INTO memberships(conversation_id, endpoint, capabilities) VALUES (?, ?, ?)", conversation.ID, TelegramGatewayEndpoint, CapSend|CapReceive|CapAdmin|CapInvoke); err != nil {
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
	var capabilities Capability
	if err := store.db.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?", conversation.ID, TelegramGatewayEndpoint).Scan(&capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities != TelegramGatewayCapabilities {
		t.Fatalf("clamped gateway capabilities=%d", capabilities)
	}
}

func TestStoreTelegramInboundRequiresCompleteClaim(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 16, 8, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named", CreatorEndpoint: "agent/a",
		DisplayName: "Ops", Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), "INSERT INTO memberships(conversation_id, endpoint, capabilities) VALUES (?, ?, ?)", conversation.ID, TelegramGatewayEndpoint, CapSend|CapReceive); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "too soon", IdempotencyKey: "telegram-update:1", Now: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("inbound before complete err=%v", err)
	}
	if err := ValidateTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "ok", InReplyToMessageID: " not-a-token", IdempotencyKey: "telegram-update:2",
	}); !errors.Is(err, ErrForbidden) {
		t.Fatal("invalid reply-to message id accepted")
	}
}

func TestStoreReserveTelegramClaimIsSingletonEnsure(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 16, 1, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	unnamed, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "unnamed", CreatorEndpoint: "agent/a",
		Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: unnamed.ID, MachineID: "machine-a", Endpoint: "agent/a",
		IdempotencyKey: "claim-unnamed", Now: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unnamed reserve err=%v", err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named", CreatorEndpoint: "agent/a",
		DisplayName: "How is it going", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
		}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: conversation.ID, MachineID: "machine-a", Endpoint: "agent/a",
		IdempotencyKey: "claim-" + conversation.ID, Now: now,
	})
	if err != nil || duplicate || first.Status != "pending" || first.DisplayName != "How is it going" || first.ConversationID != conversation.ID {
		t.Fatalf("first reserve=%#v duplicate=%t err=%v", first, duplicate, err)
	}
	retry, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: conversation.ID, MachineID: "machine-a", Endpoint: "agent/a",
		IdempotencyKey: "claim-" + conversation.ID, Now: now.Add(time.Second),
	})
	if err != nil || !duplicate || retry.CreatedAt != first.CreatedAt || retry.Status != "pending" {
		t.Fatalf("same-key retry=%#v duplicate=%t err=%v", retry, duplicate, err)
	}
	gateway, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: conversation.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "gateway-claim-" + conversation.ID, Now: now.Add(2 * time.Second),
	})
	if err != nil || !duplicate || gateway.CreatedAt != first.CreatedAt {
		t.Fatalf("other-key ensure=%#v duplicate=%t err=%v", gateway, duplicate, err)
	}
	var storedKey, storedEndpoint string
	if err := store.db.QueryRowContext(context.Background(), "SELECT idempotency_key, requested_by_endpoint FROM telegram_claims WHERE conversation_id=?", conversation.ID).Scan(&storedKey, &storedEndpoint); err != nil {
		t.Fatal(err)
	}
	if storedKey != "claim-"+conversation.ID || storedEndpoint != "agent/a" {
		t.Fatalf("ensure rewrote reservation key=%q endpoint=%q", storedKey, storedEndpoint)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: conversation.ID, MachineID: "machine-telegram", Endpoint: "agent/a",
		IdempotencyKey: "stolen", Now: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("gateway using foreign endpoint err=%v", err)
	}
}

func TestStoreReserveTelegramClaimBindsEnsureKeyToExistingClaim(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 19, 16, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	firstRoom, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named-first", CreatorEndpoint: "agent/a",
		DisplayName: "First room", Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondRoom, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-b", IdempotencyKey: "named-second", CreatorEndpoint: "agent/b",
		DisplayName: "Second room", Members: []Member{{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: firstRoom.ID, MachineID: "machine-a", Endpoint: "agent/a",
		IdempotencyKey: "agent-claim", Now: now,
	}); err != nil || duplicate {
		t.Fatalf("first reserve duplicate=%t err=%v", duplicate, err)
	}
	ensure, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: firstRoom.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "shared-ensure-key", Now: now.Add(time.Second),
	})
	if err != nil || !duplicate || ensure.ConversationID != firstRoom.ID {
		t.Fatalf("ensure existing=%#v duplicate=%t err=%v", ensure, duplicate, err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: secondRoom.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "shared-ensure-key", Now: now.Add(2 * time.Second),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("ensure key reused on another conversation err=%v", err)
	}
	replay, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: firstRoom.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "shared-ensure-key", Now: now.Add(3 * time.Second),
	})
	if err != nil || !duplicate || replay.ConversationID != firstRoom.ID {
		t.Fatalf("ensure-key replay=%#v duplicate=%t err=%v", replay, duplicate, err)
	}
	var storedKey string
	if err := store.db.QueryRowContext(context.Background(), "SELECT idempotency_key FROM telegram_claims WHERE conversation_id=?", firstRoom.ID).Scan(&storedKey); err != nil {
		t.Fatal(err)
	}
	if storedKey != "agent-claim" {
		t.Fatalf("ensure rewrote reservation key=%q", storedKey)
	}
}

func TestStoreReserveTelegramClaimBindsIdempotencyKeyToOneConversation(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 19, 15, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	firstRoom, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named-first", CreatorEndpoint: "agent/a",
		DisplayName: "First room", Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondRoom, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-b", IdempotencyKey: "named-second", CreatorEndpoint: "agent/b",
		DisplayName: "Second room", Members: []Member{{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: firstRoom.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "shared-claim-key", Now: now,
	})
	if err != nil || duplicate || first.ConversationID != firstRoom.ID {
		t.Fatalf("first reserve=%#v duplicate=%t err=%v", first, duplicate, err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: secondRoom.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "shared-claim-key", Now: now.Add(time.Second),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-key different conversation err=%v", err)
	}
	replay, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: firstRoom.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "shared-claim-key", Now: now.Add(2 * time.Second),
	})
	if err != nil || !duplicate || replay.ConversationID != firstRoom.ID {
		t.Fatalf("same-key replay=%#v duplicate=%t err=%v", replay, duplicate, err)
	}
	other, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: secondRoom.ID, MachineID: "machine-b", Endpoint: "agent/b",
		IdempotencyKey: "shared-claim-key", Now: now.Add(3 * time.Second),
	})
	if err != nil || duplicate || other.ConversationID != secondRoom.ID {
		t.Fatalf("other-machine same key=%#v duplicate=%t err=%v", other, duplicate, err)
	}
	var count int
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM telegram_claims").Scan(&count); err != nil || count != 2 {
		t.Fatalf("claims=%d err=%v", count, err)
	}
}

func TestStoreOpenReconcilesLegacyDuplicateTelegramClaimKeys(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 19, 21, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	firstRoom, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "legacy-dup-first", CreatorEndpoint: "agent/a",
		DisplayName: "Legacy first", Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondRoom, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-b", IdempotencyKey: "legacy-dup-second", CreatorEndpoint: "agent/b",
		DisplayName: "Legacy second", Members: []Member{{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: firstRoom.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "legacy-shared-key", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `DROP INDEX IF EXISTS telegram_claims_machine_key`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `INSERT INTO telegram_claims(conversation_id, status, requested_by_machine, requested_by_endpoint, idempotency_key, request_hash, created_at)
		VALUES (?, 'pending', 'machine-telegram', ?, 'legacy-shared-key', ?, ?)`, secondRoom.ID, TelegramGatewayEndpoint, telegramClaimRequestHash(secondRoom.ID), now.Add(time.Second).UTC().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("open after legacy duplicate keys: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	var kept, dropped int
	if err := reopened.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM telegram_claims WHERE conversation_id=?", firstRoom.ID).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if err := reopened.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM telegram_claims WHERE conversation_id=?", secondRoom.ID).Scan(&dropped); err != nil {
		t.Fatal(err)
	}
	if kept != 1 || dropped != 0 {
		t.Fatalf("reconcile kept=%d dropped=%d", kept, dropped)
	}
	if _, _, err := reopened.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: secondRoom.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "legacy-shared-key", Now: now.Add(2 * time.Second),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused legacy key after migrate err=%v", err)
	}
}

func TestStoreOpenPreservesCompletedDuplicateTelegramClaimKeys(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 19, 21, 30, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	firstRoom, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "legacy-complete-dup-first", CreatorEndpoint: "agent/a",
		DisplayName: "Complete first", Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondRoom, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-b", IdempotencyKey: "legacy-complete-dup-second", CreatorEndpoint: "agent/b",
		DisplayName: "Complete second", Members: []Member{{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: firstRoom.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "legacy-complete-key", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{
		ConversationID: firstRoom.ID, MachineID: "machine-telegram", Now: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `DROP INDEX IF EXISTS telegram_claims_machine_key`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `INSERT INTO telegram_claims(conversation_id, status, requested_by_machine, requested_by_endpoint, idempotency_key, request_hash, created_at)
		VALUES (?, 'pending', 'machine-telegram', ?, 'legacy-complete-key', ?, ?)`, secondRoom.ID, TelegramGatewayEndpoint, telegramClaimRequestHash(secondRoom.ID), now.Add(2*time.Second).UTC().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{
		ConversationID: secondRoom.ID, MachineID: "machine-telegram", Now: now.Add(3 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-c", []string{"agent/c"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	thirdRoom, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-c", IdempotencyKey: "legacy-complete-dup-third", CreatorEndpoint: "agent/c",
		DisplayName: "Complete third", Members: []Member{{Endpoint: "agent/c", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `INSERT INTO telegram_claims(conversation_id, status, requested_by_machine, requested_by_endpoint, idempotency_key, request_hash, created_at)
		VALUES (?, 'pending', 'machine-telegram', ?, ?, ?, ?)`, thirdRoom.ID, TelegramGatewayEndpoint, "legacy-dup-"+secondRoom.ID, telegramClaimRequestHash(thirdRoom.ID), now.Add(4*time.Second).UTC().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("open after completed duplicate keys: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	var firstStatus, firstKey, secondStatus, secondKey string
	if err := reopened.db.QueryRowContext(context.Background(), `SELECT status, idempotency_key FROM telegram_claims WHERE conversation_id=?`, firstRoom.ID).Scan(&firstStatus, &firstKey); err != nil {
		t.Fatal(err)
	}
	if firstStatus != "complete" || firstKey != "legacy-complete-key" {
		t.Fatalf("keeper status=%q key=%q", firstStatus, firstKey)
	}
	if err := reopened.db.QueryRowContext(context.Background(), `SELECT status, idempotency_key FROM telegram_claims WHERE conversation_id=?`, secondRoom.ID).Scan(&secondStatus, &secondKey); err != nil {
		t.Fatal(err)
	}
	if secondStatus != "complete" || secondKey != "legacy-dup-"+secondRoom.ID+"-1" {
		t.Fatalf("rekeyed status=%q key=%q", secondStatus, secondKey)
	}
	var thirdKey string
	if err := reopened.db.QueryRowContext(context.Background(), `SELECT idempotency_key FROM telegram_claims WHERE conversation_id=?`, thirdRoom.ID).Scan(&thirdKey); err != nil {
		t.Fatal(err)
	}
	if thirdKey != "legacy-dup-"+secondRoom.ID {
		t.Fatalf("colliding key rewritten third=%q", thirdKey)
	}
	var participants int
	if err := reopened.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM telegram_participants").Scan(&participants); err != nil || participants != 2 {
		t.Fatalf("participants=%d err=%v", participants, err)
	}
	replay, duplicate, err := reopened.CompleteTelegramClaim(TelegramClaimCompleteInput{
		ConversationID: secondRoom.ID, MachineID: "machine-telegram", Now: now.Add(4 * time.Second),
	})
	if err != nil || !duplicate || replay.Status != "complete" {
		t.Fatalf("complete replay=%#v duplicate=%t err=%v", replay, duplicate, err)
	}
}

func TestStoreReserveTelegramClaimOccupancyFence(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 16, 2, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	namedA, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named-a", CreatorEndpoint: "agent/a",
		DisplayName: "Room A", Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	namedB, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-b", IdempotencyKey: "named-b", CreatorEndpoint: "agent/b",
		DisplayName: "Room B", Members: []Member{{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: namedA.ID, MachineID: "machine-telegram", Endpoint: TelegramGatewayEndpoint,
		IdempotencyKey: "gateway-claim-a", Now: now,
	}); err != nil {
		t.Fatalf("gateway reserve of unoccupied named room err=%v", err)
	}
	if _, err := store.db.ExecContext(context.Background(), "INSERT INTO memberships(conversation_id, endpoint, capabilities) VALUES (?, ?, ?)", namedB.ID, "agent/a", CapReceive); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: namedB.ID, MachineID: "machine-b", Endpoint: "agent/b",
		IdempotencyKey: "claim-b", Now: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("claim with occupant of another named room err=%v", err)
	}
}

func TestStoreCompleteTelegramClaimMaterializesParticipant(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 16, 3, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named", CreatorEndpoint: "agent/a",
		DisplayName: "Ops", Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{ConversationID: conversation.ID, MachineID: "machine-telegram", Now: now}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("complete without reserve err=%v", err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: conversation.ID, MachineID: "machine-a", Endpoint: "agent/a",
		IdempotencyKey: "claim-" + conversation.ID, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{ConversationID: conversation.ID, MachineID: "machine-a", Now: now}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-gateway complete err=%v", err)
	}
	completed, duplicate, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{ConversationID: conversation.ID, MachineID: "machine-telegram", Now: now.Add(time.Second)})
	if err != nil || duplicate || completed.Status != "complete" || completed.CompletedAt == nil {
		t.Fatalf("complete=%#v duplicate=%t err=%v", completed, duplicate, err)
	}
	retry, duplicate, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{ConversationID: conversation.ID, MachineID: "machine-telegram", Now: now.Add(2 * time.Second)})
	if err != nil || !duplicate || retry.CompletedAt == nil || !retry.CompletedAt.Equal(*completed.CompletedAt) {
		t.Fatalf("complete retry=%#v duplicate=%t err=%v", retry, duplicate, err)
	}
	var capabilities Capability
	if err := store.db.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?", conversation.ID, TelegramGatewayEndpoint).Scan(&capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities != CapSend|CapReceive {
		t.Fatalf("gateway capabilities=%d", capabilities)
	}
	var label string
	if err := store.db.QueryRowContext(context.Background(), "SELECT label FROM telegram_participants WHERE conversation_id=?", conversation.ID).Scan(&label); err != nil || label != TelegramUserParticipant {
		t.Fatalf("participant=%q err=%v", label, err)
	}
	var events int
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM telegram_claim_events WHERE conversation_id=? AND event='complete'", conversation.ID).Scan(&events); err != nil || events != 1 {
		t.Fatalf("claim events=%d err=%v", events, err)
	}
	ensure, duplicate, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: conversation.ID, MachineID: "machine-a", Endpoint: "agent/a",
		IdempotencyKey: "later-key", Now: now.Add(3 * time.Second),
	})
	if err != nil || !duplicate || ensure.Status != "complete" {
		t.Fatalf("ensure after complete=%#v duplicate=%t err=%v", ensure, duplicate, err)
	}
}

func TestStoreAppendUserTelegramRequiresCompleteClaim(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 16, 4, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named", CreatorEndpoint: "agent/a",
		DisplayName: "Ops", Members: []Member{
			{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin},
			{Endpoint: "agent/b", Capabilities: CapReceive},
		}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", TargetRole: TelegramUserParticipant, Body: "ping", IdempotencyKey: "to-user", Now: now}
	if _, _, err := store.AppendMessage(input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unclaimed user-telegram send err=%v", err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: conversation.ID, MachineID: "machine-a", Endpoint: "agent/a",
		IdempotencyKey: "claim-" + conversation.ID, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("pending user-telegram send err=%v", err)
	}
	if _, _, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{ConversationID: conversation.ID, MachineID: "machine-telegram", Now: now}); err != nil {
		t.Fatal(err)
	}
	message, duplicate, err := store.AppendMessage(input)
	if err != nil || duplicate {
		t.Fatalf("claimed user-telegram send=%#v duplicate=%t err=%v", message, duplicate, err)
	}
	var recipients []string
	rows, err := store.db.QueryContext(context.Background(), "SELECT recipient_endpoint FROM deliveries WHERE message_id=? ORDER BY recipient_endpoint", message.ID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var recipient string
		if err := rows.Scan(&recipient); err != nil {
			t.Fatal(err)
		}
		recipients = append(recipients, recipient)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 || recipients[0] != TelegramGatewayEndpoint {
		t.Fatalf("user-telegram recipients=%q", recipients)
	}
	if cursor, err := store.RecipientCursor("machine-b", "agent/b", conversation.ID, now); err != nil || cursor != 1 {
		t.Fatalf("observer cursor=%d err=%v", cursor, err)
	}
}

func TestStoreTelegramInboundConsumesRateLimitsAndQuota(t *testing.T) {
	t.Parallel()
	cfg := tightRateLimits()
	cfg.SenderBurst = 1
	cfg.ConversationBurst = 1
	store := openRateLimitedStore(t, cfg)
	if err := store.SetQuotaLimits(tightQuota(1, 1024, 8, 4096)); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 16, 16, 6, 0, 0, time.UTC)
	conversation := createClaimedTelegramConversation(t, store, now)
	first, duplicate, err := store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "from-user", IdempotencyKey: "telegram-update:1", Now: now,
	})
	if err != nil || duplicate || first.Sequence != 1 {
		t.Fatalf("first inbound=%#v duplicate=%t err=%v", first, duplicate, err)
	}
	if counters := quotaRecipientCounters(t, store, "agent/a"); counters.Count != 1 {
		t.Fatalf("inbound quota=%#v", counters)
	}
	_, _, err = store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "again", IdempotencyKey: "telegram-update:2", Now: now,
	})
	assertRateLimited(t, err, 1)
	var messages int
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM messages WHERE conversation_id=?", conversation.ID).Scan(&messages); err != nil || messages != 1 {
		t.Fatalf("denied inbound mutated messages=%d err=%v", messages, err)
	}
}

func TestStoreTelegramInboundRefreshesPendingMetrics(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	metrics := &Metrics{}
	now := time.Date(2026, time.August, 16, 16, 7, 0, 0, time.UTC)
	conversation := createClaimedTelegramConversation(t, store, now)
	store.SetMetrics(metrics)
	if snap := metrics.Snapshot(); snap.RelayPendingDeliveries != 0 || snap.RelayPendingBytes != 0 {
		t.Fatalf("baseline pending=%#v", snap)
	}
	first, duplicate, err := store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "from-user", IdempotencyKey: "telegram-update:1", Now: now,
	})
	if err != nil || duplicate || first.Sequence != 1 {
		t.Fatalf("first inbound=%#v duplicate=%t err=%v", first, duplicate, err)
	}
	snap := metrics.Snapshot()
	if snap.RelayPendingDeliveries != 1 || snap.RelayPendingBytes != uint64(len("from-user")) {
		t.Fatalf("after inbound pending=%#v", snap)
	}
	retry, duplicate, err := store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "from-user", IdempotencyKey: "telegram-update:1", Now: now.Add(time.Second),
	})
	if err != nil || !duplicate || retry.ID != first.ID {
		t.Fatalf("replay=%#v duplicate=%t err=%v", retry, duplicate, err)
	}
	if snap := metrics.Snapshot(); snap.RelayPendingDeliveries != 1 || snap.RelayPendingBytes != uint64(len("from-user")) {
		t.Fatalf("replay pending=%#v", snap)
	}
}

func TestStoreTelegramInboundExcludesMetadataFromHash(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 16, 5, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named", CreatorEndpoint: "agent/a",
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
	first, duplicate, err := store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "ship it", IdempotencyKey: "telegram-update:42", Now: now,
	})
	if err != nil || duplicate || first.FromParticipant != TelegramUserParticipant || first.InReplyToPunaroMessageID != "" {
		t.Fatalf("inbound=%#v duplicate=%t err=%v", first, duplicate, err)
	}
	retry, duplicate, err := store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "ship it", InReplyToMessageID: first.ID,
		InReplyToEndpoint: "agent/a", TelegramThreadID: 795446, IdempotencyKey: "telegram-update:42", Now: now.Add(time.Second),
	})
	if err != nil || !duplicate || retry.ID != first.ID || retry.InReplyToPunaroMessageID != "" || retry.TelegramThreadID != 0 {
		t.Fatalf("metadata retry=%#v duplicate=%t err=%v", retry, duplicate, err)
	}
	second, duplicate, err := store.AppendTelegramInbound(TelegramInboundInput{
		ConversationID: conversation.ID, SenderMachineID: "machine-telegram", FromEndpoint: TelegramGatewayEndpoint,
		FromParticipant: TelegramUserParticipant, Body: "follow up", InReplyToMessageID: first.ID,
		InReplyToEndpoint: "agent/a", TelegramThreadID: 795446, IdempotencyKey: "telegram-update:43", Now: now.Add(2 * time.Second),
	})
	if err != nil || duplicate || second.InReplyToPunaroMessageID != first.ID || second.InReplyToEndpoint != "agent/a" || second.TelegramThreadID != 795446 {
		t.Fatalf("second inbound=%#v duplicate=%t err=%v", second, duplicate, err)
	}
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now.Add(3*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-a", "adapter-a", "agent/a", conversation.ID, now.Add(3*time.Second), time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	var leased Message
	for _, delivery := range page.Deliveries {
		if delivery.Message.ID == second.ID {
			leased = delivery.Message
		}
	}
	if leased.ID != second.ID || leased.FromEndpoint != TelegramGatewayEndpoint || leased.FromParticipant != TelegramUserParticipant || leased.InReplyToPunaroMessageID != first.ID || leased.InReplyToEndpoint != "agent/a" || leased.TelegramThreadID != 795446 {
		t.Fatalf("leased inbound=%#v deliveries=%#v", leased, page.Deliveries)
	}
}

func TestStoreSessionTopicPendingAndUnclaimed(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 16, 6, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-telegram", []string{TelegramGatewayEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SessionTopic("machine-a", "agent/a", now); !errors.Is(err, ErrForbidden) {
		t.Fatalf("empty occupancy err=%v", err)
	}
	older, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-b", IdempotencyKey: "older", CreatorEndpoint: "agent/b",
		DisplayName: "Older", Members: []Member{{Endpoint: "agent/b", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	named, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "machine-a", IdempotencyKey: "named", CreatorEndpoint: "agent/a",
		DisplayName: "Newer", Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}}, Now: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: named.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "latest", IdempotencyKey: "msg-new", Now: now.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	topic, err := store.SessionTopic("machine-a", "agent/a", now)
	if err != nil || topic.ID != named.ID || topic.Claimed || topic.DisplayName != "Newer" {
		t.Fatalf("unclaimed topic=%#v err=%v", topic, err)
	}
	unclaimed, err := store.UnclaimedNamedConversations("machine-telegram", now, 10)
	if err != nil || len(unclaimed) != 2 || unclaimed[0].ID != named.ID || unclaimed[1].ID != older.ID || unclaimed[0].LastMessageAt == nil || unclaimed[1].LastMessageAt != nil {
		t.Fatalf("unclaimed=%#v err=%v", unclaimed, err)
	}
	if _, _, err := store.ReserveTelegramClaim(TelegramClaimInput{
		ConversationID: named.ID, MachineID: "machine-a", Endpoint: "agent/a",
		IdempotencyKey: "claim-" + named.ID, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingTelegramClaims("machine-telegram", now, 1, "")
	if err != nil || len(pending) != 1 || pending[0].ConversationID != named.ID || pending[0].Status != "pending" {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	if _, err := store.PendingTelegramClaims("machine-a", now, 1, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-gateway pending err=%v", err)
	}
	if _, _, err := store.CompleteTelegramClaim(TelegramClaimCompleteInput{ConversationID: named.ID, MachineID: "machine-telegram", Now: now}); err != nil {
		t.Fatal(err)
	}
	claimed, err := store.SessionTopic("machine-a", "agent/a", now)
	if err != nil || !claimed.Claimed || claimed.ID != named.ID {
		t.Fatalf("claimed topic=%#v err=%v", claimed, err)
	}
	after, err := store.UnclaimedNamedConversations("machine-telegram", now, 10)
	if err != nil || len(after) != 1 || after[0].ID != older.ID {
		t.Fatalf("unclaimed after complete=%#v err=%v", after, err)
	}
}

func TestStoreOpenIsIdempotentWithClaimSchema(t *testing.T) {
	t.Parallel()
	database := filepath.Join(t.TempDir(), "relay.db")
	first, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	var claims, participants, events int
	if err := second.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM telegram_claims").Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if err := second.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM telegram_participants").Scan(&participants); err != nil {
		t.Fatal(err)
	}
	if err := second.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM telegram_claim_events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if claims != 0 || participants != 0 || events != 0 {
		t.Fatalf("reopen mutated claim tables claims=%d participants=%d events=%d", claims, participants, events)
	}
}

func TestStorePrepareTelegramAdoptDropsSharedRoleFromUnnamedNonKeeper(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 18, 0, 0, 0, time.UTC)
	keeper, nonKeeper := createSharedTelegramRolePair(t, store, now)

	if _, _, err := store.AppendMessage(AppendInput{
		ConversationID:  nonKeeper.ID,
		SenderMachineID: "machine-telegram",
		FromEndpoint:    TelegramPrimaryEndpoint,
		Body:            "pending for the shared role",
		IdempotencyKey:  "role-delivery",
		Now:             now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{
		ConversationID:  keeper.ID,
		SenderMachineID: "machine-telegram",
		FromEndpoint:    TelegramPrimaryEndpoint,
		Body:            "pending on the keeper",
		IdempotencyKey:  "keeper-role-delivery",
		Now:             now,
	}); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM deliveries
		WHERE recipient_endpoint=? AND acked_at IS NULL
		  AND message_id IN (SELECT id FROM messages WHERE conversation_id=?)`, roleRecipient(TelegramCodexRole), nonKeeper.ID).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("leftover role delivery pending=%d err=%v", pending, err)
	}

	if err := store.PrepareTelegramAdopt(AdoptPrepareInput{
		KeeperID: keeper.ID, NonKeeperID: nonKeeper.ID, NonKeeperName: "Non-keeper topic", Now: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	rooms, err := roleConversationIDs(store, TelegramCodexRole)
	if err != nil {
		t.Fatal(err)
	}
	if len(rooms) != 1 || rooms[0] != keeper.ID {
		t.Fatalf("role occupancy after prepare=%#v keeper=%s", rooms, keeper.ID)
	}
	prepared, err := conversationByIDViaStore(store, nonKeeper.ID)
	if err != nil || prepared.DisplayName != "Non-keeper topic" {
		t.Fatalf("non-keeper after prepare=%#v err=%v", prepared, err)
	}
	var unacked int
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM deliveries
		WHERE recipient_endpoint=? AND acked_at IS NULL
		  AND message_id IN (SELECT id FROM messages WHERE conversation_id=?)`, roleRecipient(TelegramCodexRole), nonKeeper.ID).Scan(&unacked); err != nil || unacked != 0 {
		t.Fatalf("leftover role deliveries still unacked count=%d err=%v", unacked, err)
	}
	var keeperUnacked int
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM deliveries
		WHERE recipient_endpoint=? AND acked_at IS NULL
		  AND message_id IN (SELECT id FROM messages WHERE conversation_id=?)`, roleRecipient(TelegramCodexRole), keeper.ID).Scan(&keeperUnacked); err != nil || keeperUnacked != 1 {
		t.Fatalf("keeper role delivery unacked=%d err=%v", keeperUnacked, err)
	}
	var cursor, nextSequence int64
	if err := store.db.QueryRowContext(context.Background(), "SELECT sequence FROM recipient_cursors WHERE recipient_endpoint=? AND conversation_id=?", roleRecipient(TelegramCodexRole), nonKeeper.ID).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(context.Background(), "SELECT next_sequence FROM conversations WHERE id=?", nonKeeper.ID).Scan(&nextSequence); err != nil {
		t.Fatal(err)
	}
	if cursor != nextSequence {
		t.Fatalf("non-keeper role cursor=%d next_sequence=%d", cursor, nextSequence)
	}
	var capabilities Capability
	if err := store.db.QueryRowContext(context.Background(), "SELECT capabilities FROM memberships WHERE conversation_id=? AND endpoint=?", nonKeeper.ID, TelegramPrimaryEndpoint).Scan(&capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities != CapSend|CapReceive {
		t.Fatalf("telegram/primary capabilities=%d, want send|receive only", capabilities)
	}
}

func TestStorePrepareTelegramAdoptRejectsExtraOccupant(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 16, 18, 0, 0, 0, time.UTC)
	keeper, nonKeeper := createSharedTelegramRolePair(t, store, now)
	if err := store.AdvertiseEndpoints("machine-extra", []string{"agent/extra"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), "INSERT INTO memberships(conversation_id, endpoint, capabilities) VALUES (?, ?, ?)", nonKeeper.ID, "agent/extra", CapReceive); err != nil {
		t.Fatal(err)
	}
	if err := store.PrepareTelegramAdopt(AdoptPrepareInput{
		KeeperID: keeper.ID, NonKeeperID: nonKeeper.ID, NonKeeperName: "Non-keeper topic", Now: now,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("extra occupant err=%v", err)
	}
	rooms, err := roleConversationIDs(store, TelegramCodexRole)
	if err != nil {
		t.Fatal(err)
	}
	if len(rooms) != 2 {
		t.Fatalf("failed prepare mutated role occupancy=%#v", rooms)
	}
	assertNonKeeperUnnamed(t, store, nonKeeper.ID)
}

func TestStorePrepareTelegramAdoptRejectsUnsafeState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 16, 18, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		setup     func(*testing.T, *Store, Conversation, Conversation)
		wantErr   error
		wantErrIn string
	}{
		{
			name: "keeper unnamed",
			setup: func(t *testing.T, store *Store, keeper, _ Conversation) {
				t.Helper()
				if _, err := store.db.ExecContext(context.Background(), "UPDATE conversations SET display_name=NULL WHERE id=?", keeper.ID); err != nil {
					t.Fatal(err)
				}
			},
			wantErrIn: "keeper conversation is unnamed",
		},
		{
			name: "non-keeper already named",
			setup: func(t *testing.T, store *Store, _, nonKeeper Conversation) {
				t.Helper()
				if _, err := store.db.ExecContext(context.Background(), "UPDATE conversations SET display_name=? WHERE id=?", "Already named", nonKeeper.ID); err != nil {
					t.Fatal(err)
				}
			},
			wantErrIn: "non-keeper conversation is already named",
		},
		{
			name: "role gone",
			setup: func(t *testing.T, store *Store, _, nonKeeper Conversation) {
				t.Helper()
				if _, err := store.db.ExecContext(context.Background(), "DELETE FROM role_memberships WHERE conversation_id=? AND role=?", nonKeeper.ID, TelegramCodexRole); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrConflict,
		},
		{
			name: "no telegram/primary",
			setup: func(t *testing.T, store *Store, _, nonKeeper Conversation) {
				t.Helper()
				if _, err := store.db.ExecContext(context.Background(), "DELETE FROM memberships WHERE conversation_id=? AND endpoint=?", nonKeeper.ID, TelegramPrimaryEndpoint); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrConflict,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			keeper, nonKeeper := createSharedTelegramRolePair(t, store, now)
			test.setup(t, store, keeper, nonKeeper)
			err = store.PrepareTelegramAdopt(AdoptPrepareInput{
				KeeperID: keeper.ID, NonKeeperID: nonKeeper.ID, NonKeeperName: "Non-keeper topic", Now: now,
			})
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("err=%v want %v", err, test.wantErr)
			}
			if test.wantErrIn != "" && (err == nil || !strings.Contains(err.Error(), test.wantErrIn)) {
				t.Fatalf("err=%v want %q", err, test.wantErrIn)
			}
			assertPrepareDidNotNameNonKeeper(t, store, nonKeeper.ID, test.name == "non-keeper already named")
			if test.name != "role gone" {
				assertRoleOnBothRooms(t, store, keeper.ID, nonKeeper.ID)
			} else {
				rooms, err := roleConversationIDs(store, TelegramCodexRole)
				if err != nil {
					t.Fatal(err)
				}
				if len(rooms) != 1 || rooms[0] != keeper.ID {
					t.Fatalf("role occupancy after rejected prepare=%#v", rooms)
				}
			}
		})
	}
}

func createSharedTelegramRolePair(t *testing.T, store *Store, now time.Time) (Conversation, Conversation) {
	t.Helper()
	for machine, endpoint := range map[string]string{
		"machine-creator":   "agent/creator",
		"machine-telegram":  TelegramPrimaryEndpoint,
		"studio-validation": "agent/punaro-studio/validation",
	} {
		if err := store.AdvertiseEndpoints(machine, []string{endpoint}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	members := []Member{
		{Endpoint: "agent/creator", Capabilities: CapSend | CapReceive | CapAdmin},
		{Role: TelegramCodexRole, RoleMachineID: "studio-validation", Capabilities: CapSend | CapReceive | CapAdmin},
	}
	keeper, err := store.CreateConversation("agent/creator", members, now)
	if err != nil || keeper.DisplayName != "" {
		t.Fatalf("keeper unnamed=%#v err=%v", keeper, err)
	}
	nonKeeper, err := store.CreateConversation("agent/creator", members, now)
	if err != nil || nonKeeper.DisplayName != "" || nonKeeper.ID == keeper.ID {
		t.Fatalf("non-keeper unnamed=%#v keeper=%#v err=%v", nonKeeper, keeper, err)
	}
	for _, id := range []string{keeper.ID, nonKeeper.ID} {
		if _, err := store.db.ExecContext(context.Background(), "INSERT INTO memberships(conversation_id, endpoint, capabilities) VALUES (?, ?, ?)", id, TelegramPrimaryEndpoint, CapSend|CapReceive); err != nil {
			t.Fatal(err)
		}
	}
	for i, id := range []string{keeper.ID, nonKeeper.ID} {
		if _, _, err := store.ApplyControl(ControlInput{
			ConversationID: id, ActorMachineID: "machine-creator", ActorEndpoint: "agent/creator",
			Operation: ControlRemoveMember, Member: Member{Endpoint: "agent/creator"},
			IdempotencyKey: fmt.Sprintf("remove-creator-%d", i), Now: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.BindRoleToSession("studio-validation", TelegramCodexRole, "agent/punaro-studio/validation", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	renamed, _, err := store.SetConversationDisplayName(SetDisplayNameInput{
		ConversationID: keeper.ID, ActorMachineID: "studio-validation", ActorEndpoint: "agent/punaro-studio/validation",
		DisplayName: "Keeper topic", IdempotencyKey: "rename-keeper", Now: now,
	})
	if err != nil || renamed.DisplayName != "Keeper topic" {
		t.Fatalf("rename keeper=%#v err=%v", renamed, err)
	}
	return keeper, nonKeeper
}

func roleConversationIDs(store *Store, role string) ([]string, error) {
	rows, err := store.db.QueryContext(context.Background(), "SELECT conversation_id FROM role_memberships WHERE role=? ORDER BY conversation_id", role)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var rooms []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		rooms = append(rooms, id)
	}
	return rooms, rows.Err()
}

func conversationByIDViaStore(store *Store, conversationID string) (Conversation, error) {
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		return Conversation{}, err
	}
	defer rollback(tx)
	conversation, err := conversationByID(tx, conversationID)
	if err != nil {
		return Conversation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Conversation{}, err
	}
	return conversation, nil
}

func assertNonKeeperUnnamed(t *testing.T, store *Store, conversationID string) {
	t.Helper()
	assertPrepareDidNotNameNonKeeper(t, store, conversationID, false)
}

func assertPrepareDidNotNameNonKeeper(t *testing.T, store *Store, conversationID string, alreadyNamed bool) {
	t.Helper()
	got, err := conversationByIDViaStore(store, conversationID)
	if err != nil {
		t.Fatal(err)
	}
	if alreadyNamed {
		if got.DisplayName == "" || got.DisplayName == "Non-keeper topic" {
			t.Fatalf("rejected prepare changed already-named non-keeper=%#v", got)
		}
		return
	}
	if got.DisplayName != "" {
		t.Fatalf("rejected prepare named non-keeper=%#v", got)
	}
}

func assertRoleOnBothRooms(t *testing.T, store *Store, keeperID, nonKeeperID string) {
	t.Helper()
	rooms, err := roleConversationIDs(store, TelegramCodexRole)
	if err != nil {
		t.Fatal(err)
	}
	if len(rooms) != 2 || !containsString(rooms, keeperID) || !containsString(rooms, nonKeeperID) {
		t.Fatalf("role occupancy after rejected prepare=%#v", rooms)
	}
}
