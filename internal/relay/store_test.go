package relay

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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
		{Endpoint: "agent/b", Capabilities: CapReceive},
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
	if _, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-b", ActorEndpoint: "agent/b", Operation: ControlRemoveMember, Member: Member{Endpoint: "agent/c"}, IdempotencyKey: "control-2", Now: now}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin control err=%v, want forbidden", err)
	}
	if _, _, err := store.ApplyControl(ControlInput{ConversationID: conversation.ID, ActorMachineID: "machine-a", ActorEndpoint: "agent/a", Operation: ControlRemoveMember, Member: Member{Endpoint: "agent/a"}, IdempotencyKey: "control-3", Now: now}); !errors.Is(err, ErrConflict) {
		t.Fatalf("last-admin removal err=%v, want conflict", err)
	}
	events, err := store.ControlAudit(conversation.ID, "machine-a", "agent/a", now)
	if err != nil || len(events) != 1 || events[0].Member.Endpoint != "agent/c" || events[0].Member.Capabilities != CapReceive {
		t.Fatalf("audit=%#v err=%v", events, err)
	}
	var messages int
	if err := store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM messages").Scan(&messages); err != nil || messages != 0 {
		t.Fatalf("control entered message plane: messages=%d err=%v", messages, err)
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
