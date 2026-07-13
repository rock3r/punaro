package relay

import (
	"path/filepath"
	"testing"
	"time"
)

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

	leased, err := store.LeaseDeliveries("machine-b", "agent/b", "", clock, time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
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
	firstLease, err := store.LeaseDeliveries("machine-b", "agent/b", "", clock, time.Minute, 10)
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
	secondLease, err := store.LeaseDeliveries("machine-b", "agent/b", "", clock.Add(time.Minute+time.Second), time.Minute, 10)
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
