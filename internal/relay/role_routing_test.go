package relay

import (
	"errors"
	"testing"
	"time"
)

func TestRoleAddressedRoutingTargetsOnlyActiveRoleMembersAndPreservesRetry(t *testing.T) {
	t.Parallel()
	store, err := Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/reviewer-1", "agent/reviewer-2", "agent/implementer"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin, Role: "coordinator"},
		{Endpoint: "agent/reviewer-1", Capabilities: CapReceive, Role: "reviewer"},
		{Endpoint: "agent/reviewer-2", Capabilities: CapReceive, Role: "reviewer"},
		{Endpoint: "agent/implementer", Capabilities: CapReceive, Role: "implementer"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	input := AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "review this", TargetRole: "reviewer", IdempotencyKey: "role-send", Now: now}
	message, duplicate, err := store.AppendMessage(input)
	if err != nil || duplicate || message.TargetRole != "reviewer" {
		t.Fatalf("append=%#v duplicate=%t err=%v", message, duplicate, err)
	}
	for _, endpoint := range []string{"agent/reviewer-1", "agent/reviewer-2"} {
		page, err := store.LeaseDeliveries("machine-b", "consumer-"+endpoint, endpoint, conversation.ID, now, time.Minute, 10)
		if err != nil || len(page.Deliveries) != 1 || page.Deliveries[0].Message != message {
			t.Fatalf("role delivery endpoint=%q page=%#v err=%v", endpoint, page, err)
		}
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-implementer", "agent/implementer", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 0 {
		t.Fatalf("non-role recipient page=%#v err=%v", page, err)
	}
	if err := store.UpdateMembership(conversation.ID, "machine-a", "agent/a", "agent/reviewer-1", Member{Endpoint: "agent/reviewer-1", Capabilities: CapReceive, Role: "implementer"}, now); err != nil {
		t.Fatalf("change reviewer role: %v", err)
	}
	repeated, duplicate, err := store.AppendMessage(input)
	if err != nil || !duplicate || repeated != message {
		t.Fatalf("retry after role change=%#v duplicate=%t err=%v", repeated, duplicate, err)
	}
}

func TestRoleLabelsMustBePortable(t *testing.T) {
	for _, role := range []string{"", "reviewer", "release-manager"} {
		if !ValidRole(role) {
			t.Fatalf("expected valid role %q", role)
		}
	}
	for _, role := range []string{" reviewer", "reviewer ", "reviewer\n", string(make([]byte, 65))} {
		if ValidRole(role) {
			t.Fatalf("expected invalid role %q", role)
		}
	}
}

func TestRoleAddressedRoutingFailsWithoutEligibleRecipientAndDoesNotConsumeRetry(t *testing.T) {
	t.Parallel()
	store, err := Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/old-reviewer"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a", []Member{
		{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin, Role: "coordinator"},
		{Endpoint: "agent/old-reviewer", Capabilities: CapReceive, Role: "reviewer"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Second)
	if err := store.AdvertiseEndpoints("machine-b", nil, later, time.Hour); err != nil {
		t.Fatal(err)
	}
	input := AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "review this", TargetRole: "reviewer", IdempotencyKey: "role-send", Now: later}
	if _, _, err := store.AppendMessage(input); !errors.Is(err, ErrNoEligibleRecipient) {
		t.Fatalf("missing recipient err=%v", err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/reviewer"}, later, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateMembership(conversation.ID, "machine-a", "agent/a", "agent/old-reviewer", Member{Endpoint: "agent/reviewer", Capabilities: CapReceive, Role: "reviewer"}, later); err != nil {
		t.Fatal(err)
	}
	message, duplicate, err := store.AppendMessage(input)
	if err != nil || duplicate || message.Sequence != 1 {
		t.Fatalf("retry after rebinding message=%#v duplicate=%t err=%v", message, duplicate, err)
	}
}

func TestMembershipRoleChangesRequireAdminAndSurviveRestart(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/relay.db"
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-admin", []string{"agent/admin"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-member", []string{"agent/old", "agent/new"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/admin", []Member{
		{Endpoint: "agent/admin", Capabilities: CapSend | CapReceive | CapAdmin, Role: "coordinator"},
		{Endpoint: "agent/old", Capabilities: CapReceive, Role: "reviewer"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateMembership(conversation.ID, "machine-admin", "agent/admin", "agent/admin", Member{Endpoint: "agent/admin", Capabilities: CapSend | CapReceive, Role: "coordinator"}, now); !errors.Is(err, ErrForbidden) {
		t.Fatalf("removing the last administrator err=%v", err)
	}
	if _, duplicate, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-admin", FromEndpoint: "agent/admin", Body: "queued for reviewer", TargetRole: "reviewer", IdempotencyKey: "before-rebind", Now: now}); err != nil || duplicate {
		t.Fatalf("queue before rebind duplicate=%t err=%v", duplicate, err)
	}
	if err := store.UpdateMembership(conversation.ID, "machine-member", "agent/old", "", Member{Endpoint: "agent/new", Capabilities: CapReceive, Role: "implementer"}, now); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin role change err=%v", err)
	}
	if err := store.UpdateMembership(conversation.ID, "machine-admin", "agent/admin", "agent/old", Member{Endpoint: "agent/new", Capabilities: CapReceive, Role: "implementer"}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateMembership(conversation.ID, "machine-admin", "agent/admin", "agent/old", Member{Endpoint: "agent/new", Capabilities: CapReceive, Role: "implementer"}, now); err != nil {
		t.Fatalf("replayed rebinding: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-admin", FromEndpoint: "agent/admin", Body: "implement", TargetRole: "implementer", IdempotencyKey: "after-restart", Now: now}); err != nil {
		t.Fatalf("rebound role after restart err=%v", err)
	}
	page, err := store.LeaseDeliveries("machine-member", "rebound-consumer", "agent/new", conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 2 || page.Deliveries[0].Message.Body != "queued for reviewer" || page.Deliveries[1].Message.Body != "implement" {
		t.Fatalf("rebound deliveries=%#v err=%v", page, err)
	}
}
