package relay

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestInvokeQueuesOnlyOfflineAuthorizedRecipientAndFencesRetries(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("sender-machine", []string{"agent/sender"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("recipient-machine", []string{"agent/recipient"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{
		MachineID: "sender-machine", IdempotencyKey: "create", CreatorEndpoint: "agent/sender", Now: now,
		Members: []Member{
			{Endpoint: "agent/sender", Capabilities: CapSend | CapReceive | CapAdmin | CapInvoke},
			{Endpoint: "agent/recipient", Capabilities: CapReceive},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", Body: "opaque work", IdempotencyKey: "message", Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("recipient-machine", nil, now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}

	request := InvokeInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", TargetEndpoint: "agent/recipient", IdempotencyKey: "invoke", Now: now.Add(2 * time.Second)}
	invocation, duplicate, err := store.RequestInvocation(request)
	if err != nil || duplicate || invocation.Status != InvocationPending || invocation.TargetMachineID != "recipient-machine" || invocation.Fence == "" {
		t.Fatalf("invocation=%#v duplicate=%t err=%v", invocation, duplicate, err)
	}
	repeated, duplicate, err := store.RequestInvocation(request)
	if err != nil || !duplicate || repeated != invocation {
		t.Fatalf("repeated=%#v duplicate=%t err=%v", repeated, duplicate, err)
	}
	changed := request
	changed.TargetEndpoint = "agent/sender"
	if _, _, err := store.RequestInvocation(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed idempotency request err=%v", err)
	}

	first, err := store.LeaseInvocations("recipient-machine", "adapter-a", now.Add(2*time.Second), time.Second, 10)
	if err != nil || len(first) != 1 || first[0].Fence != invocation.Fence || first[0].LeaseGeneration != 1 {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	if err := store.ReportInvocation("recipient-machine", first[0].ID, first[0].LeaseToken, first[0].LeaseGeneration, false, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if retry, err := store.LeaseInvocations("recipient-machine", "adapter-a", now.Add(3*time.Second), time.Second, 10); err != nil || len(retry) != 0 {
		t.Fatalf("early retry=%#v err=%v", retry, err)
	}
	retryAt := now.Add(4 * time.Second)
	second, err := store.LeaseInvocations("recipient-machine", "adapter-a", retryAt, time.Second, 10)
	if err != nil || len(second) != 1 || second[0].Fence != invocation.Fence || second[0].LeaseGeneration != 2 {
		t.Fatalf("second=%#v err=%v", second, err)
	}
	if err := store.ReportInvocation("recipient-machine", second[0].ID, second[0].LeaseToken, second[0].LeaseGeneration, true, retryAt); err != nil {
		t.Fatal(err)
	}
	if final, err := store.LeaseInvocations("recipient-machine", "adapter-a", retryAt.Add(time.Hour), time.Second, 10); err != nil || len(final) != 0 {
		t.Fatalf("final=%#v err=%v", final, err)
	}
	audit, err := store.InvocationAudit(invocation.ID)
	if err != nil || len(audit) != 5 || audit[0].Action != "requested" || audit[1].Action != "leased" || audit[2].Action != "retry" || audit[3].Action != "leased" || audit[4].Action != "accepted" {
		t.Fatalf("audit=%#v err=%v", audit, err)
	}
}

func TestInvokeRejectsUnauthorizedAndDoesNotQueueAlreadyRunningTarget(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a", "agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{MachineID: "machine-a", IdempotencyKey: "create", CreatorEndpoint: "agent/a", Now: now, Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin}, {Endpoint: "agent/b", Capabilities: CapReceive}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "opaque work", IdempotencyKey: "message", Now: now}); err != nil {
		t.Fatal(err)
	}
	request := InvokeInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", TargetEndpoint: "agent/b", IdempotencyKey: "invoke", Now: now}
	if _, _, err := store.RequestInvocation(request); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized invoke err=%v", err)
	}
	// Grant invoke in a distinct conversation, then prove that an attached target
	// does not create a second start request.
	conversation, err = store.CreateConversationIdempotent(CreateConversationInput{MachineID: "machine-a", IdempotencyKey: "create-invoke", CreatorEndpoint: "agent/a", Now: now, Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin | CapInvoke}, {Endpoint: "agent/b", Capabilities: CapReceive}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "opaque work", IdempotencyKey: "message-invoke", Now: now}); err != nil {
		t.Fatal(err)
	}
	request.ConversationID = conversation.ID
	request.IdempotencyKey = "invoke-running"
	invocation, duplicate, err := store.RequestInvocation(request)
	if err != nil || duplicate || invocation.Status != InvocationAlreadyRunning {
		t.Fatalf("already running invocation=%#v duplicate=%t err=%v", invocation, duplicate, err)
	}
	if repeated, duplicate, err := store.RequestInvocation(request); err != nil || !duplicate || repeated != invocation {
		t.Fatalf("already-running retry=%#v duplicate=%t err=%v", repeated, duplicate, err)
	}
	if leased, err := store.LeaseInvocations("machine-a", "adapter", now, time.Second, 10); err != nil || len(leased) != 0 {
		t.Fatalf("already-running target leased=%#v err=%v", leased, err)
	}
}

func TestInvokeDoesNotStartTargetThatAttachedAfterRequest(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("sender-machine", []string{"agent/sender"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("recipient-machine", []string{"agent/recipient"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{MachineID: "sender-machine", IdempotencyKey: "create", CreatorEndpoint: "agent/sender", Now: now, Members: []Member{{Endpoint: "agent/sender", Capabilities: CapSend | CapReceive | CapAdmin | CapInvoke}, {Endpoint: "agent/recipient", Capabilities: CapReceive}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", Body: "opaque work", IdempotencyKey: "message", Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("recipient-machine", nil, now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	invocation, _, err := store.RequestInvocation(InvokeInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", TargetEndpoint: "agent/recipient", IdempotencyKey: "invoke", Now: now.Add(2 * time.Second)})
	if err != nil || invocation.Status != InvocationPending {
		t.Fatalf("invocation=%#v err=%v", invocation, err)
	}
	if err := store.AdvertiseEndpoints("recipient-machine", []string{"agent/recipient"}, now.Add(3*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if leased, err := store.LeaseInvocations("recipient-machine", "adapter", now.Add(3*time.Second), time.Minute, 10); err != nil || len(leased) != 0 {
		t.Fatalf("leased=%#v err=%v", leased, err)
	}
	audit, err := store.InvocationAudit(invocation.ID)
	if err != nil || len(audit) != 2 || audit[1].Action != "already_running" {
		t.Fatalf("audit=%#v err=%v", audit, err)
	}
}
