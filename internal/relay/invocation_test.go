package relay

import (
	"context"
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
	coalescedRequest := request
	coalescedRequest.IdempotencyKey = "invoke-another-caller"
	coalesced, duplicate, err := store.RequestInvocation(coalescedRequest)
	if err != nil || !duplicate || coalesced != invocation {
		t.Fatalf("coalesced=%#v duplicate=%t err=%v", coalesced, duplicate, err)
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
	// A runtime may have durably accepted this start before its adapter crashes
	// and the lease expires. Keep its endpoint reserved through the recovery
	// window so another machine cannot mint a second process-start fence.
	if err := store.AdvertiseEndpoints("replacement-machine", []string{"agent/recipient"}, now.Add(3*time.Second), time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement claimed expired pending handoff: %v", err)
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
	afterAccept := request
	afterAccept.IdempotencyKey = "invoke-after-accept"
	afterAccept.Now = retryAt
	if coalesced, duplicate, err := store.RequestInvocation(afterAccept); err != nil || !duplicate || coalesced.ID != invocation.ID || coalesced.Fence != invocation.Fence || coalesced.Status != InvocationSucceeded {
		t.Fatalf("accepted coalescing invocation=%#v duplicate=%t err=%v", coalesced, duplicate, err)
	}
	// A successful local start is still fenced until the role can reattach, so
	// another machine cannot overtake it in the handoff gap.
	if err := store.AdvertiseEndpoints("replacement-machine", []string{"agent/recipient"}, retryAt.Add(time.Second), time.Hour); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement attached during accepted handoff: %v", err)
	}
	if err := store.AdvertiseEndpoints("replacement-machine", []string{"agent/recipient"}, retryAt.Add(maxInvocationBackoff+time.Second), time.Hour); err != nil {
		t.Fatalf("replacement did not attach after bounded handoff: %v", err)
	}
	if final, err := store.LeaseInvocations("recipient-machine", "adapter-a", retryAt.Add(time.Hour), time.Second, 10); err != nil || len(final) != 0 {
		t.Fatalf("final=%#v err=%v", final, err)
	}
	audit, err := store.InvocationAudit(invocation.ID)
	if err != nil || len(audit) != 7 || audit[0].Action != "requested" || audit[1].Action != "coalesced" || audit[2].Action != "leased" || audit[3].Action != "retry" || audit[4].Action != "leased" || audit[5].Action != "accepted" || audit[6].Action != "coalesced" {
		t.Fatalf("audit=%#v err=%v", audit, err)
	}
}

func TestEmptyInvocationLeaseDoesNotMaterializeControlState(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if leased, err := store.LeaseInvocations("machine-a", "adapter-a", time.Now().UTC(), time.Minute, 1); err != nil || len(leased) != 0 {
		t.Fatalf("leased=%#v err=%v", leased, err)
	}
	if err := store.ReportInvocation("machine-a", "fabricated", "token", 1, true, time.Now().UTC()); !errors.Is(err, ErrForbidden) {
		t.Fatalf("fabricated outcome err=%v", err)
	}
	if audit, err := store.InvocationAudit("unknown"); err != nil || len(audit) != 0 {
		t.Fatalf("empty audit=%#v err=%v", audit, err)
	}
	var exists bool
	if err := store.db.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='invocations')`).Scan(&exists); err != nil || exists {
		t.Fatalf("invocation state exists=%t err=%v", exists, err)
	}
}

func TestInvokeCrashLeasesAreBounded(t *testing.T) {
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
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < maxInvocationAttempts; attempt++ {
		leased, err := store.LeaseInvocations("recipient-machine", "adapter", now.Add(time.Duration(2+attempt*2)*time.Second), time.Second, 10)
		if err != nil || len(leased) != 1 || leased[0].Fence != invocation.Fence {
			t.Fatalf("attempt=%d leased=%#v err=%v", attempt, leased, err)
		}
	}
	recovery, err := store.LeaseInvocations("recipient-machine", "adapter", now.Add(8*time.Second), time.Second, 10)
	if err != nil || len(recovery) != 1 || recovery[0].Fence != invocation.Fence || !recovery[0].RecoveryOnly {
		t.Fatalf("recovery=%#v err=%v", recovery, err)
	}
	replay, err := store.LeaseInvocations("recipient-machine", "adapter", now.Add(8500*time.Millisecond), time.Second, 10)
	if err != nil || len(replay) != 1 || !replay[0].RecoveryOnly {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	if err := store.ReportInvocation("recipient-machine", replay[0].ID, replay[0].LeaseToken, replay[0].LeaseGeneration, false, now.Add(8500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if leased, err := store.LeaseInvocations("recipient-machine", "adapter", now.Add(9*time.Second), time.Second, 10); err != nil || len(leased) != 0 {
		t.Fatalf("terminal leased=%#v err=%v", leased, err)
	}
	audit, err := store.InvocationAudit(invocation.ID)
	if err != nil || len(audit) != 6 || audit[5].Action != "failed" {
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

func TestInvokePrunesTerminalIdempotencyAndAuditAfterRetention(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a", "agent/b"}, now, 2*invocationTerminalRetention); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{MachineID: "machine-a", IdempotencyKey: "create", CreatorEndpoint: "agent/a", Now: now, Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin | CapInvoke}, {Endpoint: "agent/b", Capabilities: CapReceive}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "opaque work", IdempotencyKey: "message", Now: now}); err != nil {
		t.Fatal(err)
	}
	request := InvokeInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", TargetEndpoint: "agent/b", IdempotencyKey: "invoke", Now: now}
	first, duplicate, err := store.RequestInvocation(request)
	if err != nil || duplicate || first.Status != InvocationAlreadyRunning {
		t.Fatalf("first=%#v duplicate=%t err=%v", first, duplicate, err)
	}
	request.Now = now.Add(invocationTerminalRetention - time.Millisecond)
	if repeated, duplicate, err := store.RequestInvocation(request); err != nil || !duplicate || repeated.ID != first.ID {
		t.Fatalf("retained retry=%#v duplicate=%t err=%v", repeated, duplicate, err)
	}
	request.Now = now.Add(invocationTerminalRetention + time.Millisecond)
	second, duplicate, err := store.RequestInvocation(request)
	if err != nil || duplicate || second.ID == first.ID || second.Status != InvocationAlreadyRunning {
		t.Fatalf("pruned retry=%#v duplicate=%t err=%v", second, duplicate, err)
	}
	var invocations, idempotency, audit int
	if err := store.db.QueryRowContext(context.Background(), `SELECT (SELECT count(*) FROM invocations), (SELECT count(*) FROM invocation_idempotency), (SELECT count(*) FROM invocation_audit)`).Scan(&invocations, &idempotency, &audit); err != nil || invocations != 1 || idempotency != 1 || audit != 1 {
		t.Fatalf("invocations=%d idempotency=%d audit=%d err=%v", invocations, idempotency, audit, err)
	}
}

func TestInvokeRetentionPreservesAnAcceptedAttachmentFence(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("sender-machine", []string{"agent/sender"}, now, 3*invocationTerminalRetention); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("recipient-machine", []string{"agent/recipient"}, now, 3*invocationTerminalRetention); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{MachineID: "sender-machine", IdempotencyKey: "create", CreatorEndpoint: "agent/sender", Now: now, Members: []Member{{Endpoint: "agent/sender", Capabilities: CapSend | CapReceive | CapAdmin | CapInvoke}, {Endpoint: "agent/recipient", Capabilities: CapReceive}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", Body: "opaque work", IdempotencyKey: "message", Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("recipient-machine", nil, now.Add(time.Second), 3*invocationTerminalRetention); err != nil {
		t.Fatal(err)
	}
	request := InvokeInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", TargetEndpoint: "agent/recipient", IdempotencyKey: "invoke", Now: now.Add(2 * time.Second)}
	invocation, _, err := store.RequestInvocation(request)
	if err != nil || invocation.Status != InvocationPending {
		t.Fatalf("invocation=%#v err=%v", invocation, err)
	}
	acceptedAt := now.Add(invocationTerminalRetention + 3*time.Second)
	leased, err := store.LeaseInvocations("recipient-machine", "adapter", acceptedAt, time.Minute, 1)
	if err != nil || len(leased) != 1 {
		t.Fatalf("leased=%#v err=%v", leased, err)
	}
	if err := store.ReportInvocation("recipient-machine", leased[0].ID, leased[0].LeaseToken, leased[0].LeaseGeneration, true, acceptedAt); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = "invoke-after-accept"
	request.Now = acceptedAt.Add(time.Second)
	if coalesced, duplicate, err := store.RequestInvocation(request); err != nil || !duplicate || coalesced.ID != invocation.ID || coalesced.Status != InvocationSucceeded {
		t.Fatalf("coalesced=%#v duplicate=%t err=%v", coalesced, duplicate, err)
	}
	var remaining int
	if err := store.db.QueryRowContext(context.Background(), `SELECT count(*) FROM invocations WHERE id=?`, invocation.ID).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("accepted fence rows=%d err=%v", remaining, err)
	}
	request.IdempotencyKey = "invoke-after-retention"
	request.Now = acceptedAt.Add(invocationTerminalRetention + time.Millisecond)
	if replacement, duplicate, err := store.RequestInvocation(request); err != nil || duplicate || replacement.ID == invocation.ID || replacement.Status != InvocationPending {
		t.Fatalf("expired terminal=%#v duplicate=%t err=%v", replacement, duplicate, err)
	}
}

func TestInvokeExpiresAbandonedPendingHandoffBeforeCreatingFreshFence(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("sender-machine", []string{"agent/sender"}, now, 2*invocationPendingRetention); err != nil {
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
	request := InvokeInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", TargetEndpoint: "agent/recipient", IdempotencyKey: "invoke", Now: now.Add(2 * time.Second)}
	abandoned, duplicate, err := store.RequestInvocation(request)
	if err != nil || duplicate || abandoned.Status != InvocationPending {
		t.Fatalf("abandoned=%#v duplicate=%t err=%v", abandoned, duplicate, err)
	}
	request.IdempotencyKey = "invoke-fresh"
	request.Now = now.Add(invocationPendingRetention + 3*time.Second)
	fresh, duplicate, err := store.RequestInvocation(request)
	if err != nil || duplicate || fresh.ID == abandoned.ID || fresh.Status != InvocationPending {
		t.Fatalf("fresh=%#v duplicate=%t err=%v", fresh, duplicate, err)
	}
	audit, err := store.InvocationAudit(abandoned.ID)
	if err != nil || len(audit) != 2 || audit[1].Action != "failed" {
		t.Fatalf("audit=%#v err=%v", audit, err)
	}
}

func TestInvokeDoesNotExpireAbandonedHandoffWithLiveLease(t *testing.T) {
	t.Parallel()
	store, err := Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("sender-machine", []string{"agent/sender"}, now, 2*invocationPendingRetention); err != nil {
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
	request := InvokeInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", TargetEndpoint: "agent/recipient", IdempotencyKey: "invoke", Now: now.Add(2 * time.Second)}
	invocation, _, err := store.RequestInvocation(request)
	if err != nil || invocation.Status != InvocationPending {
		t.Fatalf("invocation=%#v err=%v", invocation, err)
	}
	leasedAt := now.Add(invocationPendingRetention + 3*time.Second)
	leased, err := store.LeaseInvocations("recipient-machine", "adapter", leasedAt, time.Minute, 1)
	if err != nil || len(leased) != 1 || leased[0].ID != invocation.ID {
		t.Fatalf("leased=%#v err=%v", leased, err)
	}
	request.IdempotencyKey = "invoke-during-lease"
	request.Now = leasedAt.Add(time.Minute + time.Second)
	if coalesced, duplicate, err := store.RequestInvocation(request); err != nil || !duplicate || coalesced.ID != invocation.ID || coalesced.Status != InvocationPending {
		t.Fatalf("coalesced=%#v duplicate=%t err=%v", coalesced, duplicate, err)
	}
	if leased, err := store.LeaseInvocations("recipient-machine", "adapter", leasedAt.Add(invocationPendingRetention+time.Second), time.Minute, 1); err != nil || len(leased) != 0 {
		t.Fatalf("abandoned leased invocation=%#v err=%v", leased, err)
	}
	var status InvocationStatus
	if err := store.db.QueryRowContext(context.Background(), `SELECT status FROM invocations WHERE id=?`, invocation.ID).Scan(&status); err != nil || status != InvocationFailed {
		t.Fatalf("status=%q err=%v", status, err)
	}
}

func TestInvokeRepairsPartialOptionalSchema(t *testing.T) {
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
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{MachineID: "machine-a", IdempotencyKey: "create", CreatorEndpoint: "agent/a", Now: now, Members: []Member{{Endpoint: "agent/a", Capabilities: CapSend | CapReceive | CapAdmin | CapInvoke}, {Endpoint: "agent/b", Capabilities: CapReceive}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", Body: "opaque work", IdempotencyKey: "message", Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.ensureInvocationSchema(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `DROP TABLE invocation_idempotency`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(context.Background(), `DROP TABLE invocation_audit`); err != nil {
		t.Fatal(err)
	}
	invocation, duplicate, err := store.RequestInvocation(InvokeInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a", TargetEndpoint: "agent/b", IdempotencyKey: "invoke", Now: now})
	if err != nil || duplicate || invocation.Status != InvocationAlreadyRunning {
		t.Fatalf("invocation=%#v duplicate=%t err=%v", invocation, duplicate, err)
	}
	for _, table := range []string{"invocation_idempotency", "invocation_audit"} {
		var exists bool
		if err := store.db.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("table=%s exists=%t err=%v", table, exists, err)
		}
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

func TestInvokeDoesNotLeaseAcrossTargetOwnershipChange(t *testing.T) {
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
	if err := store.AdvertiseEndpoints("owner-a", []string{"agent/recipient"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversationIdempotent(CreateConversationInput{MachineID: "sender-machine", IdempotencyKey: "create", CreatorEndpoint: "agent/sender", Now: now, Members: []Member{{Endpoint: "agent/sender", Capabilities: CapSend | CapReceive | CapAdmin | CapInvoke}, {Endpoint: "agent/recipient", Capabilities: CapReceive}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", Body: "opaque work", IdempotencyKey: "message", Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("owner-a", nil, now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	invocation, _, err := store.RequestInvocation(InvokeInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", TargetEndpoint: "agent/recipient", IdempotencyKey: "invoke", Now: now.Add(2 * time.Second)})
	if err != nil || invocation.Status != InvocationPending {
		t.Fatalf("invocation=%#v err=%v", invocation, err)
	}
	if err := store.AdvertiseEndpoints("owner-b", []string{"agent/recipient"}, now.Add(3*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("owner-b", nil, now.Add(4*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if leased, err := store.LeaseInvocations("owner-a", "adapter-a", now.Add(5*time.Second), time.Minute, 1); err != nil || len(leased) != 0 {
		t.Fatalf("leased=%#v err=%v", leased, err)
	}
	var status InvocationStatus
	if err := store.db.QueryRowContext(context.Background(), `SELECT status FROM invocations WHERE id=?`, invocation.ID).Scan(&status); err != nil || status != InvocationFailed {
		t.Fatalf("status=%q err=%v", status, err)
	}
}

func TestInvokeCoalescesPendingWorkAcrossConversationsForOneTarget(t *testing.T) {
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
	create := func(key string) Conversation {
		conversation, err := store.CreateConversationIdempotent(CreateConversationInput{MachineID: "sender-machine", IdempotencyKey: key, CreatorEndpoint: "agent/sender", Now: now, Members: []Member{{Endpoint: "agent/sender", Capabilities: CapSend | CapReceive | CapAdmin | CapInvoke}, {Endpoint: "agent/recipient", Capabilities: CapReceive}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.AppendMessage(AppendInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", Body: "opaque work", IdempotencyKey: "message-" + key, Now: now}); err != nil {
			t.Fatal(err)
		}
		return conversation
	}
	conversationA := create("create-a")
	conversationB := create("create-b")
	if err := store.AdvertiseEndpoints("recipient-machine", nil, now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	request := func(conversation Conversation, key string, wantDuplicate bool) Invocation {
		invocation, duplicate, err := store.RequestInvocation(InvokeInput{ConversationID: conversation.ID, SenderMachineID: "sender-machine", FromEndpoint: "agent/sender", TargetEndpoint: "agent/recipient", IdempotencyKey: key, Now: now.Add(2 * time.Second)})
		if err != nil || duplicate != wantDuplicate {
			t.Fatalf("invocation=%#v duplicate=%t err=%v", invocation, duplicate, err)
		}
		return invocation
	}
	invocationA := request(conversationA, "invoke-a", false)
	invocationB := request(conversationB, "invoke-b", true)
	if invocationA.ID == "" || invocationA.Fence == "" || invocationB.ID != "" || invocationB.Fence != "" || invocationB.ConversationID != conversationB.ID || invocationB.TargetEndpoint != "agent/recipient" || invocationB.Status != InvocationPending {
		t.Fatalf("cross-conversation invocation response leaked or did not coalesce: A=%#v B=%#v", invocationA, invocationB)
	}
}
