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

func TestOrderedDirectRolePairRejectsSelfAndNonCanonical(t *testing.T) {
	t.Parallel()
	low, high, ok := OrderedDirectRolePair("role/machine-b/implementer", "role/machine-a/reviewer")
	if !ok || low != "role/machine-a/reviewer" || high != "role/machine-b/implementer" {
		t.Fatalf("pair=%q %q ok=%t", low, high, ok)
	}
	if _, _, ok := OrderedDirectRolePair("role/machine-a/reviewer", "role/machine-a/reviewer"); ok {
		t.Fatal("self pair was accepted")
	}
	if _, _, ok := OrderedDirectRolePair("role/plan-reviewer", "role/machine-a/reviewer"); ok {
		t.Fatal("legacy pair was accepted")
	}
}

func TestStoreDirectMessageCreatesConversationMessageAndTargetDelivery(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	fromRole, toRole := prepareDirectPair(t, store, now, true)

	message, duplicate, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "please review", IdempotencyKey: "dm-1", Now: now,
	})
	if err != nil || duplicate {
		t.Fatalf("first send=%#v duplicate=%t err=%v", message, duplicate, err)
	}
	if message.ConversationID == "" || message.ID == "" || message.Sequence != 1 || message.FromRole != fromRole || message.FromEndpoint != "" || message.Body != "please review" {
		t.Fatalf("message=%#v", message)
	}
	encoded, err := json.Marshal(message)
	if err != nil || !strings.Contains(string(encoded), `"from_role":"role/machine-a/reviewer"`) || strings.Contains(string(encoded), "from_endpoint") || strings.Contains(string(encoded), "agent/a") {
		t.Fatalf("envelope leaked session identity: %s err=%v", encoded, err)
	}

	targetPage, err := store.LeaseDeliveries("machine-b", "consumer-b", "agent/b", message.ConversationID, now, time.Minute, 10)
	if err != nil || len(targetPage.Deliveries) != 1 {
		t.Fatalf("target page=%#v err=%v", targetPage, err)
	}
	delivery := targetPage.Deliveries[0]
	if delivery.RecipientRole != toRole || delivery.Message.FromRole != fromRole || delivery.Message.FromEndpoint != "" || delivery.Message.ID != message.ID {
		t.Fatalf("target delivery=%#v", delivery)
	}

	senderPage, err := store.LeaseDeliveries("machine-a", "consumer-a", "agent/a", message.ConversationID, now, time.Minute, 10)
	if err != nil || len(senderPage.Deliveries) != 0 {
		t.Fatalf("sender page=%#v err=%v", senderPage, err)
	}
}

func TestStoreDirectMessageSecondDirectionReusesConversation(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	fromRole, toRole := prepareDirectPair(t, store, now, true)

	first, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "please review", IdempotencyKey: "dm-a", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	reply, duplicate, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-b", FromRole: toRole, ToRole: fromRole, Body: "done", IdempotencyKey: "dm-b", Now: now.Add(time.Second),
	})
	if err != nil || duplicate || reply.ConversationID != first.ConversationID || reply.Sequence != 2 || reply.FromRole != toRole {
		t.Fatalf("reply=%#v first=%#v duplicate=%t err=%v", reply, first, duplicate, err)
	}
}

func TestStoreDirectMessageConcurrentFirstSendsConverge(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	fromRole, toRole := prepareDirectPair(t, store, now, true)

	results := make([]Message, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		results[0], _, errs[0] = store.SendDirectMessage(DirectMessageInput{
			SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "from-a", IdempotencyKey: "dm-conc-a", Now: now,
		})
	}()
	go func() {
		defer wg.Done()
		results[1], _, errs[1] = store.SendDirectMessage(DirectMessageInput{
			SenderMachineID: "machine-b", FromRole: toRole, ToRole: fromRole, Body: "from-b", IdempotencyKey: "dm-conc-b", Now: now,
		})
	}()
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("concurrent errs=%v %v", errs[0], errs[1])
	}
	if results[0].ConversationID == "" || results[0].ConversationID != results[1].ConversationID {
		t.Fatalf("conversations diverged a=%#v b=%#v", results[0], results[1])
	}
	if results[0].ID == results[1].ID {
		t.Fatalf("distinct sends shared a message id: %#v", results[0])
	}
}

func TestStoreDirectMessageIdempotencyRetryAndConflict(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	fromRole, toRole := prepareDirectPair(t, store, now, true)
	input := DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "please review", IdempotencyKey: "dm-retry", Now: now,
	}
	first, createdDuplicate, err := store.SendDirectMessage(input)
	if err != nil || createdDuplicate {
		t.Fatalf("first=%#v duplicate=%t err=%v", first, createdDuplicate, err)
	}
	retry, duplicate, err := store.SendDirectMessage(input)
	if err != nil || !duplicate || retry != first {
		t.Fatalf("retry=%#v duplicate=%t err=%v want=%#v", retry, duplicate, err, first)
	}
	targetPage, err := store.LeaseDeliveries("machine-b", "consumer-b-retry", "agent/b", first.ConversationID, now, time.Minute, 10)
	if err != nil || len(targetPage.Deliveries) != 1 || targetPage.Deliveries[0].Message.ID != first.ID {
		t.Fatalf("retry created extra delivery: %#v err=%v", targetPage, err)
	}

	changedBody := input
	changedBody.Body = "other"
	if _, _, err := store.SendDirectMessage(changedBody); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed body err=%v", err)
	}
	changedTarget := input
	changedTarget.ToRole = "role/machine-b/other"
	registerAddressable(t, store, "machine-b", changedTarget.ToRole, "", true, "reg-other", now)
	if _, _, err := store.SendDirectMessage(changedTarget); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed target err=%v", err)
	}
	changedSource := input
	changedSource.FromRole = "role/machine-a/other"
	registerAddressable(t, store, "machine-a", changedSource.FromRole, "", true, "reg-source-other", now)
	if err := store.BindRoleToSession("machine-a", changedSource.FromRole, "agent/a", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SendDirectMessage(changedSource); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed source err=%v", err)
	}
}

func TestStoreDirectMessageRejectsUnauthorizedSourceAndTarget(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	fromRole, toRole := prepareDirectPair(t, store, now, true)

	if _, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: fromRole, Body: "self", IdempotencyKey: "dm-self", Now: now,
	}); err == nil || errors.Is(err, ErrForbidden) || errors.Is(err, ErrConflict) {
		t.Fatalf("self-send err=%v", err)
	}
	if _, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-b", FromRole: fromRole, ToRole: toRole, Body: "stolen", IdempotencyKey: "dm-stolen", Now: now,
	}); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("unowned source err=%v", err)
	}
	unbound := "role/machine-a/unbound"
	registerAddressable(t, store, "machine-a", unbound, "", true, "reg-unbound", now)
	if _, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: unbound, ToRole: toRole, Body: "unbound", IdempotencyKey: "dm-unbound", Now: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unbound source err=%v", err)
	}
	expiredAt := now.Add(2 * time.Hour)
	if _, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "expired", IdempotencyKey: "dm-expired", Now: expiredAt,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired source binding err=%v", err)
	}
	if _, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: "role/machine-b/missing", Body: "missing", IdempotencyKey: "dm-missing", Now: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing target err=%v", err)
	}
	hidden := "role/machine-b/hidden"
	registerAddressable(t, store, "machine-b", hidden, "", false, "reg-hidden", now)
	if _, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: hidden, Body: "hidden", IdempotencyKey: "dm-hidden", Now: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-addressable target err=%v", err)
	}
}

func TestStoreDirectMessageOptOutBeforeCommitCreatesNothing(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	fromRole, toRole := prepareDirectPair(t, store, now, true)
	if _, _, err := store.RegisterRoleProfile(RegisterRoleInput{
		MachineID: "machine-b", Role: toRole, DirectAddressable: false, IdempotencyKey: "opt-out", Now: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "too late", IdempotencyKey: "dm-opt-out", Now: now.Add(2 * time.Second),
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("opt-out send err=%v", err)
	}
	rooms, err := store.ConversationsForMachine("machine-a", now.Add(2*time.Second))
	if err != nil || len(rooms) != 0 {
		t.Fatalf("opt-out created a conversation: %#v err=%v", rooms, err)
	}
}

func TestStoreDirectMessageOfflineTargetReceivesAfterBindAndRebindKeepsIdentity(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	fromRole, toRole := prepareDirectPair(t, store, now, false)

	first, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "offline", IdempotencyKey: "dm-offline", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LeaseDeliveries("machine-b", "consumer-offline", "agent/b", first.ConversationID, now, time.Minute, 10); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unbound target leased a delivery")
	}

	if err := store.BindRoleToSession("machine-b", toRole, "agent/b", now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	page, err := store.LeaseDeliveries("machine-b", "consumer-later", "agent/b", first.ConversationID, now.Add(time.Second), time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 || page.Deliveries[0].Message.ID != first.ID || page.Deliveries[0].RecipientRole != toRole {
		t.Fatalf("offline receive=%#v err=%v", page, err)
	}

	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a/second"}, now.Add(2*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.BindRoleToSession("machine-a", fromRole, "agent/a/second", now.Add(2*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	second, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "after rebind", IdempotencyKey: "dm-rebind", Now: now.Add(2 * time.Second),
	})
	if err != nil || second.ConversationID != first.ConversationID || second.FromRole != fromRole || second.FromEndpoint != "" {
		t.Fatalf("rebind send=%#v first=%#v err=%v", second, first, err)
	}
}

func TestStoreDirectMessageDoesNotDeliverToUnrelatedRolesOrEndpoints(t *testing.T) {
	t.Parallel()
	store := openRoleProfileStore(t)
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	fromRole, toRole := prepareDirectPair(t, store, now, true)
	if err := store.AdvertiseEndpoints("machine-c", []string{"agent/c"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	unrelated := "role/machine-c/spectator"
	registerAddressable(t, store, "machine-c", unrelated, "", true, "reg-c", now)
	if err := store.BindRoleToSession("machine-c", unrelated, "agent/c", now, time.Hour); err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "private", IdempotencyKey: "dm-unrelated", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	unrelatedPage, err := store.LeaseDeliveries("machine-c", "consumer-c", "agent/c", "", now, time.Minute, 10)
	if err != nil || len(unrelatedPage.Deliveries) != 0 {
		t.Fatalf("unrelated page=%#v err=%v", unrelatedPage, err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b", "agent/b/extra"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	extraPage, err := store.LeaseDeliveries("machine-b", "consumer-extra", "agent/b/extra", "", now, time.Minute, 10)
	if err != nil || len(extraPage.Deliveries) != 0 {
		t.Fatalf("unbound extra session page=%#v err=%v", extraPage, err)
	}
}

func TestStoreDirectMessagePersistsAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	fromRole, toRole := prepareDirectPair(t, store, now, true)
	first, _, err := store.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "persist", IdempotencyKey: "dm-persist", Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	retry, duplicate, err := reopened.SendDirectMessage(DirectMessageInput{
		SenderMachineID: "machine-a", FromRole: fromRole, ToRole: toRole, Body: "persist", IdempotencyKey: "dm-persist", Now: now.Add(time.Minute),
	})
	if err != nil || !duplicate || retry.ID != first.ID || retry.ConversationID != first.ConversationID || retry.FromRole != fromRole {
		t.Fatalf("restart retry=%#v duplicate=%t err=%v first=%#v", retry, duplicate, err, first)
	}
}

func prepareDirectPair(t *testing.T, store *Store, now time.Time, bindTarget bool) (string, string) {
	t.Helper()
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	fromRole := "role/machine-a/reviewer"
	toRole := "role/machine-b/implementer"
	registerAddressable(t, store, "machine-a", fromRole, "Reviewer", true, "reg-a", now)
	registerAddressable(t, store, "machine-b", toRole, "Implementer", true, "reg-b", now)
	if err := store.BindRoleToSession("machine-a", fromRole, "agent/a", now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if bindTarget {
		if err := store.BindRoleToSession("machine-b", toRole, "agent/b", now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	return fromRole, toRole
}
