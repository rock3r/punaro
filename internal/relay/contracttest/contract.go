// Package contracttest contains the storage-independent durable mail contract.
// It is imported only by SQLite and PostgreSQL tests.
package contracttest

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

// Run exercises the same authorization, idempotency, delivery, lease, and
// cursor contract against one otherwise-empty backend namespace.
func Run(t *testing.T, backend relay.Backend, namespace string) {
	t.Helper()
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	machineA, machineB := namespace+"-machine-a", namespace+"-machine-b"
	consumerB := namespace + "-consumer-b"
	endpointA, endpointB := "agent/"+namespace+"/a", "agent/"+namespace+"/b"
	if err := backend.AdvertiseEndpoints(machineA, []string{endpointA}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := backend.AdvertiseEndpoints(machineB, []string{endpointB}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	members := []relay.Member{
		{Endpoint: endpointA, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
		{Endpoint: endpointB, Capabilities: relay.CapSend | relay.CapReceive},
	}
	create := relay.CreateConversationInput{MachineID: machineA, IdempotencyKey: namespace + "-create", CreatorEndpoint: endpointA, Members: members, Now: now}
	conversation, err := backend.CreateConversationIdempotent(create)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := backend.CreateConversationIdempotent(create)
	if err != nil || repeated != conversation {
		t.Fatalf("repeated conversation=%#v err=%v", repeated, err)
	}
	changedCreate := create
	changedCreate.Members = append([]relay.Member(nil), members...)
	changedCreate.Members[1].Capabilities |= relay.CapAdmin
	if _, err := backend.CreateConversationIdempotent(changedCreate); !errors.Is(err, relay.ErrConflict) {
		t.Fatalf("changed conversation retry err=%v", err)
	}
	listed, err := backend.ConversationsForMachine(machineB, now)
	if err != nil || len(listed) != 1 || listed[0] != conversation {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}

	appendMessage := func(key, body string) relay.Message {
		t.Helper()
		input := relay.AppendInput{ConversationID: conversation.ID, SenderMachineID: machineA, FromEndpoint: endpointA, Body: body, IdempotencyKey: namespace + "-" + key, Now: now}
		message, duplicate, err := backend.AppendMessage(input)
		if err != nil || duplicate {
			t.Fatalf("append message=%#v duplicate=%t err=%v", message, duplicate, err)
		}
		repeated, duplicate, err := backend.AppendMessage(input)
		if err != nil || !duplicate || repeated != message {
			t.Fatalf("repeated message=%#v duplicate=%t err=%v", repeated, duplicate, err)
		}
		changed := input
		changed.Body += " changed"
		if _, _, err := backend.AppendMessage(changed); !errors.Is(err, relay.ErrConflict) {
			t.Fatalf("changed message retry err=%v", err)
		}
		return message
	}
	first := appendMessage("send-1", "first")
	second := appendMessage("send-2", "second")
	if first.Sequence != 1 || second.Sequence != 2 {
		t.Fatalf("message sequences=%d,%d", first.Sequence, second.Sequence)
	}
	recipients, err := backend.RecipientMachines(first.ID, now)
	if err != nil || len(recipients) != 1 || recipients[0] != machineB {
		t.Fatalf("recipient machines=%#v err=%v", recipients, err)
	}
	page, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, now, time.Minute, 10)
	deliveries := page.Deliveries
	if err != nil || len(deliveries) != 2 || page.Cursors[conversation.ID] != 0 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if err := backend.AdvertiseEndpoints(machineB, []string{endpointB}, now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.LeaseDeliveries(machineB, namespace+"-consumer-b-rival", endpointB, conversation.ID, now, time.Minute, 10); !errors.Is(err, relay.ErrConflict) {
		t.Fatalf("concurrent consumer lease err=%v", err)
	}
	if err := backend.AckDelivery(machineA, endpointB, deliveries[0].ID, deliveries[0].LeaseToken, deliveries[0].LeaseGeneration, now); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("wrong-owner ack err=%v", err)
	}
	if err := backend.AckDelivery(machineB, endpointB, deliveries[1].ID, deliveries[1].LeaseToken, deliveries[1].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	if cursor, err := backend.RecipientCursor(machineB, endpointB, conversation.ID, now); err != nil || cursor != 0 {
		t.Fatalf("gapped cursor=%d err=%v", cursor, err)
	}
	if err := backend.AckDelivery(machineB, endpointB, deliveries[0].ID, deliveries[0].LeaseToken, deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	if err := backend.AckDelivery(machineB, endpointB, deliveries[0].ID, deliveries[0].LeaseToken, deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatalf("idempotent ack err=%v", err)
	}
	if cursor, err := backend.RecipientCursor(machineB, endpointB, conversation.ID, now); err != nil || cursor != 2 {
		t.Fatalf("contiguous cursor=%d err=%v", cursor, err)
	}

	third := appendMessage("send-3", "third")
	thirdPage, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, now, time.Minute, 10)
	thirdLease := thirdPage.Deliveries
	if err != nil || len(thirdLease) != 1 || thirdLease[0].Message.ID != third.ID {
		t.Fatalf("third lease=%#v err=%v", thirdLease, err)
	}
	if err := backend.AdvertiseEndpoints(machineB, nil, now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, now.Add(time.Second), time.Minute, 10); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("detached lease err=%v", err)
	}
	reclaimAt := now.Add(2 * time.Minute)
	if err := backend.AdvertiseEndpoints(machineB, []string{endpointB}, reclaimAt, time.Hour); err != nil {
		t.Fatal(err)
	}
	reclaimedPage, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, reclaimAt, time.Minute, 10)
	reclaimed := reclaimedPage.Deliveries
	if err != nil || len(reclaimed) != 1 || reclaimed[0].LeaseGeneration <= thirdLease[0].LeaseGeneration || reclaimed[0].LeaseToken == thirdLease[0].LeaseToken {
		t.Fatalf("reclaimed=%#v original=%#v err=%v", reclaimed, thirdLease, err)
	}
	if err := backend.AckDelivery(machineB, endpointB, thirdLease[0].ID, thirdLease[0].LeaseToken, thirdLease[0].LeaseGeneration, reclaimAt); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("stale ack err=%v", err)
	}
	if err := backend.AckDelivery(machineB, endpointB, reclaimed[0].ID, reclaimed[0].LeaseToken, reclaimed[0].LeaseGeneration, reclaimAt); err != nil {
		t.Fatal(err)
	}
	if cursor, err := backend.RecipientCursor(machineB, endpointB, conversation.ID, reclaimAt); err != nil || cursor != 3 {
		t.Fatalf("recovered cursor=%d err=%v", cursor, err)
	}
	selfInput := relay.AppendInput{
		ConversationID: conversation.ID, SenderMachineID: machineB, FromEndpoint: endpointB,
		Body: "recipient-authored", IdempotencyKey: namespace + "-recipient-send", Now: reclaimAt,
	}
	selfMessage, duplicate, err := backend.AppendMessage(selfInput)
	if err != nil || duplicate || selfMessage.Sequence != 4 {
		t.Fatalf("recipient-authored message=%#v duplicate=%t err=%v", selfMessage, duplicate, err)
	}
	if cursor, err := backend.RecipientCursor(machineB, endpointB, conversation.ID, reclaimAt); err != nil || cursor != 4 {
		t.Fatalf("cursor across trailing self sequence=%d err=%v", cursor, err)
	}
	afterSelf := appendMessage("send-after-self", "after self")
	if afterSelf.Sequence != 5 {
		t.Fatalf("post-self sequence=%d", afterSelf.Sequence)
	}
	afterSelfPage, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, reclaimAt, time.Minute, 10)
	afterSelfLease := afterSelfPage.Deliveries
	if err != nil || len(afterSelfLease) != 1 || afterSelfLease[0].Message.ID != afterSelf.ID {
		t.Fatalf("post-self lease=%#v err=%v", afterSelfLease, err)
	}
	if err := backend.AckDelivery(machineB, endpointB, afterSelfLease[0].ID, afterSelfLease[0].LeaseToken, afterSelfLease[0].LeaseGeneration, reclaimAt); err != nil {
		t.Fatal(err)
	}
	if cursor, err := backend.RecipientCursor(machineB, endpointB, conversation.ID, reclaimAt); err != nil || cursor != 5 {
		t.Fatalf("cursor across non-recipient sequence=%d err=%v", cursor, err)
	}

	const concurrentMessages = 8
	sequences := make(chan int64, concurrentMessages)
	errorsSeen := make(chan error, concurrentMessages)
	var writers sync.WaitGroup
	for index := 0; index < concurrentMessages; index++ {
		writers.Add(1)
		go func(index int) {
			defer writers.Done()
			message, duplicate, err := backend.AppendMessage(relay.AppendInput{
				ConversationID: conversation.ID, SenderMachineID: machineA, FromEndpoint: endpointA,
				Body: fmt.Sprintf("concurrent-%d", index), IdempotencyKey: fmt.Sprintf("%s-concurrent-%d", namespace, index), Now: reclaimAt,
			})
			if err != nil {
				errorsSeen <- err
				return
			}
			if duplicate {
				errorsSeen <- errors.New("concurrent first append reported duplicate")
				return
			}
			sequences <- message.Sequence
		}(index)
	}
	writers.Wait()
	close(sequences)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("concurrent append: %v", err)
	}
	seenSequences := make(map[int64]struct{}, concurrentMessages)
	for sequence := range sequences {
		seenSequences[sequence] = struct{}{}
	}
	for sequence := int64(6); sequence < 6+concurrentMessages; sequence++ {
		if _, found := seenSequences[sequence]; !found {
			t.Fatalf("concurrent sequences=%v, missing %d", seenSequences, sequence)
		}
	}

	abaMessage := appendMessage("aba", "aba")
	abaPage, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, reclaimAt, time.Minute, 100)
	abaLease := abaPage.Deliveries
	if err != nil || len(abaLease) == 0 || abaLease[len(abaLease)-1].Message.ID != abaMessage.ID {
		t.Fatalf("aba lease=%#v err=%v", abaLease, err)
	}
	if err := backend.AdvertiseEndpoints(machineA, []string{endpointA, endpointB}, reclaimAt.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.AppendMessage(selfInput); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("detached exact message retry err=%v", err)
	}
	if err := backend.AdvertiseEndpoints(machineB, []string{endpointB}, reclaimAt.Add(2*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := backend.AckDelivery(machineB, endpointB, abaLease[len(abaLease)-1].ID, abaLease[len(abaLease)-1].LeaseToken, abaLease[len(abaLease)-1].LeaseGeneration, reclaimAt.Add(2*time.Second)); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("ABA-stale acknowledgement err=%v", err)
	}
	releasedAfterABAPage, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, reclaimAt.Add(2*time.Second), time.Minute, 100)
	releasedAfterABA := releasedAfterABAPage.Deliveries
	if err != nil || len(releasedAfterABA) == 0 || releasedAfterABA[len(releasedAfterABA)-1].LeaseGeneration <= abaLease[len(abaLease)-1].LeaseGeneration {
		t.Fatalf("post-ABA lease=%#v err=%v", releasedAfterABA, err)
	}
	if err := backend.AdvertiseEndpoints(machineB, []string{endpointA, endpointB}, reclaimAt.Add(3*time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.CreateConversationIdempotent(create); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("detached exact conversation retry err=%v", err)
	}

	expires := now.Add(5 * time.Minute)
	if err := backend.ConsumeRequestNonce(machineA, namespace+"-nonce", now, expires); err != nil {
		t.Fatal(err)
	}
	if err := backend.ConsumeRequestNonce(machineA, namespace+"-nonce", now, expires); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("replayed nonce err=%v", err)
	}
	runLeasePageContract(t, backend, namespace, now)
	RunRateLimits(t, backend, namespace+"-rate")
}

// RateLimitSetter is implemented by durable stores that keep token-bucket
// policy in process and token state in the database.
type RateLimitSetter interface {
	relay.Backend
	SetRateLimits(relay.RateLimitConfig) error
}

// RunRateLimits proves the same durable sender/conversation token-bucket
// contract against every backend.
func RunRateLimits(t *testing.T, backend relay.Backend, namespace string) {
	t.Helper()
	limiter, ok := backend.(RateLimitSetter)
	if !ok {
		t.Fatal("backend does not expose durable rate limits")
	}
	if err := limiter.SetRateLimits(relay.DefaultRateLimitConfig()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = limiter.SetRateLimits(relay.DefaultRateLimitConfig())
	})
	now := time.Date(2026, time.August, 18, 17, 0, 0, 0, time.UTC)
	cfg := relay.RateLimitConfig{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 8, ConversationRefillPerMinute: 60, RetryAfterMaxSeconds: 60}
	if err := limiter.SetRateLimits(cfg); err != nil {
		t.Fatal(err)
	}
	machineA, machineB, machineC := namespace+"-a", namespace+"-b", namespace+"-c"
	endpointA, endpointA2, endpointB, endpointC := "agent/"+namespace+"/a", "agent/"+namespace+"/a2", "agent/"+namespace+"/b", "agent/"+namespace+"/c"
	if err := backend.AdvertiseEndpoints(machineA, []string{endpointA, endpointA2}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := backend.AdvertiseEndpoints(machineB, []string{endpointB}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := backend.AdvertiseEndpoints(machineC, []string{endpointC}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	first, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: machineA, IdempotencyKey: namespace + "-create-1", CreatorEndpoint: endpointA, Now: now,
		Members: []relay.Member{
			{Endpoint: endpointA, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Endpoint: endpointB, Capabilities: relay.CapReceive},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: machineA, IdempotencyKey: namespace + "-create-2", CreatorEndpoint: endpointA2, Now: now,
		Members: []relay.Member{
			{Endpoint: endpointA2, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Endpoint: endpointC, Capabilities: relay.CapReceive},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.AppendMessage(relay.AppendInput{ConversationID: first.ID, SenderMachineID: machineA, FromEndpoint: endpointA, Body: "one", IdempotencyKey: namespace + "-a-1", Now: now}); err != nil {
		t.Fatal(err)
	}
	_, _, err = backend.AppendMessage(relay.AppendInput{ConversationID: second.ID, SenderMachineID: machineA, FromEndpoint: endpointA2, Body: "two", IdempotencyKey: namespace + "-a-2", Now: now})
	if !errors.Is(err, relay.ErrRateLimited) {
		t.Fatalf("sender exhaustion err=%v", err)
	}
	replay, duplicate, err := backend.AppendMessage(relay.AppendInput{ConversationID: first.ID, SenderMachineID: machineA, FromEndpoint: endpointA, Body: "one", IdempotencyKey: namespace + "-a-1", Now: now})
	if err != nil || !duplicate || replay.Sequence != 1 {
		t.Fatalf("committed retry message=%#v duplicate=%t err=%v", replay, duplicate, err)
	}
	changed := relay.AppendInput{ConversationID: first.ID, SenderMachineID: machineA, FromEndpoint: endpointA, Body: "changed", IdempotencyKey: namespace + "-a-1", Now: now}
	if _, _, err := backend.AppendMessage(changed); !errors.Is(err, relay.ErrConflict) {
		t.Fatalf("changed-body err=%v, want conflict", err)
	}
	if _, _, err := backend.AppendMessage(relay.AppendInput{ConversationID: first.ID, SenderMachineID: machineA, FromEndpoint: endpointA, Body: "later", IdempotencyKey: namespace + "-a-later", Now: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}

	cfg.SenderBurst = 8
	cfg.ConversationBurst = 1
	if err := limiter.SetRateLimits(cfg); err != nil {
		t.Fatal(err)
	}
	shared, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: machineB, IdempotencyKey: namespace + "-create-shared", CreatorEndpoint: endpointB, Now: now.Add(2 * time.Second),
		Members: []relay.Member{
			{Endpoint: endpointB, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Endpoint: endpointC, Capabilities: relay.CapSend | relay.CapReceive},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.AppendMessage(relay.AppendInput{ConversationID: shared.ID, SenderMachineID: machineB, FromEndpoint: endpointB, Body: "b", IdempotencyKey: namespace + "-b-1", Now: now.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	_, _, err = backend.AppendMessage(relay.AppendInput{ConversationID: shared.ID, SenderMachineID: machineC, FromEndpoint: endpointC, Body: "c", IdempotencyKey: namespace + "-c-1", Now: now.Add(2 * time.Second)})
	if !errors.Is(err, relay.ErrRateLimited) {
		t.Fatalf("conversation exhaustion err=%v", err)
	}

	cfg.SenderBurst = 1
	cfg.ConversationBurst = 1
	if err := limiter.SetRateLimits(cfg); err != nil {
		t.Fatal(err)
	}
	concurrent, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: machineB, IdempotencyKey: namespace + "-create-concurrent", CreatorEndpoint: endpointB, Now: now.Add(3 * time.Second),
		Members: []relay.Member{
			{Endpoint: endpointB, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Endpoint: endpointC, Capabilities: relay.CapReceive},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const workers = 6
	var started, running sync.WaitGroup
	started.Add(workers)
	running.Add(workers)
	results := make(chan error, workers)
	for index := 0; index < workers; index++ {
		go func(index int) {
			defer running.Done()
			started.Done()
			started.Wait()
			_, _, err := backend.AppendMessage(relay.AppendInput{
				ConversationID: concurrent.ID, SenderMachineID: machineB, FromEndpoint: endpointB,
				Body: fmt.Sprintf("concurrent-%d", index), IdempotencyKey: fmt.Sprintf("%s-conc-%d", namespace, index),
				Now: now.Add(3 * time.Second),
			})
			results <- err
		}(index)
	}
	running.Wait()
	close(results)
	var accepted, limited int
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, relay.ErrRateLimited):
			limited++
		default:
			t.Fatalf("concurrent append err=%v", err)
		}
	}
	if accepted != 1 || limited != workers-1 {
		t.Fatalf("concurrent accepted=%d limited=%d", accepted, limited)
	}
	if err := limiter.SetRateLimits(relay.DefaultRateLimitConfig()); err != nil {
		t.Fatal(err)
	}
}

// RunRoleTargeting proves the same targeted-role and compatible-broadcast
// routing contract against every durable backend.
func RunRoleTargeting(t *testing.T, backend relay.Backend, namespace string) {
	t.Helper()
	roleBackend, ok := backend.(relay.RoleBindingBackend)
	if !ok {
		t.Fatal("backend does not implement durable role bindings")
	}
	now := time.Date(2026, time.August, 10, 13, 0, 0, 0, time.UTC)
	senderMachine, recipientMachine := namespace+"-sender", namespace+"-recipient"
	senderEndpoint, recipientEndpoint := "agent/"+namespace+"/sender", "agent/"+namespace+"/recipient"
	if err := backend.AdvertiseEndpoints(senderMachine, []string{senderEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := backend.AdvertiseEndpoints(recipientMachine, []string{recipientEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	reviewerRole, implementerRole := "role/"+namespace+"/reviewer", "role/"+namespace+"/implementer"
	conversation, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: senderMachine, CreatorEndpoint: senderEndpoint, IdempotencyKey: namespace + "-create", Now: now,
		Members: []relay.Member{
			{Endpoint: senderEndpoint, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Endpoint: recipientEndpoint, Capabilities: relay.CapReceive},
			{Role: reviewerRole, RoleMachineID: recipientMachine, Capabilities: relay.CapReceive},
			{Role: implementerRole, RoleMachineID: recipientMachine, Capabilities: relay.CapReceive},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{reviewerRole, implementerRole} {
		if err := roleBackend.BindRoleToSession(recipientMachine, role, recipientEndpoint, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	targetedInput := relay.AppendInput{ConversationID: conversation.ID, SenderMachineID: senderMachine, FromEndpoint: senderEndpoint, TargetRole: reviewerRole, Body: "targeted", IdempotencyKey: namespace + "-targeted", Now: now}
	targeted, duplicate, err := backend.AppendMessage(targetedInput)
	if err != nil || duplicate {
		t.Fatalf("targeted message=%#v duplicate=%t err=%v", targeted, duplicate, err)
	}
	machines, err := backend.RecipientMachines(targeted.ID, now)
	if err != nil || len(machines) != 1 || machines[0] != recipientMachine {
		t.Fatalf("targeted recipient machines=%v err=%v", machines, err)
	}
	page, err := backend.LeaseDeliveries(recipientMachine, namespace+"-consumer", recipientEndpoint, conversation.ID, now, time.Minute, 10)
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("targeted page=%#v err=%v", page, err)
	}
	if page.Deliveries[0].RecipientRole != reviewerRole {
		t.Fatalf("targeted recipient role=%q want %q", page.Deliveries[0].RecipientRole, reviewerRole)
	}
	if err := backend.AckDelivery(recipientMachine, recipientEndpoint, page.Deliveries[0].ID, page.Deliveries[0].LeaseToken, page.Deliveries[0].LeaseGeneration, now); err != nil {
		t.Fatal(err)
	}
	if cursor, err := backend.RecipientCursor(recipientMachine, recipientEndpoint, conversation.ID, now); err != nil || cursor != targeted.Sequence {
		t.Fatalf("targeted recipient cursor=%d want=%d err=%v", cursor, targeted.Sequence, err)
	}
	changed := targetedInput
	changed.TargetRole = implementerRole
	if _, _, err := backend.AppendMessage(changed); !errors.Is(err, relay.ErrConflict) {
		t.Fatalf("changed target retry err=%v", err)
	}
	missing := targetedInput
	missing.IdempotencyKey = namespace + "-missing"
	missing.TargetRole = "role/" + namespace + "/missing"
	if _, _, err := backend.AppendMessage(missing); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("missing target role err=%v", err)
	}
	broadcast, duplicate, err := backend.AppendMessage(relay.AppendInput{ConversationID: conversation.ID, SenderMachineID: senderMachine, FromEndpoint: senderEndpoint, Body: "broadcast", IdempotencyKey: namespace + "-broadcast", Now: now})
	if err != nil || duplicate {
		t.Fatalf("broadcast message=%#v duplicate=%t err=%v", broadcast, duplicate, err)
	}
	broadcastPage, err := backend.LeaseDeliveries(recipientMachine, namespace+"-consumer", recipientEndpoint, conversation.ID, now, time.Minute, 10)
	if err != nil || len(broadcastPage.Deliveries) != 3 {
		t.Fatalf("broadcast page=%#v err=%v", broadcastPage, err)
	}
	roles := map[string]int{"": 0, reviewerRole: 0, implementerRole: 0}
	for _, delivery := range broadcastPage.Deliveries {
		roles[delivery.RecipientRole]++
	}
	if roles[""] != 1 || roles[reviewerRole] != 1 || roles[implementerRole] != 1 || len(roles) != 3 {
		t.Fatalf("broadcast recipient roles=%v", roles)
	}
}

// RunRoleProfiles proves opt-in canonical role registration, idempotency,
// ownership, and hidden legacy roles against every durable backend.
func RunRoleProfiles(t *testing.T, backend relay.Backend, namespace string) {
	t.Helper()
	store, ok := backend.(relay.RoleProfileBackend)
	if !ok {
		t.Fatal("backend does not implement durable role profiles")
	}
	now := time.Date(2026, time.August, 18, 16, 0, 0, 0, time.UTC)
	machineA, machineB := namespace+"-a", namespace+"-b"
	role := "role/" + machineA + "/reviewer"
	input := relay.RegisterRoleInput{
		MachineID: machineA, Role: role, DisplayName: "  Reviewer  ", IdempotencyKey: namespace + "-register", Now: now,
	}
	first, created, err := store.RegisterRoleProfile(input)
	if err != nil || !created {
		t.Fatalf("first register=%#v created=%t err=%v", first, created, err)
	}
	if first.Role != role || first.DisplayName != "Reviewer" || first.DirectAddressable || !first.UpdatedAt.Equal(now) {
		t.Fatalf("first profile=%#v", first)
	}
	retry, created, err := store.RegisterRoleProfile(input)
	if err != nil || created || !sameRoleProfile(retry, first) {
		t.Fatalf("retry=%#v created=%t err=%v", retry, created, err)
	}
	changed := input
	changed.DisplayName = "Other"
	if _, _, err := store.RegisterRoleProfile(changed); !errors.Is(err, relay.ErrConflict) {
		t.Fatalf("changed-body retry err=%v", err)
	}
	read, err := store.RoleProfile(role)
	if err != nil || !sameRoleProfile(read, first) {
		t.Fatalf("read=%#v err=%v", read, err)
	}
	for _, invalid := range []relay.RegisterRoleInput{
		{MachineID: machineA, Role: "role/" + machineB + "/reviewer", IdempotencyKey: namespace + "-prefix", Now: now},
		{MachineID: namespace, Role: "role/" + machineA + "/reviewer", IdempotencyKey: namespace + "-overlap", Now: now},
		{MachineID: machineA, Role: "role/plan-reviewer", IdempotencyKey: namespace + "-legacy", Now: now},
		{MachineID: machineA, Role: "role/" + machineA + "/Reviewer", IdempotencyKey: namespace + "-slug", Now: now},
		{MachineID: machineA, Role: "role/" + machineA + "/_bad", IdempotencyKey: namespace + "-invalid", Now: now},
		{MachineID: machineA, Role: role, DisplayName: strings.Repeat("n", 129), IdempotencyKey: namespace + "-display", Now: now},
	} {
		if _, _, err := store.RegisterRoleProfile(invalid); err == nil || errors.Is(err, relay.ErrForbidden) || errors.Is(err, relay.ErrConflict) {
			t.Fatalf("invalid register %q err=%v", invalid.Role, err)
		}
	}
	endpointA, endpointB := "agent/"+namespace+"/a", "agent/"+namespace+"/b"
	if err := backend.AdvertiseEndpoints(machineA, []string{endpointA}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := backend.AdvertiseEndpoints(machineB, []string{endpointB}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	takeoverRole := "role/" + machineA + "/taken"
	if _, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: machineA, CreatorEndpoint: endpointA, IdempotencyKey: namespace + "-takeover-create", Now: now,
		Members: []relay.Member{
			{Endpoint: endpointA, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Role: takeoverRole, RoleMachineID: machineB, Capabilities: relay.CapReceive},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RegisterRoleProfile(relay.RegisterRoleInput{
		MachineID: machineA, Role: takeoverRole, IdempotencyKey: namespace + "-takeover", Now: now,
	}); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("takeover err=%v", err)
	}
	if _, err := store.RoleProfile(takeoverRole); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("unregistered takeover target was visible: %v", err)
	}
	later := now.Add(time.Minute)
	updated, created, err := store.RegisterRoleProfile(relay.RegisterRoleInput{
		MachineID: machineA, Role: role, DisplayName: "Lead Reviewer", DirectAddressable: true, IdempotencyKey: namespace + "-update", Now: later,
	})
	if err != nil || created {
		t.Fatalf("update=%#v created=%t err=%v", updated, created, err)
	}
	if updated.Role != first.Role || updated.DisplayName != "Lead Reviewer" || !updated.DirectAddressable || !updated.UpdatedAt.Equal(later) {
		t.Fatalf("updated=%#v first=%#v", updated, first)
	}
	disabled, _, err := store.RegisterRoleProfile(relay.RegisterRoleInput{
		MachineID: machineA, Role: role, DirectAddressable: false, IdempotencyKey: namespace + "-disable", Now: later.Add(time.Second),
	})
	if err != nil || disabled.DirectAddressable {
		t.Fatalf("disabled=%#v err=%v", disabled, err)
	}
	legacyRole := "role/" + namespace + "-legacy"
	if _, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: machineA, CreatorEndpoint: endpointA, IdempotencyKey: namespace + "-legacy-create", Now: now,
		Members: []relay.Member{
			{Endpoint: endpointA, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Role: legacyRole, RoleMachineID: machineB, Capabilities: relay.CapReceive},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RoleProfile(legacyRole); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("legacy role was visible before registration: %v", err)
	}
	roleBackend, ok := backend.(relay.RoleBindingBackend)
	if !ok {
		t.Fatal("backend does not implement durable role bindings")
	}
	if err := roleBackend.BindRoleToSession(machineB, legacyRole, endpointB, now, time.Hour); err != nil {
		t.Fatalf("legacy role binding: %v", err)
	}
	canonical, created, err := store.RegisterRoleProfile(relay.RegisterRoleInput{
		MachineID: machineB, Role: "role/" + machineB + "/reviewer", DirectAddressable: true, IdempotencyKey: namespace + "-canonical", Now: now,
	})
	if err != nil || !created || canonical.Role != "role/"+machineB+"/reviewer" {
		t.Fatalf("canonical register=%#v created=%t err=%v", canonical, created, err)
	}
	if _, err := store.RoleProfile(legacyRole); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("legacy role was renamed or exposed: %v", err)
	}
	bodyConversation, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: machineA, CreatorEndpoint: endpointA, IdempotencyKey: namespace + "-body-create", Now: now,
		Members: []relay.Member{{Endpoint: endpointA, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin}},
	})
	if err != nil {
		t.Fatal(err)
	}
	invented := "role/" + machineA + "/from-body"
	if _, _, err := backend.AppendMessage(relay.AppendInput{
		ConversationID: bodyConversation.ID, SenderMachineID: machineA, FromEndpoint: endpointA,
		Body: "register " + invented, IdempotencyKey: namespace + "-body", Now: now.Add(2 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RoleProfile(invented); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("message body created a role profile: %v", err)
	}
	preciseNow := now.Add(4 * time.Minute).Add(123456789 * time.Nanosecond)
	preciseRole := "role/" + machineA + "/precise"
	precise, created, err := store.RegisterRoleProfile(relay.RegisterRoleInput{
		MachineID: machineA, Role: preciseRole, DisplayName: "Precise", IdempotencyKey: namespace + "-precise", Now: preciseNow,
	})
	if err != nil || !created || !precise.UpdatedAt.Equal(preciseNow.UTC().Truncate(time.Millisecond)) {
		t.Fatalf("precise register=%#v created=%t err=%v", precise, created, err)
	}
	preciseRetry, created, err := store.RegisterRoleProfile(relay.RegisterRoleInput{
		MachineID: machineA, Role: preciseRole, DisplayName: "Precise", IdempotencyKey: namespace + "-precise", Now: preciseNow.Add(time.Hour),
	})
	if err != nil || created || !sameRoleProfile(preciseRetry, precise) {
		t.Fatalf("precise retry=%#v created=%t err=%v", preciseRetry, created, err)
	}
	concurrentRole := "role/" + machineA + "/concurrent"
	concurrentInput := relay.RegisterRoleInput{
		MachineID: machineA, Role: concurrentRole, DisplayName: "Concurrent", IdempotencyKey: namespace + "-concurrent", Now: now.Add(5 * time.Minute),
	}
	const workers = 8
	profiles := make([]relay.RoleProfile, workers)
	createdFlags := make([]bool, workers)
	errs := make([]error, workers)
	var started, done sync.WaitGroup
	started.Add(workers)
	done.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer done.Done()
			started.Done()
			started.Wait()
			profiles[i], createdFlags[i], errs[i] = store.RegisterRoleProfile(concurrentInput)
		}(i)
	}
	done.Wait()
	var concurrentFirst relay.RoleProfile
	createdCount := 0
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent worker %d err=%v", i, err)
		}
		if createdFlags[i] {
			createdCount++
			concurrentFirst = profiles[i]
		}
	}
	if createdCount != 1 {
		t.Fatalf("concurrent created=%d want 1", createdCount)
	}
	for i, profile := range profiles {
		if !sameRoleProfile(profile, concurrentFirst) {
			t.Fatalf("concurrent worker %d profile=%#v want=%#v", i, profile, concurrentFirst)
		}
	}
}

func sameRoleProfile(got, want relay.RoleProfile) bool {
	return got.Role == want.Role && got.DisplayName == want.DisplayName && got.DirectAddressable == want.DirectAddressable && got.UpdatedAt.Equal(want.UpdatedAt)
}

func runLeasePageContract(t *testing.T, backend relay.Backend, namespace string, now time.Time) {
	t.Helper()
	senderMachine, recipientMachine := namespace+"-page-sender", namespace+"-page-recipient"
	senderEndpoint, recipientEndpoint := "agent/"+namespace+"/page-sender", "agent/"+namespace+"/page-recipient"
	if err := backend.AdvertiseEndpoints(senderMachine, []string{senderEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := backend.AdvertiseEndpoints(recipientMachine, []string{recipientEndpoint}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	members := []relay.Member{
		{Endpoint: senderEndpoint, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
		{Endpoint: recipientEndpoint, Capabilities: relay.CapReceive},
	}
	createConversation := func(key string, members []relay.Member) relay.Conversation {
		t.Helper()
		conversation, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
			MachineID: senderMachine, IdempotencyKey: namespace + "-" + key,
			CreatorEndpoint: senderEndpoint, Members: members, Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return conversation
	}
	firstConversation := createConversation("page-first", members)
	secondConversation := createConversation("page-second", members)
	unauthorizedConversation := createConversation("page-unauthorized", members[:1])
	if _, err := backend.LeaseDeliveries(recipientMachine, namespace+"-failed-consumer", recipientEndpoint, unauthorizedConversation.ID, now, time.Minute, 1); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("unauthorized filtered lease err=%v", err)
	}
	appendMessage := func(conversation relay.Conversation, key string, createdAt time.Time) relay.Message {
		t.Helper()
		message, duplicate, err := backend.AppendMessage(relay.AppendInput{
			ConversationID: conversation.ID, SenderMachineID: senderMachine, FromEndpoint: senderEndpoint,
			Body: key, IdempotencyKey: namespace + "-" + key, Now: createdAt,
		})
		if err != nil || duplicate {
			t.Fatalf("append %s message=%#v duplicate=%t err=%v", key, message, duplicate, err)
		}
		return message
	}
	lexicallyEarlier, lexicallyLater := firstConversation, secondConversation
	if lexicallyEarlier.ID > lexicallyLater.ID {
		lexicallyEarlier, lexicallyLater = lexicallyLater, lexicallyEarlier
	}
	chronologicallyEarlier := appendMessage(lexicallyLater, "page-submillisecond-earlier", now.Add(100*time.Microsecond))
	chronologicallyLater := appendMessage(lexicallyEarlier, "page-submillisecond-later", now.Add(900*time.Microsecond))
	if !chronologicallyEarlier.CreatedAt.Equal(now) || !chronologicallyLater.CreatedAt.Equal(now) {
		t.Fatalf("message timestamps were not normalized to milliseconds: earlier=%s later=%s", chronologicallyEarlier.CreatedAt, chronologicallyLater.CreatedAt)
	}
	expected := []relay.Message{
		chronologicallyEarlier,
		chronologicallyLater,
		appendMessage(firstConversation, "page-first-2", now.Add(-time.Second)),
	}
	sort.Slice(expected, func(left, right int) bool {
		if !expected[left].CreatedAt.Equal(expected[right].CreatedAt) {
			return expected[left].CreatedAt.Before(expected[right].CreatedAt)
		}
		if expected[left].ConversationID != expected[right].ConversationID {
			return expected[left].ConversationID < expected[right].ConversationID
		}
		if expected[left].Sequence != expected[right].Sequence {
			return expected[left].Sequence < expected[right].Sequence
		}
		return expected[left].ID < expected[right].ID
	})
	page, err := backend.LeaseDeliveries(recipientMachine, namespace+"-page-consumer", recipientEndpoint, "", now, time.Minute, 2)
	if err != nil || len(page.Deliveries) != 2 {
		t.Fatalf("ordered lease page=%#v err=%v", page, err)
	}
	for index := range page.Deliveries {
		if page.Deliveries[index].Message.ID != expected[index].ID {
			t.Fatalf("ordered lease page=%#v expected=%#v", page.Deliveries, expected[:2])
		}
		if page.Cursors[page.Deliveries[index].Message.ConversationID] != 0 {
			t.Fatalf("lease page cursors=%#v", page.Cursors)
		}
	}
}
