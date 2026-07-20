// Package contracttest contains the storage-independent durable mail contract.
// It is imported only by SQLite and PostgreSQL tests.
package contracttest

import (
	"errors"
	"fmt"
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
	deliveries, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, now, time.Minute, 10)
	if err != nil || len(deliveries) != 2 {
		t.Fatalf("deliveries=%#v err=%v", deliveries, err)
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
	thirdLease, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, now, time.Minute, 10)
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
	reclaimed, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, reclaimAt, time.Minute, 10)
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
	afterSelfLease, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, reclaimAt, time.Minute, 10)
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
	abaLease, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, reclaimAt, time.Minute, 100)
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
	releasedAfterABA, err := backend.LeaseDeliveries(machineB, consumerB, endpointB, conversation.ID, reclaimAt.Add(2*time.Second), time.Minute, 100)
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
}
