package contracttest

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

// RunRateLimits exercises durable sender and conversation token buckets against
// one otherwise-empty backend namespace. Each case uses distinct machines so
// durable buckets cannot leak across scenarios.
func RunRateLimits(t *testing.T, backend relay.Backend, namespace string) {
	t.Helper()
	configurer, ok := backend.(relay.RateLimitConfigurer)
	if !ok {
		t.Fatal("relay backend does not persist rate-limit policy")
	}
	t.Cleanup(func() {
		if err := configurer.SetRateLimitPolicy(relay.DefaultRateLimitPolicy()); err != nil {
			t.Errorf("restore default rate-limit policy: %v", err)
		}
	})
	now := time.Date(2026, time.August, 18, 18, 0, 0, 0, time.UTC)
	setup := func(suffix, peerSuffix string) (string, string, string, string, relay.Conversation) {
		t.Helper()
		machine := namespace + "-rate-" + suffix
		peer := namespace + "-rate-" + peerSuffix
		endpoint := "agent/" + namespace + "/rate/" + suffix
		peerEndpoint := "agent/" + namespace + "/rate/" + peerSuffix
		if err := backend.AdvertiseEndpoints(machine, []string{endpoint}, now, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := backend.AdvertiseEndpoints(peer, []string{peerEndpoint}, now, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
		members := []relay.Member{
			{Endpoint: endpoint, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Endpoint: peerEndpoint, Capabilities: relay.CapSend | relay.CapReceive},
		}
		conversation, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
			MachineID: machine, IdempotencyKey: namespace + "-" + suffix + "-create", CreatorEndpoint: endpoint, Members: members, Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return machine, peer, endpoint, peerEndpoint, conversation
	}
	appendMessage := func(conversationID, machine, endpoint, key, body string, clock time.Time) (relay.Message, bool, error) {
		return backend.AppendMessage(relay.AppendInput{
			ConversationID: conversationID, SenderMachineID: machine, FromEndpoint: endpoint, Body: body, IdempotencyKey: namespace + "-" + key, Now: clock,
		})
	}

	if err := configurer.SetRateLimitPolicy(relay.RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 10, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	sender, _, senderEndpoint, _, firstRoom := setup("sender-a", "sender-b")
	peerC := namespace + "-rate-sender-c"
	endpointC := "agent/" + namespace + "/rate/sender-c"
	if err := backend.AdvertiseEndpoints(peerC, []string{endpointC}, now, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	crossRoom, err := backend.CreateConversationIdempotent(relay.CreateConversationInput{
		MachineID: sender, IdempotencyKey: namespace + "-sender-cross-create", CreatorEndpoint: senderEndpoint,
		Members: []relay.Member{
			{Endpoint: senderEndpoint, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
			{Endpoint: endpointC, Capabilities: relay.CapSend | relay.CapReceive},
		},
		Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := appendMessage(firstRoom.ID, sender, senderEndpoint, "sender-send-1", "one", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := appendMessage(crossRoom.ID, sender, senderEndpoint, "sender-send-2", "two", now); !errors.Is(err, relay.ErrRateLimited) {
		t.Fatalf("sender bucket across conversations err=%v", err)
	}

	if err := configurer.SetRateLimitPolicy(relay.RateLimitPolicy{SenderBurst: 10, SenderRefillPerMinute: 60, ConversationBurst: 1, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	convA, convB, convAEndpoint, convBEndpoint, shared := setup("conv-a", "conv-b")
	if _, _, err := appendMessage(shared.ID, convA, convAEndpoint, "conv-send-a", "one", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := appendMessage(shared.ID, convB, convBEndpoint, "conv-send-b", "two", now); !errors.Is(err, relay.ErrRateLimited) {
		t.Fatalf("conversation bucket across senders err=%v", err)
	}

	if err := configurer.SetRateLimitPolicy(relay.RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 30, ConversationBurst: 10, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	refillA, _, refillEndpoint, _, refillRoom := setup("refill-a", "refill-b")
	original, _, err := appendMessage(refillRoom.ID, refillA, refillEndpoint, "refill-send-1", "original", now)
	if err != nil {
		t.Fatal(err)
	}
	repeated, duplicate, err := appendMessage(refillRoom.ID, refillA, refillEndpoint, "refill-send-1", "original", now)
	if err != nil || !duplicate || repeated != original {
		t.Fatalf("committed retry message=%#v duplicate=%t err=%v", repeated, duplicate, err)
	}
	changed := relay.AppendInput{ConversationID: refillRoom.ID, SenderMachineID: refillA, FromEndpoint: refillEndpoint, Body: "changed", IdempotencyKey: namespace + "-refill-send-1", Now: now}
	if _, _, err := backend.AppendMessage(changed); !errors.Is(err, relay.ErrConflict) {
		t.Fatalf("changed-body err=%v", err)
	}
	_, _, err = appendMessage(refillRoom.ID, refillA, refillEndpoint, "refill-send-2", "two", now)
	var limited *relay.RateLimitedError
	if !errors.As(err, &limited) || limited.RetryAfterSeconds() != 2 {
		t.Fatalf("retry-after err=%v limited=%#v", err, limited)
	}
	if _, _, err := appendMessage(refillRoom.ID, refillA, refillEndpoint, "refill-send-2", "two", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}

	if err := configurer.SetRateLimitPolicy(relay.RateLimitPolicy{SenderBurst: 1, SenderRefillPerMinute: 60, ConversationBurst: 8, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60}); err != nil {
		t.Fatal(err)
	}
	concurrentA, _, concurrentEndpoint, _, concurrentRoom := setup("concurrent-a", "concurrent-b")
	const workers = 8
	results := make(chan error, workers)
	var started sync.WaitGroup
	started.Add(workers)
	release := make(chan struct{})
	for index := 0; index < workers; index++ {
		go func(index int) {
			started.Done()
			<-release
			_, _, err := appendMessage(concurrentRoom.ID, concurrentA, concurrentEndpoint, fmt.Sprintf("concurrent-%d", index), fmt.Sprintf("body-%d", index), now)
			results <- err
		}(index)
	}
	started.Wait()
	close(release)
	accepted, rejected := 0, 0
	for index := 0; index < workers; index++ {
		err := <-results
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, relay.ErrRateLimited):
			rejected++
		default:
			t.Fatalf("concurrent send err=%v", err)
		}
	}
	if accepted != 1 || rejected != workers-1 {
		t.Fatalf("accepted=%d rejected=%d", accepted, rejected)
	}
}
