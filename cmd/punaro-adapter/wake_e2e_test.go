//go:build e2e

package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/adapter"
	"github.com/rock3r/punaro/internal/relay"
)

// TestE2EPayloadFreeWake exercises a configured relay without embedding any
// deployment details. It deliberately asserts only wake metadata; the durable
// lease path remains the way a client fetches message content.
func TestE2EPayloadFreeWake(t *testing.T) {
	sender := os.Getenv("PUNARO_E2E_SENDER")
	receiver := os.Getenv("PUNARO_E2E_RECEIVER")
	if sender == "" || receiver == "" {
		t.Skip("set PUNARO_E2E_SENDER and PUNARO_E2E_RECEIVER to run the live wake test")
	}
	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	client, err := adapter.NewHTTPRelayClient(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := make(chan relay.WakeEvent, 1)
	readErr := make(chan error, 1)
	go func() { readErr <- client.ReadNotifications(ctx, func(event relay.WakeEvent) { events <- event }) }()

	conversation, err := client.CreateConversation(ctx, sender, []relay.Member{
		{Endpoint: sender, Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
		{Endpoint: receiver, Capabilities: relay.CapReceive},
	}, "e2e-wake-create-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	for sequence := 0; sequence < 20; sequence++ {
		if _, err := client.Send(ctx, conversation.ID, sender, "wake-e2e", fmt.Sprintf("e2e-wake-send-%s-%d", uuid.NewString(), sequence)); err != nil {
			t.Fatal(err)
		}
		select {
		case event := <-events:
			if event.TopicID != conversation.ID || event.Sequence < 1 {
				t.Fatalf("unexpected wake metadata: %#v", event)
			}
			return
		case err := <-readErr:
			t.Fatalf("notification stream ended: %v", err)
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Fatal("did not receive a payload-free wake hint")
}
