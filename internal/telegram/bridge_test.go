package telegram

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rock3r/punaro/internal/relay"
)

type fakeBridgeRelay struct {
	advertised []string
	deliveries []relay.Delivery
	acked      []string
}

func (r *fakeBridgeRelay) Advertise(_ context.Context, endpoints []string) error {
	r.advertised = append([]string(nil), endpoints...)
	return nil
}

func (r *fakeBridgeRelay) Lease(context.Context, string) ([]relay.Delivery, error) {
	return r.deliveries, nil
}

func (r *fakeBridgeRelay) Ack(_ context.Context, delivery relay.Delivery) error {
	r.acked = append(r.acked, delivery.ID)
	return nil
}

func TestBridgeSyncsInboundAndOutboundThroughOneAttachedGatewayEndpoint(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	relayClient := &fakeBridgeRelay{deliveries: []relay.Delivery{{ID: "delivery-1", Message: relay.Message{ConversationID: "conversation-1", FromEndpoint: "agent/a", Body: "reply"}}}}
	richSender := &recordedRichSender{}
	submitted := 0
	bridge := Bridge{
		Relay:    relayClient,
		Endpoint: "telegram/gateway",
		State:    state,
		Poller:   fakePoller{updates: []Update{{ID: 10, UserID: 55, ChatID: 100, ThreadID: 7, Text: "question"}}},
		Gateway: Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error {
			submitted++
			return nil
		}},
		Sender: richSender,
	}
	next, err := bridge.SyncOnce(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if next != 11 || submitted != 1 || len(relayClient.advertised) != 1 || relayClient.advertised[0] != "telegram/gateway" || len(relayClient.acked) != 1 || relayClient.acked[0] != "delivery-1" || len(richSender.html) != 1 {
		t.Fatalf("next=%d submitted=%d advertised=%#v acked=%#v sent=%#v", next, submitted, relayClient.advertised, relayClient.acked, richSender.html)
	}
}
