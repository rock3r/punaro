package postgres

import (
	"testing"

	"github.com/rock3r/punaro/internal/relay"
)

func TestPostgresAppendDeliveryRecipientsExcludesGatewaySelfSend(t *testing.T) {
	recipients, err := postgresAppendDeliveryRecipients(nil, "unused", relay.TelegramGatewayEndpoint, relay.TelegramUserParticipant, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 0 {
		t.Fatalf("gateway self-send recipients=%q", recipients)
	}
	recipients, err = postgresAppendDeliveryRecipients(nil, "unused", "agent/a", relay.TelegramUserParticipant, true)
	if err != nil || len(recipients) != 1 || recipients[0] != relay.TelegramGatewayEndpoint {
		t.Fatalf("agent user-telegram recipients=%q err=%v", recipients, err)
	}
}
