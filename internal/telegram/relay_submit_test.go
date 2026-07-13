package telegram

import (
	"context"
	"testing"

	"github.com/rock3r/punaro/internal/relay"
)

type recordedRelaySender struct {
	conversation string
	endpoint     string
	body         string
	key          string
}

func (s *recordedRelaySender) Send(_ context.Context, conversation, endpoint, body, key string) (relay.Message, error) {
	s.conversation = conversation
	s.endpoint = endpoint
	s.body = body
	s.key = key
	return relay.Message{ID: "message-1"}, nil
}

func TestSubmitToRelayUsesTelegramUpdateIDForRetryIdentity(t *testing.T) {
	t.Parallel()
	sender := &recordedRelaySender{}
	submit := SubmitToRelay(sender, "telegram/gateway")
	if err := submit(context.Background(), Submission{UpdateID: 42, ConversationID: "conversation-1", Text: "question"}); err != nil {
		t.Fatal(err)
	}
	if sender.conversation != "conversation-1" || sender.endpoint != "telegram/gateway" || sender.body != "question" || sender.key != "telegram-update:42" {
		t.Fatalf("relay call = %#v", sender)
	}
}

func TestSubmitToRelayRejectsMissingUpdateIdentity(t *testing.T) {
	t.Parallel()
	if err := SubmitToRelay(&recordedRelaySender{}, "telegram/gateway")(context.Background(), Submission{ConversationID: "conversation-1", Text: "question"}); err == nil {
		t.Fatal("submission without update identity accepted")
	}
}
