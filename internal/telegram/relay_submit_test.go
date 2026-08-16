package telegram

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/rock3r/punaro/internal/relay"
)

type recordedInboundSender struct {
	conversation     string
	endpoint         string
	participant      string
	body             string
	replyMessageID   string
	replyEndpoint    string
	telegramThreadID int64
	key              string
}

func (s *recordedInboundSender) SendTelegramInbound(_ context.Context, conversationID, fromEndpoint, fromParticipant, body, inReplyToMessageID, inReplyToEndpoint string, telegramThreadID int64, idempotencyKey string) (relay.Message, error) {
	s.conversation = conversationID
	s.endpoint = fromEndpoint
	s.participant = fromParticipant
	s.body = body
	s.replyMessageID = inReplyToMessageID
	s.replyEndpoint = inReplyToEndpoint
	s.telegramThreadID = telegramThreadID
	s.key = idempotencyKey
	return relay.Message{ID: "message-1"}, nil
}

func TestSubmitToRelayUsesTelegramInboundAndResolvesReplyTo(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.RecordOutbound(100, 9, "conversation-1", "punaro-9", "agent/a", testCallbackNow); err != nil {
		t.Fatal(err)
	}
	sender := &recordedInboundSender{}
	submit := SubmitToRelay(sender, relay.TelegramGatewayEndpoint, state, nil)
	if err := submit(context.Background(), Submission{UpdateID: 42, ConversationID: "conversation-1", Text: "question", ChatID: 100, ThreadID: 7, ReplyToID: 9}); err != nil {
		t.Fatal(err)
	}
	if sender.conversation != "conversation-1" || sender.endpoint != relay.TelegramGatewayEndpoint || sender.participant != relay.TelegramUserParticipant || sender.body != "question" || sender.key != "telegram-update:42" || sender.replyMessageID != "punaro-9" || sender.replyEndpoint != "agent/a" || sender.telegramThreadID != 7 {
		t.Fatalf("relay call = %#v", sender)
	}
}

func TestSubmitToRelayOmitsReplyMetadataOnMapMiss(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	sender := &recordedInboundSender{}
	var logs []string
	submit := SubmitToRelay(sender, relay.TelegramGatewayEndpoint, state, func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) })
	if err := submit(context.Background(), Submission{UpdateID: 42, ConversationID: "conversation-1", Text: "question", ChatID: 100, ThreadID: 7, ReplyToID: 9}); err != nil {
		t.Fatal(err)
	}
	if sender.replyMessageID != "" || sender.replyEndpoint != "" || sender.telegramThreadID != 7 {
		t.Fatalf("miss should omit reply metadata: %#v", sender)
	}
	if !hasLogClass(logs, "telegram_outbound_map_miss") {
		t.Fatalf("logs=%#v", logs)
	}
}

func TestSubmitToRelayOmitsReplyMetadataFromAnotherConversation(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.RecordOutbound(100, 9, "conversation-other", "punaro-other", "agent/b", testCallbackNow); err != nil {
		t.Fatal(err)
	}
	sender := &recordedInboundSender{}
	var logs []string
	submit := SubmitToRelay(sender, relay.TelegramGatewayEndpoint, state, func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) })
	if err := submit(context.Background(), Submission{UpdateID: 42, ConversationID: "conversation-1", Text: "question", ChatID: 100, ThreadID: 7, ReplyToID: 9}); err != nil {
		t.Fatal(err)
	}
	if sender.replyMessageID != "" || sender.replyEndpoint != "" {
		t.Fatalf("cross-conversation reply metadata attached: %#v", sender)
	}
	if !hasLogClass(logs, "telegram_outbound_map_miss") {
		t.Fatalf("logs=%#v", logs)
	}
}

func TestSubmitToRelayRejectsMissingUpdateIdentity(t *testing.T) {
	t.Parallel()
	if err := SubmitToRelay(&recordedInboundSender{}, relay.TelegramGatewayEndpoint, nil, nil)(context.Background(), Submission{ConversationID: "conversation-1", Text: "question"}); err == nil {
		t.Fatal("submission without update identity accepted")
	}
}
