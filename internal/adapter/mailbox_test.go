package adapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

func TestCLIMailboxUsesActiveGroupMembersAsAttachments(t *testing.T) {
	t.Parallel()
	var calls [][]string
	mailbox := newCLIMailbox("agent-mailbox", "/state", "group/punaro", func(_ context.Context, args []string, _ []byte) ([]byte, error) {
		calls = append(calls, args)
		return []byte(`[{"person":"agent/active","active":true},{"person":"agent/detached","active":false}]`), nil
	})
	attached, err := mailbox.Attached(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(attached) != 1 || attached[0] != "agent/active" {
		t.Fatalf("attached = %#v", attached)
	}
	if strings.Join(calls[0], " ") != "agent-mailbox --state-dir /state group members --group group/punaro --json" {
		t.Fatalf("mailbox command = %#v", calls)
	}
}

func TestCLIMailboxSendsInertPunaroEnvelope(t *testing.T) {
	t.Parallel()
	var args []string
	var stdin []byte
	mailbox := newCLIMailbox("agent-mailbox", "", "group/punaro", func(_ context.Context, command []string, input []byte) ([]byte, error) {
		args = command
		stdin = input
		return []byte(`{"message_id":"local-1"}`), nil
	})
	if err := mailbox.Send(context.Background(), "agent/active", InboundMessage{PunaroMessageID: "message-1", ConversationID: "conversation-1", Body: "untrusted body"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(args, " ") != "agent-mailbox send --to agent/active --subject Punaro message --content-type application/vnd.punaro.message+json --schema-version 1 --body-file - --json" {
		t.Fatalf("send command = %#v", args)
	}
	if !strings.Contains(string(stdin), `"punaro_message_id":"message-1"`) || !strings.Contains(string(stdin), `"body":"untrusted body"`) {
		t.Fatalf("send body = %s", stdin)
	}
}

func TestCLIMailboxSendsTelegramInboundMetadata(t *testing.T) {
	t.Parallel()
	var stdin []byte
	mailbox := newCLIMailbox("agent-mailbox", "", "group/punaro", func(_ context.Context, _ []string, input []byte) ([]byte, error) {
		stdin = append([]byte(nil), input...)
		return []byte(`{"message_id":"local-1"}`), nil
	})
	createdAt := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	if err := mailbox.Send(context.Background(), "agent/active", InboundMessage{
		PunaroMessageID:          "message-1",
		ConversationID:           "conversation-1",
		Sequence:                 3,
		FromEndpoint:             relay.TelegramUserParticipant,
		FromParticipant:          relay.TelegramUserParticipant,
		InReplyToEndpoint:        "agent/sender",
		InReplyToPunaroMessageID: "message-0",
		TelegramThreadID:         795446,
		Body:                     "untrusted body",
		CreatedAt:                createdAt,
	}); err != nil {
		t.Fatal(err)
	}
	var got InboundMessage
	if err := json.Unmarshal(stdin, &got); err != nil {
		t.Fatalf("decode envelope: %v body=%s", err, stdin)
	}
	if got.FromEndpoint != relay.TelegramUserParticipant || got.FromParticipant != relay.TelegramUserParticipant {
		t.Fatalf("from = %#v", got)
	}
	if got.InReplyToEndpoint != "agent/sender" || got.InReplyToPunaroMessageID != "message-0" || got.TelegramThreadID != 795446 {
		t.Fatalf("reply metadata = %#v body=%s", got, stdin)
	}
}
