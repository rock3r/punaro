package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func TestCLIMailboxReadsPaginatedWaypostAttachments(t *testing.T) {
	t.Parallel()
	var calls [][]string
	mailbox := newCLIMailbox("waypost", "/state", "group/punaro", func(_ context.Context, args []string, _ []byte) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(args) >= 2 && args[len(args)-2] == "--cursor" && args[len(args)-1] == "next" {
			return []byte(`{"items":[{"person":"agent/b","active":true},{"person":"agent/retired","active":false}]}`), nil
		}
		return []byte(`{"items":[{"person":"agent/a","active":true}],"next_cursor":"next"}`), nil
	})
	attached, err := mailbox.Attached(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(attached, ",") != "agent/a,agent/b" {
		t.Fatalf("attached = %#v", attached)
	}
	if len(calls) != 2 || strings.Join(calls[1], " ") != "waypost --state-dir /state group members --group group/punaro --json --cursor next" {
		t.Fatalf("mailbox calls = %#v", calls)
	}
}

func TestInstalledWaypostCLIMailboxSmoke(t *testing.T) {
	binary := strings.TrimSpace(os.Getenv("PUNARO_TEST_WAYPOST_BINARY"))
	if binary == "" {
		t.Skip("PUNARO_TEST_WAYPOST_BINARY is not set")
	}
	state := filepath.Join(t.TempDir(), "waypost")
	for _, args := range [][]string{
		{"--state-dir", state, "group", "create", "--group", "group/punaro"},
	} {
		if output, err := exec.CommandContext(t.Context(), binary, args...).CombinedOutput(); err != nil { // #nosec G204,G702 -- explicit test-only reviewed binary and fixed fixture arguments.
			t.Fatalf("waypost %v: %v: %s", args, err, output)
		}
	}
	for index := range 51 {
		person := fmt.Sprintf("agent/smoke-%02d", index)
		args := []string{"--state-dir", state, "group", "add-member", "--group", "group/punaro", "--person", person}
		if output, err := exec.CommandContext(t.Context(), binary, args...).CombinedOutput(); err != nil { // #nosec G204,G702 -- explicit test-only reviewed binary and fixed fixture arguments.
			t.Fatalf("waypost add-member %q: %v: %s", person, err, output)
		}
	}
	mailbox, err := NewCLIMailbox(binary, state, "group/punaro")
	if err != nil {
		t.Fatal(err)
	}
	attached, err := mailbox.Attached(t.Context())
	if err != nil || len(attached) != 51 || attached[0] != "agent/smoke-00" || attached[50] != "agent/smoke-50" {
		t.Fatalf("attached=%v err=%v", attached, err)
	}
	if err := mailbox.Send(t.Context(), "agent/smoke-00", InboundMessage{PunaroMessageID: "message-1", ConversationID: "conversation-1", Body: "untrusted body"}); err != nil {
		t.Fatal(err)
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
		TelegramThreadID:         700001,
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
	if got.InReplyToEndpoint != "agent/sender" || got.InReplyToPunaroMessageID != "message-0" || got.TelegramThreadID != 700001 {
		t.Fatalf("reply metadata = %#v body=%s", got, stdin)
	}
}
