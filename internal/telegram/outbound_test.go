package telegram

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rock3r/punaro/internal/relay"
)

type recordedRichSender struct {
	chat   int64
	thread int64
	html   []string
	lastID int64
}

func (s *recordedRichSender) SendRichMessage(_ context.Context, chatID, threadID int64, html string) (int64, error) {
	s.chat = chatID
	s.thread = threadID
	s.html = append(s.html, html)
	s.lastID++
	return s.lastID, nil
}

func TestSendDeliveryRoutesToExactTopicAndEscapesAgentText(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	sender := &recordedRichSender{}
	delivery := relay.Delivery{Message: relay.Message{ConversationID: "conversation-1", FromEndpoint: "agent/a<unsafe>", Body: "<script>not markup</script>"}}
	if err := SendDelivery(context.Background(), state, sender, delivery, 100); err != nil {
		t.Fatal(err)
	}
	if sender.chat != 100 || sender.thread != 7 || len(sender.html) != 1 {
		t.Fatalf("telegram target=%d/%d messages=%#v", sender.chat, sender.thread, sender.html)
	}
	want := "<p><b>Reply from </b><code>agent/a&lt;unsafe&gt;</code></p><pre>&lt;script&gt;not markup&lt;/script&gt;</pre>"
	if sender.html[0] != want {
		t.Fatalf("html=%q\nwant=%q", sender.html[0], want)
	}
}

func TestSendDeliveryRecordsTelegramOutboundMap(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	sender := &recordedRichSender{}
	delivery := relay.Delivery{ID: "delivery-1", Message: relay.Message{ID: "message-1", ConversationID: "conversation-1", FromEndpoint: "agent/a", Body: "reply"}}
	if err := SendDelivery(context.Background(), state, sender, delivery, 100); err != nil {
		t.Fatal(err)
	}
	ref, found, err := state.LookupOutbound(100, 1)
	if err != nil || !found || ref.ConversationID != "conversation-1" || ref.PunaroMessageID != "message-1" || ref.FromEndpoint != "agent/a" {
		t.Fatalf("outbound=%#v found=%v err=%v", ref, found, err)
	}
}

func TestSendDeliveryRejectsUnroutedConversation(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	err = SendDelivery(context.Background(), state, &recordedRichSender{}, relay.Delivery{Message: relay.Message{ConversationID: "unrouted", FromEndpoint: "agent/a", Body: "reply"}}, 100)
	if err == nil {
		t.Fatal("unrouted delivery was sent to Telegram")
	}
	if isPermanentTelegramFailure(err) {
		t.Fatalf("unrouted delivery was classified as permanent: %v", err)
	}
}

func TestSendDeliveryRejectsRouteForDifferentTelegramChat(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(99, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	sender := &recordedRichSender{}
	err = SendDelivery(context.Background(), state, sender, relay.Delivery{Message: relay.Message{ConversationID: "conversation-1", FromEndpoint: "agent/a", Body: "reply"}}, 55)
	if err == nil || sender.chat != 0 {
		t.Fatalf("foreign-chat delivery was sent: err=%v chat=%d", err, sender.chat)
	}
	if isPermanentTelegramFailure(err) {
		t.Fatalf("foreign-chat delivery was classified as permanent: %v", err)
	}
}
