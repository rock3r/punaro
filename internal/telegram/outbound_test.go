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
}

func (s *recordedRichSender) SendRichMessage(_ context.Context, chatID, threadID int64, html string) error {
	s.chat = chatID
	s.thread = threadID
	s.html = append(s.html, html)
	return nil
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
	if err := SendDelivery(context.Background(), state, sender, delivery); err != nil {
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

func TestSendDeliveryRejectsUnroutedConversation(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := SendDelivery(context.Background(), state, &recordedRichSender{}, relay.Delivery{Message: relay.Message{ConversationID: "unrouted", FromEndpoint: "agent/a", Body: "reply"}}); err == nil {
		t.Fatal("unrouted delivery was sent to Telegram")
	}
}
