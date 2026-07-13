package telegram

import (
	"path/filepath"
	"testing"
)

func TestStateRecordsCompletedUpdatesAndRequiresExplicitTopicRoute(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	processed, err := state.Processed(42)
	if err != nil || processed {
		t.Fatalf("initial processed=%v err=%v", processed, err)
	}
	if err := state.MarkProcessed(42); err != nil {
		t.Fatal(err)
	}
	processed, err = state.Processed(42)
	if err != nil || !processed {
		t.Fatalf("completed processed=%v err=%v", processed, err)
	}
	if _, found, err := state.Route(100, 7); err != nil || found {
		t.Fatalf("unexpected route found=%v err=%v", found, err)
	}
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	conversation, found, err := state.Route(100, 7)
	if err != nil || !found || conversation != "conversation-1" {
		t.Fatalf("route=%q found=%v err=%v", conversation, found, err)
	}
	chat, thread, found, err := state.RouteForConversation("conversation-1")
	if err != nil || !found || chat != 100 || thread != 7 {
		t.Fatalf("reverse route chat=%d thread=%d found=%v err=%v", chat, thread, found, err)
	}
	if err := state.SetRoute(100, 8, "conversation-1"); err == nil {
		t.Fatal("one conversation was mapped to more than one Telegram topic")
	}
}
