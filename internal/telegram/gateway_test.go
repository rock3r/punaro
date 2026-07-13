package telegram

import (
	"context"
	"path/filepath"
	"testing"
)

func TestGatewayAuthorizesClaimsAndRoutesTelegramTextOnce(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	var submitted []Submission
	gateway := Gateway{AllowedUserID: 55, State: state, Submit: func(_ context.Context, submission Submission) error {
		submitted = append(submitted, submission)
		return nil
	}}
	if err := gateway.Handle(context.Background(), Update{ID: 1, UserID: 99, ChatID: 100, ThreadID: 7, Text: "ignored"}); err != nil {
		t.Fatal(err)
	}
	if len(submitted) != 0 {
		t.Fatal("unauthorized update was submitted")
	}
	if err := gateway.Handle(context.Background(), Update{ID: 2, UserID: 55, ChatID: 100, ThreadID: 7, Text: "question"}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Handle(context.Background(), Update{ID: 2, UserID: 55, ChatID: 100, ThreadID: 7, Text: "question"}); err != nil {
		t.Fatal(err)
	}
	if len(submitted) != 1 || submitted[0].ConversationID != "conversation-1" || submitted[0].Text != "question" {
		t.Fatalf("submitted=%#v", submitted)
	}
}

func TestGatewayRejectsUnboundTopicWithoutFallback(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	gateway := Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error { t.Fatal("unbound topic submitted"); return nil }}
	if err := gateway.Handle(context.Background(), Update{ID: 1, UserID: 55, ChatID: 100, ThreadID: 7, Text: "question"}); err == nil {
		t.Fatal("unbound topic accepted")
	}
}
