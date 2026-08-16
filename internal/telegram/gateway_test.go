package telegram

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rock3r/punaro/internal/relay"
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
	if len(submitted) != 1 || submitted[0].UpdateID != 2 || submitted[0].ConversationID != "conversation-1" || submitted[0].Text != "question" {
		t.Fatalf("submitted=%#v", submitted)
	}
}

func TestGatewaySkipsUnboundTopicWithoutFallback(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	gateway := Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error { t.Fatal("unbound topic submitted"); return nil }}
	if err := gateway.Handle(context.Background(), Update{ID: 1, UserID: 55, ChatID: 100, ThreadID: 7, Text: "question"}); err != nil {
		t.Fatal(err)
	}
	processed, err := state.Processed(1)
	if err != nil || !processed {
		t.Fatalf("unbound update was not durably skipped: processed=%v err=%v", processed, err)
	}
}

func TestGatewayRetriesUnrecordedUpdateAfterRelayFailure(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	gateway := Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error {
		attempts++
		if attempts == 1 {
			return context.DeadlineExceeded
		}
		return nil
	}}
	update := Update{ID: 1, UserID: 55, ChatID: 100, ThreadID: 7, Text: "question"}
	if err := gateway.Handle(context.Background(), update); err == nil {
		t.Fatal("relay failure was accepted")
	}
	if err := gateway.Handle(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Handle(context.Background(), update); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("submit attempts = %d, want 2", attempts)
	}
}

func TestGatewayStartAndListAreOperatorCommands(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 7, "conversation-routed"); err != nil {
		t.Fatal(err)
	}
	notify := &recordingNotify{}
	var logs []string
	var submitted []Submission
	longName := strings.Repeat("名", 80)
	gateway := Gateway{
		AllowedUserID: 55,
		State:         state,
		Submit: func(_ context.Context, submission Submission) error {
			submitted = append(submitted, submission)
			return nil
		},
		ListUnclaimed: func(context.Context) ([]relay.UnclaimedTopic, error) {
			return []relay.UnclaimedTopic{
				{ID: "conversation-1", DisplayName: "How is it going"},
				{ID: "conversation-2", DisplayName: longName},
			}, nil
		},
		Notify: notify,
		Now:    func() time.Time { return testCallbackNow },
		Log:    func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
	}
	if err := gateway.Handle(context.Background(), Update{ID: 1, UserID: 55, ChatID: 55, Text: "/start@TopicBot", IsCommand: true, Command: "start"}); err != nil {
		t.Fatal(err)
	}
	if len(submitted) != 0 || len(notify.messages) != 1 || notify.messages[0].chatID != 55 || notify.messages[0].text != startHelpText || notify.messages[0].keyboard != nil {
		t.Fatalf("start submitted=%#v messages=%#v", submitted, notify.messages)
	}
	if !hasLogClass(logs, "telegram_command") || !strings.Contains(strings.Join(logs, "\n"), "cmd=start") {
		t.Fatalf("start logs=%#v", logs)
	}
	if err := gateway.Handle(context.Background(), Update{ID: 2, UserID: 55, ChatID: 55, ThreadID: 7, Text: "/list", IsCommand: true, Command: "list"}); err != nil {
		t.Fatal(err)
	}
	if len(submitted) != 0 || len(notify.messages) != 2 || notify.messages[1].chatID != 55 || notify.messages[1].text != listPromptText || len(notify.messages[1].keyboard) != 2 {
		t.Fatalf("list submitted=%#v messages=%#v", submitted, notify.messages)
	}
	first := notify.messages[1].keyboard[0][0]
	second := notify.messages[1].keyboard[1][0]
	if first.Text != "How is it going" || second.Text != strings.Repeat("名", 64) || utf8.RuneCountInString(second.Text) != 64 {
		t.Fatalf("buttons=%#v", notify.messages[1].keyboard)
	}
	if first.CallbackData == "conversation-1" || second.CallbackData == "conversation-2" || strings.Contains(notify.messages[1].text, "conversation-1") {
		t.Fatal("conversation id leaked into Telegram operator UX")
	}
	if conversation, found, consumed, err := state.lookupCallbackToken(first.CallbackData, testCallbackNow); err != nil || !found || consumed || conversation != "conversation-1" {
		t.Fatalf("issued token conversation=%q found=%v consumed=%v err=%v", conversation, found, consumed, err)
	}
	if !hasLogClass(logs, "telegram_command") || !strings.Contains(strings.Join(logs, "\n"), "cmd=list") {
		t.Fatalf("list logs=%#v", logs)
	}
}

func TestGatewayListEmptyHasNoKeyboard(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	notify := &recordingNotify{}
	gateway := Gateway{
		AllowedUserID: 55,
		State:         state,
		Submit:        func(context.Context, Submission) error { t.Fatal("empty list submitted"); return nil },
		ListUnclaimed: func(context.Context) ([]relay.UnclaimedTopic, error) { return nil, nil },
		Notify:        notify,
		Now:           func() time.Time { return testCallbackNow },
		Log:           func(string, ...any) {},
	}
	if err := gateway.Handle(context.Background(), Update{ID: 1, UserID: 55, ChatID: 55, IsCommand: true, Command: "list"}); err != nil {
		t.Fatal(err)
	}
	if len(notify.messages) != 1 || notify.messages[0].text != listEmptyText || notify.messages[0].keyboard != nil {
		t.Fatalf("empty list=%#v", notify.messages)
	}
}

func TestGatewayCallbackWithoutClaimExecutionStaysInert(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	notify := &recordingNotify{}
	var logs []string
	gateway := Gateway{
		AllowedUserID: 55,
		State:         state,
		Submit:        func(context.Context, Submission) error { t.Fatal("callback submitted as mail"); return nil },
		ListUnclaimed: func(context.Context) ([]relay.UnclaimedTopic, error) {
			return []relay.UnclaimedTopic{{ID: "conversation-1", DisplayName: "Ops"}}, nil
		},
		Notify: notify,
		Now:    func() time.Time { return testCallbackNow },
		Log:    func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
	}
	if err := gateway.Handle(context.Background(), Update{ID: 1, UserID: 55, ChatID: 55, IsCommand: true, Command: "list"}); err != nil {
		t.Fatal(err)
	}
	raw := notify.messages[0].keyboard[0][0].CallbackData
	if err := gateway.Handle(context.Background(), Update{ID: 2, UserID: 55, ChatID: 55, CallbackID: "cbq-1", CallbackData: raw}); err != nil {
		t.Fatal(err)
	}
	if len(notify.answers) != 1 || notify.answers[0].id != "cbq-1" || notify.answers[0].text != callbackFailureText {
		t.Fatalf("answers=%#v", notify.answers)
	}
	if _, found, consumed, err := state.lookupCallbackToken(raw, testCallbackNow); err != nil || !found || consumed {
		t.Fatalf("6a consumed callback token: found=%v consumed=%v err=%v", found, consumed, err)
	}
	var claimExecutions int
	if err := state.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='claim_executions'`).Scan(&claimExecutions); err != nil || claimExecutions != 0 {
		t.Fatalf("6a inserted claim_executions: count=%d err=%v", claimExecutions, err)
	}
	if strings.Contains(strings.Join(logs, "\n"), raw) {
		t.Fatalf("callback token leaked into logs: %#v", logs)
	}
	if !hasLogClass(logs, "telegram_update_inert") {
		t.Fatalf("callback logs=%#v", logs)
	}
}

func TestGatewayUnauthorizedCallbackStaysUnconsumed(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	notify := &recordingNotify{}
	var logs []string
	gateway := Gateway{
		AllowedUserID: 55,
		State:         state,
		Submit:        func(context.Context, Submission) error { t.Fatal("callback submitted as mail"); return nil },
		ListUnclaimed: func(context.Context) ([]relay.UnclaimedTopic, error) {
			return []relay.UnclaimedTopic{{ID: "conversation-1", DisplayName: "Ops"}}, nil
		},
		Notify: notify,
		Now:    func() time.Time { return testCallbackNow },
		Log:    func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
	}
	if err := gateway.Handle(context.Background(), Update{ID: 1, UserID: 55, ChatID: 55, IsCommand: true, Command: "list"}); err != nil {
		t.Fatal(err)
	}
	raw := notify.messages[0].keyboard[0][0].CallbackData
	if err := gateway.Handle(context.Background(), Update{ID: 2, UserID: 99, ChatID: 99, CallbackID: "cbq-forwarded", CallbackData: raw}); err != nil {
		t.Fatal(err)
	}
	if len(notify.answers) != 1 || notify.answers[0].id != "cbq-forwarded" || notify.answers[0].text != callbackFailureText {
		t.Fatalf("answers=%#v", notify.answers)
	}
	if _, found, consumed, err := state.lookupCallbackToken(raw, testCallbackNow); err != nil || !found || consumed {
		t.Fatalf("unauthorized callback consumed token: found=%v consumed=%v err=%v", found, consumed, err)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "reason=unauthorized") {
		t.Fatalf("unauthorized callback logs=%#v", logs)
	}
}

func TestGatewayKeepsMainChatTextAndUnknownCommandsInert(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	notify := &recordingNotify{}
	var logs []string
	var submitted []Submission
	gateway := Gateway{
		AllowedUserID: 55,
		State:         state,
		Submit: func(_ context.Context, submission Submission) error {
			submitted = append(submitted, submission)
			return nil
		},
		Notify: notify,
		Log:    func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
	}
	if err := gateway.Handle(context.Background(), Update{ID: 1, UserID: 55, ChatID: 55, Text: "hello from the main chat"}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Handle(context.Background(), Update{ID: 2, UserID: 55, ChatID: 55, ThreadID: 7, Text: "/help", IsCommand: true, Command: "help"}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Handle(context.Background(), Update{ID: 3, UserID: 55, ChatID: 55, ThreadID: 7, Text: "/list"}); err != nil {
		t.Fatal(err)
	}
	if len(notify.messages) != 0 || len(submitted) != 1 || submitted[0].Text != "/list" || submitted[0].ConversationID != "conversation-1" {
		t.Fatalf("submitted=%#v messages=%#v", submitted, notify.messages)
	}
	if !hasLogClass(logs, "telegram_update_inert") || !hasLogClass(logs, "telegram_update_submitted") {
		t.Fatalf("inert/submit logs=%#v", logs)
	}
}

type recordingNotify struct {
	messages []recordedOperatorMessage
	answers  []recordedCallbackAnswer
}

type recordedOperatorMessage struct {
	chatID   int64
	text     string
	keyboard [][]InlineKeyboardButton
}

type recordedCallbackAnswer struct {
	id   string
	text string
}

func (n *recordingNotify) SendMessage(_ context.Context, chatID int64, text string, keyboard [][]InlineKeyboardButton) error {
	n.messages = append(n.messages, recordedOperatorMessage{chatID: chatID, text: text, keyboard: keyboard})
	return nil
}

func (n *recordingNotify) AnswerCallbackQuery(_ context.Context, callbackID, text string) error {
	n.answers = append(n.answers, recordedCallbackAnswer{id: callbackID, text: text})
	return nil
}

type failingCallbackNotify struct {
	recordingNotify
	err error
}

func (n *failingCallbackNotify) AnswerCallbackQuery(context.Context, string, string) error {
	return n.err
}

func hasLogClass(logs []string, class string) bool {
	needle := "class=" + class
	for _, line := range logs {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}
