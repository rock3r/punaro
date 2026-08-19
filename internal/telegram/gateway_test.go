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
	if err := gateway.Handle(context.Background(), Update{ID: 2, UserID: 55, ChatID: 100, ThreadID: 7, MessageID: 12, ReplyToID: 9, Text: "question"}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Handle(context.Background(), Update{ID: 2, UserID: 55, ChatID: 100, ThreadID: 7, MessageID: 12, ReplyToID: 9, Text: "question"}); err != nil {
		t.Fatal(err)
	}
	if len(submitted) != 1 || submitted[0].UpdateID != 2 || submitted[0].ConversationID != "conversation-1" || submitted[0].Text != "question" || submitted[0].ChatID != 100 || submitted[0].ThreadID != 7 || submitted[0].ReplyToID != 9 {
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

func TestGatewayListFailsClosedOnAmbiguousButtonLabels(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	notify := &recordingNotify{}
	prefix := strings.Repeat("名", maxButtonTextRunes)
	gateway := Gateway{
		AllowedUserID: 55,
		State:         state,
		Submit:        func(context.Context, Submission) error { t.Fatal("ambiguous list submitted"); return nil },
		ListUnclaimed: func(context.Context) ([]relay.UnclaimedTopic, error) {
			return []relay.UnclaimedTopic{
				{ID: "conversation-1", DisplayName: prefix + "one"},
				{ID: "conversation-2", DisplayName: prefix + "two"},
			}, nil
		},
		Notify: notify,
		Now:    func() time.Time { return testCallbackNow },
		Log:    func(string, ...any) {},
	}
	if err := gateway.Handle(context.Background(), Update{ID: 1, UserID: 55, ChatID: 55, IsCommand: true, Command: "list"}); err != nil {
		t.Fatalf("ambiguous list must be consumed: %v", err)
	}
	if len(notify.messages) != 1 || notify.messages[0].text != listAmbiguousText || notify.messages[0].keyboard != nil {
		t.Fatalf("ambiguous list notify=%#v", notify.messages)
	}
	processed, err := state.Processed(1)
	if err != nil || !processed {
		t.Fatalf("ambiguous list processed=%v err=%v", processed, err)
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

func TestGatewayCallbackReservesExecutionThenConsumesToken(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	notify := &recordingNotify{}
	var logs []string
	topics := &recordingTopicCreator{threadID: 795446}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "Ops"}}
	executor := &ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }}
	gateway := Gateway{
		AllowedUserID: 55,
		State:         state,
		Submit:        func(context.Context, Submission) error { t.Fatal("callback submitted as mail"); return nil },
		ListUnclaimed: func(context.Context) ([]relay.UnclaimedTopic, error) {
			return []relay.UnclaimedTopic{{ID: "conversation-1", DisplayName: "Ops"}}, nil
		},
		Notify: notify,
		Claims: executor,
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
	if len(notify.answers) != 1 || notify.answers[0].id != "cbq-1" || notify.answers[0].text != callbackAcceptedText {
		t.Fatalf("answers=%#v", notify.answers)
	}
	if _, found, consumed, err := state.lookupCallbackToken(raw, testCallbackNow); err != nil || !found || !consumed {
		t.Fatalf("token found=%v consumed=%v err=%v", found, consumed, err)
	}
	if len(claims.reserves) != 1 || claims.reserves[0].endpoint != relay.TelegramGatewayEndpoint || claims.reserves[0].key != GatewayClaimKey("conversation-1") {
		t.Fatalf("reserves=%#v", claims.reserves)
	}
	if len(topics.names) != 1 || topics.names[0] != "Ops" || topics.chatIDs[0] != 55 {
		t.Fatalf("createForumTopic=%#v chats=%#v", topics.names, topics.chatIDs)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795446 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
	if !hasLogClass(logs, "telegram_claim_reserved") || !hasLogClass(logs, "telegram_claim_completed") {
		t.Fatalf("callback logs=%#v", logs)
	}
	if strings.Contains(strings.Join(logs, "\n"), raw) {
		t.Fatalf("callback token leaked into logs: %#v", logs)
	}
}

func TestGatewayCallbackExecuteClaimFailureDoesNotFailHandle(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	notify := &recordingNotify{}
	var logs []string
	claims := &recordingClaimRelay{reserveErr: fmt.Errorf("relay rejected request with HTTP 500")}
	executor := &ClaimExecutor{State: state, Relay: claims, Topics: &recordingTopicCreator{threadID: 1}, AllowedUserID: 55, Log: func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }}
	gateway := Gateway{
		AllowedUserID: 55,
		State:         state,
		Submit:        func(context.Context, Submission) error { t.Fatal("callback submitted as mail"); return nil },
		ListUnclaimed: func(context.Context) ([]relay.UnclaimedTopic, error) {
			return []relay.UnclaimedTopic{{ID: "conversation-1", DisplayName: "Ops"}}, nil
		},
		Notify: notify,
		Claims: executor,
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
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseReserved {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
	if !hasLogClass(logs, "telegram_claim_failed") || !strings.Contains(strings.Join(logs, "\n"), "phase=reserved") {
		t.Fatalf("failure logs=%#v", logs)
	}
}

func TestGatewayInvalidCallbackStaysInert(t *testing.T) {
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
		Notify:        notify,
		Now:           func() time.Time { return testCallbackNow },
		Log:           func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
	}
	if err := gateway.Handle(context.Background(), Update{ID: 2, UserID: 55, ChatID: 55, CallbackID: "cbq-1", CallbackData: "opaque-token"}); err != nil {
		t.Fatal(err)
	}
	if len(notify.answers) != 1 || notify.answers[0].text != callbackFailureText {
		t.Fatalf("answers=%#v", notify.answers)
	}
	if incomplete, err := state.IncompleteClaimExecutions(); err != nil || len(incomplete) != 0 {
		t.Fatalf("inert callback created execution: %#v err=%v", incomplete, err)
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
