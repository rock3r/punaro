package telegram

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRunnerAdvancesOffsetAfterGatewayHandling(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	var submitted int
	runner := Runner{Poller: fakePoller{updates: []Update{{ID: 10, UserID: 55, ChatID: 100, ThreadID: 7, Text: "hello"}}}, Gateway: Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error { submitted++; return nil }}}
	next, err := runner.RunOnce(context.Background(), 10)
	if err != nil || next != 11 || submitted != 1 {
		t.Fatalf("next=%d submitted=%d err=%v", next, submitted, err)
	}
}

func TestRunnerSkipsUnboundTopicAndContinuesToLaterRoutedUpdate(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	submitted := 0
	runner := Runner{Poller: fakePoller{updates: []Update{
		{ID: 10, UserID: 55, ChatID: 100, ThreadID: 8, Text: "unbound"},
		{ID: 11, UserID: 55, ChatID: 100, ThreadID: 7, Text: "routed"},
	}}, Gateway: Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error { submitted++; return nil }}}
	next, err := runner.RunOnce(context.Background(), 10)
	if err != nil || next != 12 || submitted != 1 {
		t.Fatalf("next=%d submitted=%d err=%v", next, submitted, err)
	}
}

func TestRunnerAdvancesOffsetWhenCallbackAnswerFails(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	notify := &failingCallbackNotify{err: context.DeadlineExceeded}
	runner := Runner{Poller: fakePoller{updates: []Update{
		{ID: 20, UserID: 55, ChatID: 55, CallbackID: "cbq-old", CallbackData: "opaque-token"},
		{ID: 21, UserID: 55, ChatID: 55, ThreadID: 7, Text: "later"},
	}}, Gateway: Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error { t.Fatal("callback submitted"); return nil }, Notify: notify, Log: func(string, ...any) {}}}
	next, err := runner.RunOnce(context.Background(), 20)
	if err != nil || next != 22 {
		t.Fatalf("next=%d err=%v", next, err)
	}
	processed, err := state.Processed(20)
	if err != nil || !processed {
		t.Fatalf("failed callback answer stalled the offset: processed=%v err=%v", processed, err)
	}
}

func TestRunnerAdvancesOffsetAfterInertCallback(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	notify := &recordingNotify{}
	runner := Runner{Poller: fakePoller{updates: []Update{{ID: 20, UserID: 55, ChatID: 55, CallbackID: "cbq-1", CallbackData: "opaque-token"}}}, Gateway: Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error { t.Fatal("callback submitted"); return nil }, Notify: notify, Log: func(string, ...any) {}}}
	next, err := runner.RunOnce(context.Background(), 20)
	if err != nil || next != 21 || len(notify.answers) != 1 || notify.answers[0].text != callbackFailureText {
		t.Fatalf("next=%d answers=%#v err=%v", next, notify.answers, err)
	}
}

type fakePoller struct{ updates []Update }

func (p fakePoller) Updates(context.Context, int64) ([]Update, error) { return p.updates, nil }
