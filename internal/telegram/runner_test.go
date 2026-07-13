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

type fakePoller struct{ updates []Update }

func (p fakePoller) Updates(context.Context, int64) ([]Update, error) { return p.updates, nil }
