package telegram

import (
	"path/filepath"
	"testing"
)

func TestStateClaimsUpdatesOnceAndRequiresExplicitTopicRoute(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	claimed, err := state.ClaimUpdate(42)
	if err != nil || !claimed {
		t.Fatalf("first claim=%v err=%v", claimed, err)
	}
	claimed, err = state.ClaimUpdate(42)
	if err != nil || claimed {
		t.Fatalf("duplicate claim=%v err=%v", claimed, err)
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
}
