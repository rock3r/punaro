package canopi

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

func event(id, agent string, state protocol.State, activity time.Time) protocol.Event {
	return protocol.Event{
		SpecVersion: 1, EventID: id, Source: protocol.SourceClaudeCode,
		Machine:   protocol.Machine{ID: "studio-m2", Label: "studio-m2"},
		SessionID: agent, AgentInstanceID: agent, State: state,
		ActivityAt: activity, EmittedAt: activity,
		Task: protocol.Task{Title: agent}, Metadata: map[string]any{"hook": "test"},
	}
}

func TestSnapshotSortsAllRecordsByStateThenRecentActivity(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	store := NewStore(Config{WorkingTTL: time.Hour, DoneRetention: 2 * time.Hour})
	inputs := []protocol.Event{
		event("working-new", "working-new", protocol.StateWorking, now.Add(-time.Minute)),
		event("done-old", "done-old", protocol.StateDone, now.Add(-20*time.Minute)),
		event("waiting-old", "waiting-old", protocol.StateWaitingForUser, now.Add(-30*time.Minute)),
		event("done-new", "done-new", protocol.StateDone, now.Add(-2*time.Minute)),
		event("waiting-new", "waiting-new", protocol.StateWaitingForUser, now.Add(-3*time.Minute)),
	}
	for _, input := range inputs {
		if result, err := store.Apply(input); err != nil || !result.Applied {
			t.Fatalf("Apply(%s) = %+v, %v", input.EventID, result, err)
		}
	}
	got := store.Snapshot(now).Agents
	want := []string{"waiting-new", "waiting-old", "done-new", "done-old", "working-new"}
	if len(got) != len(want) {
		t.Fatalf("len(Agents) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].AgentInstanceID != want[i] {
			t.Errorf("Agents[%d] = %q, want %q", i, got[i].AgentInstanceID, want[i])
		}
	}
}

func TestApplyIsIdempotentAndRejectsOutOfOrderUpdates(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	store := NewStore(DefaultConfig())
	newer := event("event-2", "agent", protocol.StateDone, now)
	if result, err := store.Apply(newer); err != nil || !result.Applied {
		t.Fatalf("first Apply() = %+v, %v", result, err)
	}
	firstRevision := store.Revision()
	if result, err := store.Apply(newer); err != nil || !result.Duplicate || result.Applied {
		t.Fatalf("duplicate Apply() = %+v, %v", result, err)
	}
	if store.Revision() != firstRevision {
		t.Fatal("duplicate event changed the revision")
	}
	older := event("event-3", "agent", protocol.StateWorking, now.Add(-time.Second))
	if result, err := store.Apply(older); err != nil || !result.Stale || result.Applied {
		t.Fatalf("older Apply() = %+v, %v", result, err)
	}
	if got := store.Snapshot(now).Agents[0].State; got != protocol.StateDone {
		t.Fatalf("state = %q, want done", got)
	}
}

func TestApplyUsesEventIDAsEqualTimestampTieBreaker(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	store := NewStore(DefaultConfig())
	_, _ = store.Apply(event("event-b", "agent", protocol.StateDone, now))
	result, err := store.Apply(event("event-a", "agent", protocol.StateWorking, now))
	if err != nil || !result.Stale {
		t.Fatalf("Apply(lower tie breaker) = %+v, %v", result, err)
	}
	result, err = store.Apply(event("event-c", "agent", protocol.StateWaitingForUser, now))
	if err != nil || !result.Applied {
		t.Fatalf("Apply(higher tie breaker) = %+v, %v", result, err)
	}
}

func TestSnapshotExpiresNonTerminalAndRetainsDoneIndependently(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	store := NewStore(Config{WorkingTTL: 30 * time.Minute, DoneRetention: 2 * time.Hour})
	_, _ = store.Apply(event("working", "working", protocol.StateWorking, now.Add(-31*time.Minute)))
	_, _ = store.Apply(event("waiting", "waiting", protocol.StateWaitingForUser, now.Add(-29*time.Minute)))
	_, _ = store.Apply(event("done-keep", "done-keep", protocol.StateDone, now.Add(-119*time.Minute)))
	_, _ = store.Apply(event("done-expire", "done-expire", protocol.StateDone, now.Add(-121*time.Minute)))
	got := store.Snapshot(now).Agents
	if len(got) != 2 || got[0].AgentInstanceID != "waiting" || got[1].AgentInstanceID != "done-keep" {
		t.Fatalf("Agents = %#v, want waiting and retained done", got)
	}
}

func TestPersistentStoreSurvivesRestartAndKeepsDedupe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	store, err := OpenStore(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	input := event("event-1", "agent", protocol.StateWorking, now)
	if result, err := store.Apply(input); err != nil || !result.Applied {
		t.Fatalf("Apply() = %+v, %v", result, err)
	}
	reopened, err := OpenStore(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := reopened.Apply(input); err != nil || !result.Duplicate {
		t.Fatalf("Apply() after restart = %+v, %v", result, err)
	}
}
