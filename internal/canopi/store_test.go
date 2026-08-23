package canopi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	store.now = func() time.Time { return now }
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
	store.now = func() time.Time { return now }
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
	store.now = func() time.Time { return now }
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
	store.now = func() time.Time { return now }
	_, _ = store.Apply(event("working", "working", protocol.StateWorking, now.Add(-31*time.Minute)))
	_, _ = store.Apply(event("waiting", "waiting", protocol.StateWaitingForUser, now.Add(-29*time.Minute)))
	_, _ = store.Apply(event("done-keep", "done-keep", protocol.StateDone, now.Add(-119*time.Minute)))
	_, _ = store.Apply(event("done-expire", "done-expire", protocol.StateDone, now.Add(-121*time.Minute)))
	got := store.Snapshot(now).Agents
	if len(got) != 2 || got[0].AgentInstanceID != "waiting" || got[1].AgentInstanceID != "done-keep" {
		t.Fatalf("Agents = %#v, want waiting and retained done", got)
	}
}

func TestSnapshotRetainsExpiredRecordWhenPersistenceFails(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	config := DefaultConfig()
	config.WorkingTTL = 30 * time.Minute
	store := NewStore(config)
	store.now = func() time.Time { return now }
	if _, err := store.Apply(event("working", "agent", protocol.StateWorking, now)); err != nil {
		t.Fatal(err)
	}
	store.persist = func(persistedStore) error { return errors.New("simulated persistence failure") }
	snapshot := store.Snapshot(now.Add(31 * time.Minute))
	if len(snapshot.Agents) != 1 || snapshot.Agents[0].AgentInstanceID != "agent" {
		t.Fatalf("Snapshot() hid undurably expired record: %#v", snapshot.Agents)
	}
	if snapshot.Revision != 1 || store.Revision() != 1 {
		t.Fatalf("expiry failure revision = %d/%d, want 1/1", snapshot.Revision, store.Revision())
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

func TestOpenStoreRejectsStateFileBeyondConfiguredBoundBeforeReading(t *testing.T) {
	config := DefaultConfig()
	config.MaxLiveRecords = 1
	path := filepath.Join(t.TempDir(), "oversized-state.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxStateFileBytes(config.MaxLiveRecords)+1); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path, config); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("OpenStore() error = %v, want bounded state-file rejection", err)
	}
}

func TestMaxStateFileBytesAccountsForWorstCaseJSONEscaping(t *testing.T) {
	wantMinimum := int64(persistedStateEnvelopeBytes) +
		int64(maxPersistedEventBytes*maxJSONEncodedExpansion) +
		int64(maxRememberedEventIDs*maxSerializedEventIDBytes)
	if got := maxStateFileBytes(1); got < wantMinimum {
		t.Fatalf("maxStateFileBytes(1) = %d, want at least %d", got, wantMinimum)
	}
}

func TestPersistStoreReclaimsCrashLeftTemporary(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	orphan := filepath.Join(directory, stateTemporaryPrefix(path)+"crashed")
	if err := os.WriteFile(orphan, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistStore(path, persistedStore{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crash-left state temporary still exists: %v", err)
	}
}

func TestPersistStoreDoesNotReclaimAnotherStateFilesTemporary(t *testing.T) {
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first.json")
	secondPath := filepath.Join(directory, "second.json")
	secondTemporary := filepath.Join(directory, stateTemporaryPrefix(secondPath)+"active")
	if err := os.WriteFile(secondTemporary, []byte("in progress"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistStore(firstPath, persistedStore{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(secondTemporary); err != nil {
		t.Fatalf("another state file's active temporary was removed: %v", err)
	}
}

func TestApplyPersistenceFailureDoesNotAcknowledgeOrMutate(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	store := NewStore(DefaultConfig())
	store.now = func() time.Time { return now }
	persistCalls := 0
	store.persist = func(persistedStore) error {
		persistCalls++
		if persistCalls == 1 {
			return errors.New("simulated persistence failure")
		}
		return nil
	}
	input := event("event-retry", "agent", protocol.StateWorking, now)
	if result, err := store.Apply(input); err == nil || result != (ApplyResult{}) {
		t.Fatalf("failed Apply() = %+v, %v", result, err)
	}
	if store.Revision() != 0 || len(store.Snapshot(now).Agents) != 0 {
		t.Fatal("failed persistence mutated acknowledged in-memory state")
	}
	if result, err := store.Apply(input); err != nil || !result.Applied {
		t.Fatalf("retry Apply() = %+v, %v", result, err)
	}
}

func TestApplyBoundsLiveRecordsButAllowsExistingAgentUpdates(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	config := DefaultConfig()
	config.MaxLiveRecords = 2
	store := NewStore(config)
	store.now = func() time.Time { return now }
	for _, input := range []protocol.Event{
		event("event-a", "agent-a", protocol.StateWorking, now),
		event("event-b", "agent-b", protocol.StateWorking, now),
	} {
		if result, err := store.Apply(input); err != nil || !result.Applied {
			t.Fatalf("Apply(%s) = %+v, %v", input.EventID, result, err)
		}
	}
	if _, err := store.Apply(event("event-c", "agent-c", protocol.StateWorking, now)); !errors.Is(err, ErrLiveRecordLimit) {
		t.Fatalf("third agent error = %v, want ErrLiveRecordLimit", err)
	}
	if result, err := store.Apply(event("event-a-done", "agent-a", protocol.StateDone, now.Add(time.Second))); err != nil || !result.Applied {
		t.Fatalf("existing agent update = %+v, %v", result, err)
	}
}

func TestApplyExpiresStaleRecordsBeforeCapacityAdmission(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	config := DefaultConfig()
	config.MaxLiveRecords = 1
	store := NewStore(config)
	store.now = func() time.Time { return now }
	if result, err := store.Apply(event("expired", "expired-agent", protocol.StateWorking, now.Add(-config.WorkingTTL-time.Second))); err != nil || !result.Applied {
		t.Fatalf("Apply(expired record) = %+v, %v", result, err)
	}
	if result, err := store.Apply(event("replacement", "replacement-agent", protocol.StateWorking, now)); err != nil || !result.Applied {
		t.Fatalf("Apply(replacement) = %+v, %v", result, err)
	}
	agents := store.Snapshot(now).Agents
	if len(agents) != 1 || agents[0].AgentInstanceID != "replacement-agent" {
		t.Fatalf("Agents = %#v, want only replacement-agent", agents)
	}
}

func TestApplyRejectsActivityBeyondConfiguredClockSkew(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	config := DefaultConfig()
	config.MaxFutureSkew = 5 * time.Minute
	store := NewStore(config)
	store.now = func() time.Time { return now }
	if _, err := store.Apply(event("future", "agent", protocol.StateWorking, now.Add(5*time.Minute+time.Nanosecond))); !errors.Is(err, ErrFutureActivity) {
		t.Fatalf("future event error = %v, want ErrFutureActivity", err)
	}
	if result, err := store.Apply(event("boundary", "agent", protocol.StateWorking, now.Add(5*time.Minute))); err != nil || !result.Applied {
		t.Fatalf("boundary event = %+v, %v", result, err)
	}
}

func TestApplyAcknowledgesDurableDuplicateAfterClockRollback(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	config := DefaultConfig()
	store := NewStore(config)
	store.now = func() time.Time { return now }
	input := event("boundary", "agent", protocol.StateWorking, now.Add(config.MaxFutureSkew))
	if result, err := store.Apply(input); err != nil || !result.Applied {
		t.Fatalf("initial Apply() = %+v, %v", result, err)
	}
	now = now.Add(-time.Minute)
	if result, err := store.Apply(input); err != nil || !result.Duplicate {
		t.Fatalf("duplicate after rollback = %+v, %v", result, err)
	}
}
