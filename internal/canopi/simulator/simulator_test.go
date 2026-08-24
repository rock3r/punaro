package simulator

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"github.com/rock3r/punaro/internal/canopi"
)

func TestEventsModelRealisticMultiMachineOverflow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	events := Events(now, 0, "run-a")
	if len(events) != 19 {
		t.Fatalf("len(Events) = %d, want 19", len(events))
	}
	machines := map[string]struct{}{}
	counts := map[protocol.State]int{}
	for _, event := range events {
		if err := event.Validate(); err != nil {
			t.Fatalf("event %q invalid: %v", event.EventID, err)
		}
		machines[event.Machine.ID] = struct{}{}
		counts[event.State]++
		payload, _ := json.Marshal(event)
		for _, forbidden := range []string{"prompt", "transcript", "tool_output"} {
			if json.Valid(payload) && contains(payload, forbidden) {
				t.Fatalf("event contains forbidden private field %q: %s", forbidden, payload)
			}
		}
	}
	if len(machines) < 3 {
		t.Fatalf("machine count = %d, want at least 3", len(machines))
	}
	if counts[protocol.StateWaitingForUser] != 3 || counts[protocol.StateDone] != 4 || counts[protocol.StateWorking] != 12 {
		t.Fatalf("state counts = %#v", counts)
	}
	store := canopi.NewStore(canopi.DefaultConfig())
	for _, event := range events {
		_, _ = store.Apply(event)
	}
	if got := store.Snapshot(now).Totals.Waiting; got != 3 {
		t.Fatalf("waiting agents surviving default TTL = %d, want 3", got)
	}
	page, err := canopi.Paginate(events, canopi.GridConfig{Columns: 2, Rows: 6})
	if err != nil {
		t.Fatal(err)
	}
	wantVisibleWorking := []string{"Orion / add caching", "Vega / metrics API", "Echo / UI polish", "Nova / billing sync"}
	for index, want := range wantVisibleWorking {
		if got := page.Agents[7+index].Task.Title; got != want {
			t.Fatalf("visible working agent %d = %q, want %q", index, got, want)
		}
	}
}

func TestEventsAdvanceAWaitingAndResumeLifecycleAcrossTicks(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	working := Events(now, 0, "run-a")[8]
	waiting := Events(now.Add(8*time.Second), 1, "run-a")[8]
	resumed := Events(now.Add(16*time.Second), 2, "run-a")[8]

	if working.State != protocol.StateWorking {
		t.Fatalf("tick 0 state = %q, want working", working.State)
	}
	if waiting.State != protocol.StateWaitingForUser || waiting.WaitingReason != protocol.WaitingReasonPermission {
		t.Fatalf("tick 1 state = %q/%q, want waiting_for_user/permission", waiting.State, waiting.WaitingReason)
	}
	if resumed.State != protocol.StateWorking || resumed.WaitingReason != "" {
		t.Fatalf("tick 2 state = %q/%q, want working with no waiting reason", resumed.State, resumed.WaitingReason)
	}
	if waiting.ActivityAt != now.Add(8*time.Second) {
		t.Fatalf("waiting activity = %s, want current tick time", waiting.ActivityAt)
	}
	if resumed.ActivityAt != now.Add(16*time.Second) {
		t.Fatalf("resumed activity = %s, want current tick time", resumed.ActivityAt)
	}
	if working.EventID == waiting.EventID || waiting.EventID == resumed.EventID {
		t.Fatal("lifecycle ticks must have unique event IDs")
	}
	if waiting.EventID != "sim-v3:run-a:1:09" {
		t.Fatalf("waiting event ID = %q, want versioned simulator ID", waiting.EventID)
	}
}

func TestEventsScopeIDsToSimulatorRun(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	first := Events(now, 0, "run-a")[0]
	second := Events(now, 0, "run-b")[0]
	if first.EventID == second.EventID {
		t.Fatalf("separate runs reused event ID %q", first.EventID)
	}
}

func contains(payload []byte, value string) bool {
	for index := 0; index+len(value) <= len(payload); index++ {
		if string(payload[index:index+len(value)]) == value {
			return true
		}
	}
	return false
}
