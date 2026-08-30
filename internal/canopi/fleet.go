package canopi

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

// EncodeFleetConvergence encodes one bounded convergence event as a Canopi lifecycle event.
func EncodeFleetConvergence(generation int64, digest, state string) ([]byte, error) {
	event, err := FleetConvergenceEvent(generation, digest, state, time.Unix(1, 0).UTC())
	if err != nil {
		return nil, err
	}
	return json.Marshal(event)
}

// FleetConvergenceEvent builds a content-free lifecycle event Store.Apply accepts.
func FleetConvergenceEvent(generation int64, digest, state string, now time.Time) (protocol.Event, error) {
	if now.IsZero() {
		now = time.Unix(1, 0).UTC()
	}
	event := protocol.Event{
		SpecVersion:     protocol.SpecVersion,
		EventID:         "fleet-config-" + strconv.FormatInt(generation, 10),
		Source:          protocol.SourceOther,
		Machine:         protocol.Machine{ID: "fleet-config", Label: "fleet-config"},
		SessionID:       "fleet-config",
		AgentInstanceID: "fleet-config",
		State:           protocol.StateDone,
		ActivityAt:      now,
		EmittedAt:       now,
		Task:            protocol.Task{Title: "fleet-config"},
		Metadata: map[string]any{
			"fleet_digest":     digest,
			"fleet_state":      state,
			"fleet_generation": generation,
		},
	}
	if err := event.Validate(); err != nil {
		return protocol.Event{}, err
	}
	return event, nil
}

// ApplyFleetConvergence records one fleet-config convergence event in the dashboard store.
func (s *Store) ApplyFleetConvergence(generation int64, digest, state string, now time.Time) (ApplyResult, error) {
	event, err := FleetConvergenceEvent(generation, digest, state, now)
	if err != nil {
		return ApplyResult{}, err
	}
	return s.Apply(event)
}
