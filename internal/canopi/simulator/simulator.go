// Package simulator generates realistic, privacy-safe multi-machine activity.
package simulator

import (
	"fmt"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

type simulatedAgent struct {
	title   string
	machine protocol.Machine
	state   protocol.State
	age     time.Duration
	source  protocol.Source
}

var agents = []simulatedAgent{
	{"indexino / XML parser", protocol.Machine{ID: "studio-m2", Label: "studio-m2"}, protocol.StateWaitingForUser, 2 * time.Minute, protocol.SourceCodex},
	{"Jewel / API choice", protocol.Machine{ID: "mbp-seb", Label: "mbp-seb"}, protocol.StateWaitingForUser, 18 * time.Minute, protocol.SourceClaudeCode},
	{"Spectre / permissions", protocol.Machine{ID: "linux-box", Label: "linux-box"}, protocol.StateWaitingForUser, 28 * time.Minute, protocol.SourcePi},
	{"Punaro / tests", protocol.Machine{ID: "studio-m2", Label: "studio-m2"}, protocol.StateDone, 23 * time.Minute, protocol.SourceClaudeCode},
	{"guest-pass / deploy", protocol.Machine{ID: "mbp-seb", Label: "mbp-seb"}, protocol.StateDone, 45 * time.Minute, protocol.SourceCodex},
	{"Lumos / docs", protocol.Machine{ID: "linux-box", Label: "linux-box"}, protocol.StateDone, time.Hour, protocol.SourceGrokBuild},
	{"Atlas / refactor CLI", protocol.Machine{ID: "studio-m2", Label: "studio-m2"}, protocol.StateDone, 110 * time.Minute, protocol.SourcePi},
	{"Orion / add caching", protocol.Machine{ID: "studio-m2", Label: "studio-m2"}, protocol.StateWorking, 3 * time.Minute, protocol.SourceClaudeCode},
	{"Vega / metrics API", protocol.Machine{ID: "mbp-seb", Label: "mbp-seb"}, protocol.StateWorking, 7 * time.Minute, protocol.SourceCodex},
	{"Echo / UI polish", protocol.Machine{ID: "linux-box", Label: "linux-box"}, protocol.StateWorking, 12 * time.Minute, protocol.SourceGrokBuild},
	{"Nova / billing sync", protocol.Machine{ID: "studio-m2", Label: "studio-m2"}, protocol.StateWorking, 25 * time.Minute, protocol.SourcePi},
	{"Pioneer / review", protocol.Machine{ID: "mbp-seb", Label: "mbp-seb"}, protocol.StateWorking, 26 * time.Minute, protocol.SourceClaudeCode},
	{"Canopi / renderer", protocol.Machine{ID: "studio-m2", Label: "studio-m2"}, protocol.StateWorking, 26*time.Minute + 30*time.Second, protocol.SourceCodex},
	{"Mailbox / retry queue", protocol.Machine{ID: "linux-box", Label: "linux-box"}, protocol.StateWorking, 27 * time.Minute, protocol.SourcePi},
	{"Skia / benchmark", protocol.Machine{ID: "mbp-seb", Label: "mbp-seb"}, protocol.StateWorking, 27*time.Minute + 30*time.Second, protocol.SourceGrokBuild},
	{"Relay / enrollment", protocol.Machine{ID: "studio-m2", Label: "studio-m2"}, protocol.StateWorking, 28 * time.Minute, protocol.SourceClaudeCode},
	{"Memory / evidence", protocol.Machine{ID: "linux-box", Label: "linux-box"}, protocol.StateWorking, 28*time.Minute + 30*time.Second, protocol.SourceCodex},
	{"Telegram / gateway", protocol.Machine{ID: "mbp-seb", Label: "mbp-seb"}, protocol.StateWorking, 29 * time.Minute, protocol.SourcePi},
	{"Grok / hook spike", protocol.Machine{ID: "studio-m2", Label: "studio-m2"}, protocol.StateWorking, 29*time.Minute + 30*time.Second, protocol.SourceGrokBuild},
}

// Events returns one deterministic lifecycle batch for the supplied clock tick.
func Events(now time.Time, tick int) []protocol.Event {
	events := make([]protocol.Event, 0, len(agents))
	for index, agent := range agents {
		// Vega alternates between active work and a permission wait so a running
		// simulator exercises real state changes and conditional panel refreshes.
		if index == 8 && tick%2 == 1 {
			agent.state = protocol.StateWaitingForUser
			agent.age = 0
		}
		activity := now.Add(-agent.age)
		reason := protocol.WaitingReason("")
		if agent.state == protocol.StateWaitingForUser {
			reason = protocol.WaitingReasonPermission
		}
		agentID := fmt.Sprintf("sim-agent-%02d", index+1)
		events = append(events, protocol.Event{
			SpecVersion:     protocol.SpecVersion,
			EventID:         fmt.Sprintf("sim-v2:%d:%02d", tick, index+1),
			Source:          agent.source,
			Machine:         agent.machine,
			SessionID:       agentID,
			AgentInstanceID: agentID,
			State:           agent.state,
			WaitingReason:   reason,
			ActivityAt:      activity.UTC(),
			EmittedAt:       now.UTC(),
			Task:            protocol.Task{Title: agent.title},
			Metadata:        map[string]any{"simulated": true},
		})
	}
	return events
}
