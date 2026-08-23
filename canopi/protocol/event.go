// Package protocol defines Canopi's transport-neutral coding-agent lifecycle
// event. It deliberately contains no Punaro transport or authentication types.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
	"unicode/utf8"
)

// SpecVersion is the current normalized lifecycle-event schema version.
const SpecVersion = 1

// Source identifies the coding-agent provider that emitted an event.
type Source string

// Supported event sources. Other preserves forward-compatible custom adapters.
const (
	SourcePi         Source = "pi"
	SourceClaudeCode Source = "claude_code"
	SourceCodex      Source = "codex"
	SourceGrokBuild  Source = "grok_build"
	SourceOther      Source = "other"
)

// State is the normalized current lifecycle state of an agent instance.
type State string

// Supported normalized lifecycle states, in no particular display order.
const (
	StateWorking        State = "working"
	StateWaitingForUser State = "waiting_for_user"
	StateDone           State = "done"
)

// WaitingReason describes why an agent needs user attention.
type WaitingReason string

// Supported reasons for the waiting-for-user state.
const (
	WaitingReasonPermission  WaitingReason = "permission"
	WaitingReasonQuestion    WaitingReason = "question"
	WaitingReasonElicitation WaitingReason = "elicitation"
	WaitingReasonApproval    WaitingReason = "approval"
	WaitingReasonOther       WaitingReason = "other"
)

// Machine identifies the host on which an agent instance is running.
type Machine struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Task contains the privacy-safe display identity of an agent's work.
type Task struct {
	Title            string `json:"title"`
	Repository       string `json:"repository,omitempty"`
	WorkingDirectory string `json:"working_directory,omitempty"`
}

// Event is the transport-neutral normalized lifecycle event.
type Event struct {
	SpecVersion           int            `json:"spec_version"`
	EventID               string         `json:"event_id"`
	Source                Source         `json:"source"`
	Machine               Machine        `json:"machine"`
	SessionID             string         `json:"session_id"`
	AgentInstanceID       string         `json:"agent_instance_id"`
	ParentAgentInstanceID string         `json:"parent_agent_instance_id,omitempty"`
	State                 State          `json:"state"`
	WaitingReason         WaitingReason  `json:"waiting_reason,omitempty"`
	ActivityAt            time.Time      `json:"activity_at"`
	EmittedAt             time.Time      `json:"emitted_at"`
	Task                  Task           `json:"task"`
	Metadata              map[string]any `json:"metadata,omitempty"`
}

var machineIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

var allowedMetadataKeys = map[string]struct{}{
	"agent_type": {},
	"hook":       {},
	"simulated":  {},
}

// Key returns the stable identity used to track an agent across events.
func (e Event) Key() string {
	return string(e.Source) + "\x00" + e.Machine.ID + "\x00" + e.AgentInstanceID
}

// Validate checks the protocol, bounds, state consistency, and privacy rules.
func (e Event) Validate() error {
	if e.SpecVersion != SpecVersion {
		return fmt.Errorf("spec_version must be %d", SpecVersion)
	}
	if err := bounded("event_id", e.EventID, 1, 200); err != nil {
		return err
	}
	switch e.Source {
	case SourcePi, SourceClaudeCode, SourceCodex, SourceGrokBuild, SourceOther:
	default:
		return fmt.Errorf("unsupported source %q", e.Source)
	}
	if err := bounded("machine.id", e.Machine.ID, 1, 100); err != nil {
		return err
	}
	if !machineIDPattern.MatchString(e.Machine.ID) {
		return errors.New("machine.id contains unsupported characters")
	}
	if err := bounded("machine.label", e.Machine.Label, 1, 40); err != nil {
		return err
	}
	if err := bounded("session_id", e.SessionID, 1, 300); err != nil {
		return err
	}
	if err := bounded("agent_instance_id", e.AgentInstanceID, 1, 300); err != nil {
		return err
	}
	if e.ParentAgentInstanceID != "" {
		if err := bounded("parent_agent_instance_id", e.ParentAgentInstanceID, 1, 300); err != nil {
			return err
		}
	}
	switch e.State {
	case StateWorking, StateWaitingForUser, StateDone:
	default:
		return fmt.Errorf("unsupported state %q", e.State)
	}
	if e.WaitingReason != "" {
		switch e.WaitingReason {
		case WaitingReasonPermission, WaitingReasonQuestion, WaitingReasonElicitation, WaitingReasonApproval, WaitingReasonOther:
		default:
			return fmt.Errorf("unsupported waiting_reason %q", e.WaitingReason)
		}
	}
	if e.State != StateWaitingForUser && e.WaitingReason != "" {
		return errors.New("waiting_reason is only valid for waiting_for_user")
	}
	if e.ActivityAt.IsZero() || e.EmittedAt.IsZero() {
		return errors.New("activity_at and emitted_at are required")
	}
	if err := bounded("task.title", e.Task.Title, 1, 80); err != nil {
		return err
	}
	if utf8.RuneCountInString(e.Task.Repository) > 300 {
		return errors.New("task.repository exceeds 300 characters")
	}
	if utf8.RuneCountInString(e.Task.WorkingDirectory) > 1000 {
		return errors.New("task.working_directory exceeds 1000 characters")
	}
	for key, value := range e.Metadata {
		if _, allowed := allowedMetadataKeys[key]; !allowed {
			return fmt.Errorf("metadata key %q is not allowed", key)
		}
		if key == "agent_type" {
			if _, valid := value.(string); value != nil && !valid {
				return errors.New("metadata agent_type must be a string or null")
			}
			continue
		}
		if !isPrimitiveMetadata(value) {
			return fmt.Errorf("metadata %q must contain a primitive value", key)
		}
	}
	return nil
}

func isPrimitiveMetadata(value any) bool {
	switch value.(type) {
	case nil, string, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, bool:
		return true
	default:
		return false
	}
}

// DecodeEvent strictly decodes one bounded event and rejects unknown fields.
func DecodeEvent(reader io.Reader, maxBytes int64) (Event, error) {
	if maxBytes <= 0 {
		return Event{}, errors.New("maxBytes must be positive")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return Event{}, fmt.Errorf("read event: %w", err)
	}
	if int64(len(payload)) > maxBytes {
		return Event{}, fmt.Errorf("event exceeds %d bytes", maxBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var event Event
	if err := decoder.Decode(&event); err != nil {
		return Event{}, fmt.Errorf("decode event: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Event{}, errors.New("event must contain exactly one JSON object")
	}
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	return event, nil
}

func bounded(name, value string, minLength, maxLength int) error {
	length := utf8.RuneCountInString(value)
	if length < minLength || length > maxLength {
		return fmt.Errorf("%s length must be between %d and %d", name, minLength, maxLength)
	}
	return nil
}
