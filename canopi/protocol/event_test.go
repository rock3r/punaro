package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validEvent() Event {
	return Event{
		SpecVersion:     1,
		EventID:         "claude:studio-m2:session-1:permission-1",
		Source:          SourceClaudeCode,
		Machine:         Machine{ID: "studio-m2", Label: "studio-m2"},
		SessionID:       "session-1",
		AgentInstanceID: "session-1",
		State:           StateWaitingForUser,
		WaitingReason:   WaitingReasonPermission,
		ActivityAt:      time.Date(2026, 8, 23, 9, 0, 0, 0, time.UTC),
		EmittedAt:       time.Date(2026, 8, 23, 9, 0, 1, 0, time.UTC),
		Task:            Task{Title: "Punaro / tests", Repository: "rock3r/punaro"},
		Metadata:        map[string]any{"hook": "PermissionRequest"},
	}
}

func TestEventValidationAcceptsTransportNeutralEvent(t *testing.T) {
	event := validEvent()
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got, want := event.Key(), "claude_code\x00studio-m2\x00session-1"; got != want {
		t.Fatalf("Key() = %q, want %q", got, want)
	}
}

func TestEventValidationRejectsSensitiveMetadata(t *testing.T) {
	for _, key := range []string{"prompt", "transcript", "tool_output", "last_assistant_message"} {
		t.Run(key, func(t *testing.T) {
			event := validEvent()
			event.Metadata[key] = "must stay local"
			if err := event.Validate(); err == nil || !strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("Validate() error = %v, want sensitive metadata rejection", err)
			}
		})
	}
}

func TestDecodeEventIsStrictAndBounded(t *testing.T) {
	event := validEvent()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"spec_version":1`), []byte(`"spec_version":1,"unexpected":true`), 1)
	if _, err := DecodeEvent(bytes.NewReader(payload), int64(len(payload))); err == nil {
		t.Fatal("DecodeEvent() accepted an unknown field")
	}
	if _, err := DecodeEvent(bytes.NewReader(make([]byte, 1025)), 1024); err == nil {
		t.Fatal("DecodeEvent() accepted an oversized body")
	}
}
