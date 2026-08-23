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

func TestEventValidationAllowsOnlyPrivacySafeMetadata(t *testing.T) {
	for _, key := range []string{"prompt", "transcript", "tool_output", "last_assistant_message", "toolInput", "body", "api_key", "systemPrompt"} {
		t.Run(key, func(t *testing.T) {
			event := validEvent()
			event.Metadata[key] = "must stay local"
			if err := event.Validate(); err == nil || !strings.Contains(err.Error(), "metadata key") {
				t.Fatalf("Validate() error = %v, want metadata allowlist rejection", err)
			}
		})
	}
	for key, value := range map[string]any{"hook": "PermissionRequest", "simulated": true, "agent_type": "Explore"} {
		t.Run("allow_"+key, func(t *testing.T) {
			event := validEvent()
			event.Metadata = map[string]any{key: value}
			if err := event.Validate(); err != nil {
				t.Fatalf("Validate() rejected allowed metadata key %q: %v", key, err)
			}
		})
	}
	for _, value := range []any{true, 1, 1.5} {
		event := validEvent()
		event.Metadata = map[string]any{"agent_type": value}
		if err := event.Validate(); err == nil {
			t.Fatalf("Validate() accepted agent_type value %#v outside the wire schema", value)
		}
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

func TestDecodeEventPreservesLargeIntegerMetadataExactly(t *testing.T) {
	event := validEvent()
	event.Metadata = nil
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"task":`), []byte(`"metadata":{"simulated":9007199254740993},"task":`), 1)
	decoded, err := DecodeEvent(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(decoded.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(metadata), `{"simulated":9007199254740993}`; got != want {
		t.Fatalf("decoded metadata = %s, want %s", got, want)
	}
}

func TestDecodeEventRejectsExplicitNullMetadata(t *testing.T) {
	event := validEvent()
	event.Metadata = nil
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"task":`), []byte(`"metadata":null,"task":`), 1)
	if _, err := DecodeEvent(bytes.NewReader(payload), int64(len(payload))); err == nil {
		t.Fatal("DecodeEvent() accepted explicit null metadata")
	}
}
