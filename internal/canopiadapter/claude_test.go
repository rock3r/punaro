package canopiadapter

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

func TestMapClaudeHookUsesInstalledPermissionSchemaWithoutPrivateContent(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","transcript_path":"/private/transcript.jsonl","cwd":"/src/punaro","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"secret command"}}`)
	event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: "studio-m2", MachineLabel: "Studio M2", TaskTitle: "Punaro / tests", EventIDKey: []byte("test-secret")}, time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	if err != nil || !emit {
		t.Fatalf("MapClaudeHook() = %+v, %t, %v", event, emit, err)
	}
	if event.State != protocol.StateWaitingForUser || event.WaitingReason != protocol.WaitingReasonPermission {
		t.Fatalf("state = %q, reason = %q", event.State, event.WaitingReason)
	}
	encoded, _ := json.Marshal(event)
	for _, private := range []string{"secret command", "transcript.jsonl", "tool_input"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("normalized event leaked %q: %s", private, encoded)
		}
	}
}

func TestMapClaudeHookDoesNotLetAssistantTextOverrideTerminalHook(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"Stop","stop_hook_active":false,"last_assistant_message":"I need one choice before I can continue. Which database should I use?"}`)
	event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / choice", EventIDKey: []byte("test-secret")}, time.Now())
	if err != nil || !emit {
		t.Fatalf("MapClaudeHook() = %+v, %t, %v", event, emit, err)
	}
	if event.State != protocol.StateDone || event.WaitingReason != "" {
		t.Fatalf("state = %q, reason = %q", event.State, event.WaitingReason)
	}
	encoded, _ := json.Marshal(event)
	if strings.Contains(string(encoded), "Which database") {
		t.Fatalf("normalized event leaked final assistant text: %s", encoded)
	}
}

func TestMapClaudeHookIgnoresTaskCompletedWithoutTaskIdentity(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"TaskCompleted","task_id":"task-1"}`)
	if event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / tests", EventIDKey: []byte("test-secret")}, time.Now()); err != nil || emit || event.EventID != "" {
		t.Fatalf("MapClaudeHook(TaskCompleted) = %+v, %t, %v", event, emit, err)
	}
}

func TestMapClaudeHookEventIDDistinguishesSeparateIdenticalInvocations(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"toolu_1","tool_response":{"output":"private"}}`)
	config := AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / tests", EventIDKey: []byte("test-secret")}
	first, _, err := MapClaudeHook(raw, config, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := MapClaudeHook(raw, config, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if first.EventID == second.EventID {
		t.Fatalf("separate identical invocations collapsed to event ID %q", first.EventID)
	}
}

func TestMapClaudeHookEventIDRemainsBoundedForLongValidIdentity(t *testing.T) {
	raw := []byte(`{"session_id":"` + strings.Repeat("s", 300) + `","cwd":"/src/punaro","hook_event_name":"SessionStart"}`)
	event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: strings.Repeat("m", 100), MachineLabel: "machine", TaskTitle: "Punaro / tests", EventIDKey: []byte("test-secret")}, time.Now())
	if err != nil || !emit {
		t.Fatalf("MapClaudeHook(long identity) = %+v, %t, %v", event, emit, err)
	}
	if len(event.EventID) > 200 {
		t.Fatalf("event ID length = %d, want <= 200", len(event.EventID))
	}
}

func TestMapClaudeHookRequiresSecretEventIDKey(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"UserPromptSubmit","prompt":"private"}`)
	if _, _, err := MapClaudeHook(raw, AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / tests"}, time.Now()); err == nil {
		t.Fatal("MapClaudeHook() accepted an unkeyed digest of private hook input")
	}
}

func TestMapClaudeSubagentIncludesPrivacySafeAgentType(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"SubagentStart","agent_id":"agent-1","agent_type":"Explore"}`)
	event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / tests", EventIDKey: []byte("test-secret")}, time.Now())
	if err != nil || !emit {
		t.Fatalf("MapClaudeHook() = %+v, %t, %v", event, emit, err)
	}
	if event.Metadata["agent_type"] != "Explore" || event.ParentAgentInstanceID != "session-1" {
		t.Fatalf("subagent metadata/parent = %#v/%q", event.Metadata, event.ParentAgentInstanceID)
	}
}
