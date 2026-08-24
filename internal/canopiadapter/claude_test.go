package canopiadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

func TestDeliverRejectsPlaintextNonLoopbackEndpoint(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("plaintext non-loopback request reached the transport")
		return nil, nil
	})}
	if err := Deliver(context.Background(), client, "http://192.0.2.40:8090", "token", spoolEvent("event-1")); err == nil {
		t.Fatal("Deliver() accepted a plaintext non-loopback endpoint")
	}
}

func TestDeliverDoesNotForwardBearerAcrossRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("redirect target received the bearer-authenticated request")
	}))
	defer target.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	err := Deliver(context.Background(), origin.Client(), origin.URL, "token", spoolEvent("event-redirect"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("Deliver() redirect error = %v, want rejected HTTP 307", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestMapClaudeHookUsesInstalledPermissionSchemaWithoutPrivateContent(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","transcript_path":"/private/transcript.jsonl","cwd":"/src/punaro","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"secret command"}}`)
	event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: "studio-m2", MachineLabel: "Studio M2", TaskTitle: "Punaro / tests"}, time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
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
	event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / choice"}, time.Now())
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

func TestMapClaudeElicitationResultClearsWaitingState(t *testing.T) {
	config := AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / choice"}
	waiting, emit, err := MapClaudeHook([]byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"Elicitation"}`), config, time.Now())
	if err != nil || !emit || waiting.State != protocol.StateWaitingForUser || waiting.WaitingReason != protocol.WaitingReasonElicitation {
		t.Fatalf("MapClaudeHook(Elicitation) = %+v, %t, %v", waiting, emit, err)
	}
	resumed, emit, err := MapClaudeHook([]byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"ElicitationResult"}`), config, time.Now())
	if err != nil || !emit || resumed.State != protocol.StateWorking || resumed.WaitingReason != "" {
		t.Fatalf("MapClaudeHook(ElicitationResult) = %+v, %t, %v", resumed, emit, err)
	}
}

func TestClaudeHookExampleSubscribesToElicitationResult(t *testing.T) {
	payload, err := os.ReadFile("../../canopi/providers/claude-code-hooks.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Hooks map[string]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(payload, &config); err != nil {
		t.Fatal(err)
	}
	if _, subscribed := config.Hooks["ElicitationResult"]; !subscribed {
		t.Fatal("Claude hook example does not subscribe to ElicitationResult")
	}
}

func TestMapClaudeHookIgnoresTaskCompletedWithoutTaskIdentity(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"TaskCompleted","task_id":"task-1"}`)
	if event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / tests"}, time.Now()); err != nil || emit || event.EventID != "" {
		t.Fatalf("MapClaudeHook(TaskCompleted) = %+v, %t, %v", event, emit, err)
	}
}

func TestMapClaudeHookEventIDDistinguishesSeparateIdenticalInvocations(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"toolu_1","tool_response":{"output":"private"}}`)
	config := AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / tests"}
	first, _, err := MapClaudeHook(raw, config, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := MapClaudeHook(raw, config, time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if first.EventID == second.EventID {
		t.Fatalf("separate identical invocations collapsed to event ID %q", first.EventID)
	}
}

func TestMapClaudeHookEventIDRemainsBoundedForLongValidIdentity(t *testing.T) {
	raw := []byte(`{"session_id":"` + strings.Repeat("s", 300) + `","cwd":"/src/punaro","hook_event_name":"SessionStart"}`)
	event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: strings.Repeat("m", 100), MachineLabel: "machine", TaskTitle: "Punaro / tests"}, time.Now())
	if err != nil || !emit {
		t.Fatalf("MapClaudeHook(long identity) = %+v, %t, %v", event, emit, err)
	}
	if len(event.EventID) > 200 {
		t.Fatalf("event ID length = %d, want <= 200", len(event.EventID))
	}
}

func TestMapClaudeHookBoundsDerivedDisplayFields(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/` + strings.Repeat("x", 120) + `","hook_event_name":"SessionStart"}`)
	event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: strings.Repeat("m", 100)}, time.Now())
	if err != nil || !emit {
		t.Fatalf("MapClaudeHook(long defaults) = %+v, %t, %v", event, emit, err)
	}
	if got := len([]rune(event.Machine.Label)); got != 40 {
		t.Fatalf("derived machine label length = %d, want 40", got)
	}
	if got := len([]rune(event.Task.Title)); got != 80 {
		t.Fatalf("derived task title length = %d, want 80", got)
	}
}

func TestMapClaudeHookUsesOpaqueRandomEventIDWithoutBearerKey(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"UserPromptSubmit","prompt":"private"}`)
	event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / tests"}, time.Now())
	if err != nil || !emit {
		t.Fatalf("MapClaudeHook() = %+v, %t, %v", event, emit, err)
	}
	if !strings.HasPrefix(event.EventID, "claude_code:") || len(event.EventID) != len("claude_code:")+64 {
		t.Fatalf("event ID = %q, want opaque 256-bit identifier", event.EventID)
	}
	source, err := os.ReadFile("claude.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"EventIDKey", "hmac.New", "digest.Write(raw)"} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("event ID source still depends on private hook material via %q", forbidden)
		}
	}
}

func TestMapClaudeSubagentIncludesPrivacySafeAgentType(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"SubagentStart","agent_id":"agent-1","agent_type":"Explore"}`)
	event, emit, err := MapClaudeHook(raw, AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / tests"}, time.Now())
	if err != nil || !emit {
		t.Fatalf("MapClaudeHook() = %+v, %t, %v", event, emit, err)
	}
	if event.Metadata["agent_type"] != "Explore" || event.ParentAgentInstanceID != "session-1" {
		t.Fatalf("subagent metadata/parent = %#v/%q", event.Metadata, event.ParentAgentInstanceID)
	}
}
