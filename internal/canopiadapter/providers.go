package canopiadapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

// MapCodexHook maps the installed Codex CLI's Claude-compatible command-hook
// payload. It deliberately reads only lifecycle identity fields, never prompts,
// transcripts, tool input, tool output, or approval text.
func MapCodexHook(raw []byte, config AdapterConfig, now time.Time) (protocol.Event, bool, error) {
	return mapSnakeCaseHook(raw, config, now, protocol.SourceCodex, "Codex")
}

// MapGrokHook maps Grok Build's camelCase lifecycle hook payload without
// retaining provider messages, tool data, or hook output.
func MapGrokHook(raw []byte, config AdapterConfig, now time.Time) (protocol.Event, bool, error) {
	if err := protocol.ValidateJSONEncoding(raw); err != nil {
		return protocol.Event{}, false, fmt.Errorf("decode Grok hook: %w", err)
	}
	var hook struct {
		SessionID        string `json:"sessionId"`
		CWD              string `json:"cwd"`
		HookEventName    string `json:"hookEventName"`
		NotificationType string `json:"notificationType"`
		AgentID          string `json:"agentId"`
		AgentType        string `json:"agentType"`
	}
	if err := json.Unmarshal(raw, &hook); err != nil {
		return protocol.Event{}, false, fmt.Errorf("decode Grok hook: %w", err)
	}
	return mapProviderLifecycle(protocol.SourceGrokBuild, "Grok Build", hook.SessionID, hook.CWD, hook.HookEventName, hook.NotificationType, hook.AgentID, hook.AgentType, config, now)
}

// MapPiLifecycle constructs a normalized Pi event from the deliberately tiny
// extension boundary. Pi's extension must not forward the prompt, system prompt,
// context, tool arguments, tool results, or assistant messages to this package.
func MapPiLifecycle(sessionID, lifecycle string, state protocol.State, reason protocol.WaitingReason, config AdapterConfig, now time.Time) (protocol.Event, error) {
	if lifecycle == "" {
		return protocol.Event{}, errors.New("pi lifecycle is required")
	}
	return newProviderEvent(protocol.SourcePi, "Pi", sessionID, "", lifecycle, state, reason, "", "", config, now)
}

func mapSnakeCaseHook(raw []byte, config AdapterConfig, now time.Time, source protocol.Source, providerName string) (protocol.Event, bool, error) {
	if err := protocol.ValidateJSONEncoding(raw); err != nil {
		return protocol.Event{}, false, fmt.Errorf("decode %s hook: %w", providerName, err)
	}
	var hook claudeHook
	if err := json.Unmarshal(raw, &hook); err != nil {
		return protocol.Event{}, false, fmt.Errorf("decode %s hook: %w", providerName, err)
	}
	return mapProviderLifecycle(source, providerName, hook.SessionID, hook.CWD, hook.HookEventName, hook.NotificationType, hook.AgentID, hook.AgentType, config, now)
}

func mapProviderLifecycle(source protocol.Source, providerName, sessionID, cwd, lifecycle, notificationType, agentID, agentType string, config AdapterConfig, now time.Time) (protocol.Event, bool, error) {
	if sessionID == "" || lifecycle == "" {
		return protocol.Event{}, false, errors.New("provider hook requires session identity and lifecycle name")
	}
	state, reason, emit := classifyProviderLifecycle(lifecycle, notificationType)
	if !emit {
		return protocol.Event{}, false, nil
	}
	event, err := newProviderEvent(source, providerName, sessionID, cwd, lifecycle, state, reason, agentID, agentType, config, now)
	return event, true, err
}

func newProviderEvent(source protocol.Source, providerName, sessionID, cwd, lifecycle string, state protocol.State, reason protocol.WaitingReason, agentID, agentType string, config AdapterConfig, now time.Time) (protocol.Event, error) {
	if config.MachineID == "" {
		return protocol.Event{}, errors.New("machine ID is required")
	}
	if sessionID == "" {
		return protocol.Event{}, errors.New("provider session identity is required")
	}
	machineLabel := config.MachineLabel
	if machineLabel == "" {
		machineLabel = truncateRunes(config.MachineID, 40)
	}
	taskTitle := config.TaskTitle
	if taskTitle == "" {
		name := filepath.Base(cwd)
		if name == "." || name == string(filepath.Separator) || name == "" {
			name = providerName
		}
		suffix := " / " + providerName
		taskTitle = truncateRunes(name, 80-len([]rune(suffix))) + suffix
	}
	if agentID == "" {
		agentID = sessionID
	}
	parentID := ""
	if agentID != sessionID {
		parentID = sessionID
	}
	eventID, err := newProviderEventID(source)
	if err != nil {
		return protocol.Event{}, err
	}
	event := protocol.Event{
		SpecVersion:           protocol.SpecVersion,
		EventID:               eventID,
		Source:                source,
		Machine:               protocol.Machine{ID: config.MachineID, Label: machineLabel},
		SessionID:             sessionID,
		AgentInstanceID:       agentID,
		ParentAgentInstanceID: parentID,
		State:                 state,
		WaitingReason:         reason,
		ActivityAt:            now.UTC(),
		EmittedAt:             now.UTC(),
		Task:                  protocol.Task{Title: taskTitle, Repository: config.Repository},
		Metadata:              map[string]any{"hook": lifecycle},
	}
	if agentType != "" {
		event.Metadata["agent_type"] = agentType
	}
	if err := event.Validate(); err != nil {
		return protocol.Event{}, err
	}
	return event, nil
}

func classifyProviderLifecycle(lifecycle, notificationType string) (protocol.State, protocol.WaitingReason, bool) {
	switch compactLifecycleName(lifecycle) {
	case "permissionrequest":
		return protocol.StateWaitingForUser, protocol.WaitingReasonPermission, true
	case "elicitation":
		return protocol.StateWaitingForUser, protocol.WaitingReasonElicitation, true
	case "elicitationresult":
		return protocol.StateWorking, "", true
	case "notification":
		switch compactLifecycleName(notificationType) {
		case "permissionprompt":
			return protocol.StateWaitingForUser, protocol.WaitingReasonPermission, true
		case "agentneedsinput", "idleprompt", "elicitationdialog":
			return protocol.StateWaitingForUser, protocol.WaitingReasonOther, true
		default:
			return "", "", false
		}
	case "stop", "subagentstop", "sessionend", "sessionshutdown":
		return protocol.StateDone, "", true
	case "taskcompleted":
		return "", "", false
	case "sessionstart", "userpromptsubmit", "pretooluse", "posttooluse", "posttoolusefailure", "posttoolbatch", "subagentstart", "taskcreated", "turnstart", "toolcall", "toolresult":
		return protocol.StateWorking, "", true
	default:
		return "", "", false
	}
}

func compactLifecycleName(value string) string {
	var compact strings.Builder
	compact.Grow(len(value))
	for _, runeValue := range strings.ToLower(value) {
		if runeValue >= 'a' && runeValue <= 'z' || runeValue >= '0' && runeValue <= '9' {
			compact.WriteRune(runeValue)
		}
	}
	return compact.String()
}
