// Package canopiadapter maps provider-specific hooks to normalized events.
package canopiadapter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

// AdapterConfig supplies privacy-safe local identity and event-ID keying.
type AdapterConfig struct {
	MachineID    string
	MachineLabel string
	TaskTitle    string
	Repository   string
	EventIDKey   []byte
}

type claudeHook struct {
	SessionID        string `json:"session_id"`
	CWD              string `json:"cwd"`
	HookEventName    string `json:"hook_event_name"`
	NotificationType string `json:"notification_type"`
	AgentID          string `json:"agent_id"`
	AgentType        string `json:"agent_type"`
}

// MapClaudeHook maps a current Claude Code hook payload without forwarding it.
func MapClaudeHook(raw []byte, config AdapterConfig, now time.Time) (protocol.Event, bool, error) {
	if config.MachineID == "" {
		return protocol.Event{}, false, errors.New("machine ID is required")
	}
	if len(config.EventIDKey) == 0 {
		return protocol.Event{}, false, errors.New("secret event ID key is required")
	}
	var hook claudeHook
	if err := json.Unmarshal(raw, &hook); err != nil {
		return protocol.Event{}, false, fmt.Errorf("decode Claude hook: %w", err)
	}
	if hook.SessionID == "" || hook.HookEventName == "" {
		return protocol.Event{}, false, errors.New("claude hook requires session_id and hook_event_name")
	}
	state, reason, emit := classifyClaudeHook(hook)
	if !emit {
		return protocol.Event{}, false, nil
	}
	machineLabel := config.MachineLabel
	if machineLabel == "" {
		machineLabel = truncateRunes(config.MachineID, 40)
	}
	taskTitle := config.TaskTitle
	if taskTitle == "" {
		name := filepath.Base(hook.CWD)
		if name == "." || name == string(filepath.Separator) || name == "" {
			name = "Claude Code"
		}
		const suffix = " / Claude"
		taskTitle = truncateRunes(name, 80-len([]rune(suffix))) + suffix
	}
	agentID := hook.AgentID
	parentID := ""
	if agentID == "" {
		agentID = hook.SessionID
	} else {
		parentID = hook.SessionID
	}
	digest := hmac.New(sha256.New, config.EventIDKey)
	_, _ = digest.Write([]byte(config.MachineID))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(raw)
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(now.UTC().Format(time.RFC3339Nano)))
	event := protocol.Event{
		SpecVersion:           protocol.SpecVersion,
		EventID:               "claude_code:" + hex.EncodeToString(digest.Sum(nil)),
		Source:                protocol.SourceClaudeCode,
		Machine:               protocol.Machine{ID: config.MachineID, Label: machineLabel},
		SessionID:             hook.SessionID,
		AgentInstanceID:       agentID,
		ParentAgentInstanceID: parentID,
		State:                 state,
		WaitingReason:         reason,
		ActivityAt:            now.UTC(),
		EmittedAt:             now.UTC(),
		Task:                  protocol.Task{Title: taskTitle, Repository: config.Repository},
		Metadata:              map[string]any{"hook": hook.HookEventName},
	}
	if hook.AgentType != "" {
		event.Metadata["agent_type"] = hook.AgentType
	}
	if err := event.Validate(); err != nil {
		return protocol.Event{}, false, err
	}
	return event, true, nil
}

func truncateRunes(value string, maximum int) string {
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	return string(runes[:maximum])
}

func classifyClaudeHook(hook claudeHook) (protocol.State, protocol.WaitingReason, bool) {
	switch hook.HookEventName {
	case "PermissionRequest":
		return protocol.StateWaitingForUser, protocol.WaitingReasonPermission, true
	case "Elicitation", "ElicitationResult":
		return protocol.StateWaitingForUser, protocol.WaitingReasonElicitation, true
	case "Notification":
		switch hook.NotificationType {
		case "permission_prompt":
			return protocol.StateWaitingForUser, protocol.WaitingReasonPermission, true
		case "agent_needs_input", "idle_prompt", "elicitation_dialog":
			return protocol.StateWaitingForUser, protocol.WaitingReasonOther, true
		default:
			return "", "", false
		}
	case "Stop", "SubagentStop":
		return protocol.StateDone, "", true
	case "TaskCompleted":
		// Claude's TaskCompleted hook identifies a task, not the root session or
		// a separately addressable agent in Canopi's current model.
		return "", "", false
	case "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch", "SubagentStart", "TaskCreated":
		return protocol.StateWorking, "", true
	default:
		return "", "", false
	}
}

// Deliver posts one normalized event to a transport endpoint.
func Deliver(ctx context.Context, client *http.Client, endpoint, token string, event protocol.Event) error {
	if client == nil {
		return errors.New("HTTP client is required")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/v1/events", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("canopi collector returned HTTP %d", response.StatusCode)
	}
	return nil
}
