package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestHookLaunchesDetachedDeliveryWithoutWaitingForNetwork(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"private"}}`)
	environment := map[string]string{
		"CANOPI_ENDPOINT":      "http://canopi.test",
		"CANOPI_TOKEN_FILE":    "/private/token",
		"CANOPI_MACHINE_ID":    "studio-m2",
		"CANOPI_TASK_TITLE":    "Punaro / tests",
		"CANOPI_MACHINE_LABEL": "Studio M2",
	}
	spawned := false
	err := runHook(bytes.NewReader(raw), func(key string) string { return environment[key] }, func(string) ([]byte, error) {
		return []byte("test-secret"), nil
	}, func(payload []byte) error {
		spawned = true
		if bytes.Contains(payload, []byte("private")) {
			t.Fatal("normalized child payload contains private hook input")
		}
		return errors.New("simulated launch failure")
	})
	if err != nil {
		t.Fatalf("runHook() error = %v; adapter failures must be swallowed", err)
	}
	if !spawned {
		t.Fatal("runHook() did not launch detached delivery")
	}
}
