package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"github.com/rock3r/punaro/internal/canopiadapter"
)

func TestHookDurablyQueuesBeforeDetachedDeliveryLaunchFailure(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"private"}}`)
	environment := map[string]string{
		"CANOPI_ENDPOINT":      "http://canopi.test",
		"CANOPI_TOKEN_FILE":    "/private/token",
		"CANOPI_MACHINE_ID":    "studio-m2",
		"CANOPI_TASK_TITLE":    "Punaro / tests",
		"CANOPI_MACHINE_LABEL": "Studio M2",
		"CANOPI_SPOOL_DIR":     t.TempDir(),
	}
	if err := runPrepare(func(key string) string { return environment[key] }); err != nil {
		t.Fatal(err)
	}
	spawned := false
	err := runHook(bytes.NewReader(raw), func(key string) string { return environment[key] }, func() error {
		spawned = true
		return errors.New("simulated launch failure")
	})
	if err != nil {
		t.Fatalf("runHook() error = %v; adapter failures must be swallowed", err)
	}
	if !spawned {
		t.Fatal("runHook() did not launch detached delivery")
	}
	spool := canopiadapter.Spool{Directory: environment["CANOPI_SPOOL_DIR"]}
	if got, err := spool.Pending(); err != nil || got != 1 {
		t.Fatalf("durable pending events = %d, %v", got, err)
	}
	files, err := filepath.Glob(filepath.Join(environment["CANOPI_SPOOL_DIR"], "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("spool files = %v, %v", files, err)
	}
	payload, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("private")) {
		t.Fatal("durable normalized payload contains private hook input")
	}
}

func TestPrepareCreatesSpoolBeforeHooksAreEnabled(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "spool")
	environment := map[string]string{"CANOPI_SPOOL_DIR": directory}
	if err := runPrepare(func(key string) string { return environment[key] }); err != nil {
		t.Fatal(err)
	}
	spool := canopiadapter.Spool{Directory: directory}
	if got, err := spool.Pending(); err != nil || got != 0 {
		t.Fatalf("prepared spool pending = %d, %v", got, err)
	}
}

func TestHookReturnsEnqueueFailureInsteadOfAcknowledgingIt(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"PermissionRequest"}`)
	environment := map[string]string{
		"CANOPI_ENDPOINT":   "http://canopi.test",
		"CANOPI_TOKEN_FILE": "/private/token",
		"CANOPI_MACHINE_ID": "studio-m2",
		"CANOPI_SPOOL_DIR":  filepath.Join(t.TempDir(), "unprepared-spool"),
	}
	if err := runHook(bytes.NewReader(raw), func(key string) string { return environment[key] }, func() error { return nil }); err == nil {
		t.Fatal("runHook() accepted an event that was not durably queued")
	}
}

func TestHookReturnsMalformedPayloadFailure(t *testing.T) {
	environment := map[string]string{
		"CANOPI_ENDPOINT":   "http://canopi.test",
		"CANOPI_TOKEN_FILE": "/private/token",
		"CANOPI_MACHINE_ID": "studio-m2",
		"CANOPI_SPOOL_DIR":  t.TempDir(),
	}
	if err := runHook(bytes.NewReader([]byte(`{"session_id":`)), func(key string) string { return environment[key] }, func() error { return nil }); err == nil {
		t.Fatal("runHook() accepted malformed provider input")
	}
}

func TestHookUsesInvocationTimeBeforeInputProcessing(t *testing.T) {
	raw := []byte(`{"session_id":"session-1","cwd":"/src/punaro","hook_event_name":"PermissionRequest"}`)
	environment := map[string]string{
		"CANOPI_ENDPOINT":   "http://canopi.test",
		"CANOPI_TOKEN_FILE": "/private/token",
		"CANOPI_MACHINE_ID": "studio-m2",
		"CANOPI_SPOOL_DIR":  t.TempDir(),
	}
	if err := runPrepare(func(key string) string { return environment[key] }); err != nil {
		t.Fatal(err)
	}
	invokedAt := time.Date(2026, 8, 24, 9, 12, 0, 0, time.FixedZone("offset", 3600))
	if err := runHookAt(bytes.NewReader(raw), func(key string) string { return environment[key] }, func() error { return nil }, invokedAt); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(environment["CANOPI_SPOOL_DIR"], "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("spool files = %v, %v", files, err)
	}
	payload, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	event, err := protocol.DecodeEvent(bytes.NewReader(payload), 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !event.ActivityAt.Equal(invokedAt.UTC()) || !event.EmittedAt.Equal(invokedAt.UTC()) {
		t.Fatalf("event timestamps = %s/%s, want invocation time %s", event.ActivityAt, event.EmittedAt, invokedAt.UTC())
	}
}
