package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/canopiadapter"
)

func TestHookDelegatesCaptureWithoutReadingProviderInput(t *testing.T) {
	spawned := false
	err := runHook(func() error {
		spawned = true
		return errors.New("simulated launch failure")
	})
	if err != nil {
		t.Fatalf("runHook() error = %v; adapter failures must be swallowed", err)
	}
	if !spawned {
		t.Fatal("runHook() did not launch detached capture")
	}
}

func TestDetachedCaptureDurablyQueuesWithoutWaitingForNetwork(t *testing.T) {
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
	err := runCapture(bytes.NewReader(raw), func(key string) string { return environment[key] }, func() error {
		spawned = true
		return errors.New("simulated launch failure")
	})
	if err != nil {
		t.Fatalf("runCapture() error = %v", err)
	}
	if !spawned {
		t.Fatal("runCapture() did not launch detached supervisor")
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

func TestDetachedProcessConfigurationSurvivesHookParentExit(t *testing.T) {
	unixSource, err := os.ReadFile("process_detach_unix.go")
	if err != nil {
		t.Fatal(err)
	}
	windowsSource, err := os.ReadFile("process_detach_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unixSource), "Setsid: true") {
		t.Fatal("Unix capture worker does not start in a detached session")
	}
	for _, required := range []string{"DETACHED_PROCESS", "CREATE_NEW_PROCESS_GROUP"} {
		if !strings.Contains(string(windowsSource), required) {
			t.Fatalf("Windows capture worker is missing %s", required)
		}
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
