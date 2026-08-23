// canopi-claude-hook adapts Claude Code command hooks to Canopi events. The
// hook-facing process only normalizes and starts a detached delivery child; all
// network I/O happens after the hook-facing process has returned.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"github.com/rock3r/punaro/internal/canopiadapter"
)

const maxHookBytes = 1 << 20

func main() {
	if len(os.Args) == 2 && os.Args[1] == "deliver" {
		_ = runDelivery(os.Stdin, os.Getenv)
		return
	}
	_ = runHook(os.Stdin, os.Getenv, os.ReadFile, spawnDetached)
}

func runHook(input io.Reader, getenv func(string) string, readFile func(string) ([]byte, error), spawn func([]byte) error) error {
	if getenv("CANOPI_ENDPOINT") == "" || getenv("CANOPI_TOKEN_FILE") == "" || getenv("CANOPI_MACHINE_ID") == "" {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxHookBytes+1))
	if err != nil || len(raw) > maxHookBytes {
		return nil //nolint:nilerr // Hook failures must never affect Claude Code.
	}
	eventIDKey, err := readFile(getenv("CANOPI_TOKEN_FILE"))
	if err != nil || len(strings.TrimSpace(string(eventIDKey))) == 0 {
		return nil //nolint:nilerr // Hook failures must never affect Claude Code.
	}
	event, emit, err := canopiadapter.MapClaudeHook(raw, canopiadapter.AdapterConfig{
		MachineID:    getenv("CANOPI_MACHINE_ID"),
		MachineLabel: getenv("CANOPI_MACHINE_LABEL"),
		TaskTitle:    getenv("CANOPI_TASK_TITLE"),
		Repository:   getenv("CANOPI_REPOSITORY"),
		EventIDKey:   []byte(strings.TrimSpace(string(eventIDKey))),
	}, time.Now())
	if err != nil || !emit {
		return nil //nolint:nilerr // Invalid or irrelevant hooks are deliberately swallowed.
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return nil //nolint:nilerr // Hook failures must never affect Claude Code.
	}
	_ = spawn(payload)
	return nil
}

func spawnDetached(payload []byte) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(context.Background(), executable, "deliver") // #nosec G204 -- os.Executable returns this already-running adapter binary; arguments are fixed.
	command.Stdin = bytes.NewReader(payload)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func runDelivery(input io.Reader, getenv func(string) string) error {
	event, err := protocol.DecodeEvent(input, maxHookBytes)
	if err != nil {
		return err
	}
	tokenBytes, err := os.ReadFile(getenv("CANOPI_TOKEN_FILE"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	client := &http.Client{Timeout: 750 * time.Millisecond}
	return canopiadapter.Deliver(ctx, client, getenv("CANOPI_ENDPOINT"), strings.TrimSpace(string(tokenBytes)), event)
}
