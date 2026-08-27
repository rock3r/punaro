// canopi-provider-hook is the shared durable local runner for Codex, Grok
// Build, and Pi integrations. Provider-facing invocations only publish a
// privacy-safe normalized event to a local spool; delivery happens later.
package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"github.com/rock3r/punaro/internal/canopiadapter"
	"github.com/rock3r/punaro/internal/canopicredential"
)

const maxHookBytes = 1 << 20

type provider string

const (
	providerCodex provider = "codex"
	providerGrok  provider = "grok"
	providerPi    provider = "pi"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	selected, ok := parseProvider(os.Args[1])
	if !ok {
		os.Exit(2)
	}
	command := "hook"
	if len(os.Args) == 3 {
		command = os.Args[2]
	}
	switch command {
	case "prepare":
		if runPrepare(selected, os.Getenv) != nil {
			os.Exit(1)
		}
	case "supervise":
		_ = runSupervisor(selected, os.Getenv)
	case "deliver":
		_ = runDelivery(selected, os.Getenv)
	case "emit":
		if runEmit(selected, os.Stdin, os.Getenv, func() error { return spawnDetached(selected) }) != nil {
			os.Exit(1)
		}
	case "relay":
		// Codex 0.142.4 parses async hooks but reports that they are not yet
		// supported. This synchronous parent only hands its stdin to a detached
		// child and always returns; the child performs all parsing and spool I/O.
		// A launch failure must never add a provider-visible failure or delay.
		_ = relayHookDetached(selected)
	case "hook":
		if selected == providerPi || runHook(selected, os.Stdin, os.Getenv, func() error { return spawnDetached(selected) }) != nil {
			os.Exit(1)
		}
	default:
		os.Exit(2)
	}
}

func parseProvider(value string) (provider, bool) {
	switch provider(value) {
	case providerCodex, providerGrok, providerPi:
		return provider(value), true
	default:
		return "", false
	}
}

func runPrepare(selected provider, getenv func(string) string) error {
	spool, err := deliverySpool(selected, getenv)
	if err != nil {
		return err
	}
	return spool.Prepare()
}

func runHook(selected provider, input io.Reader, getenv func(string) string, spawn func() error) error {
	return runHookAt(selected, input, getenv, spawn, time.Now())
}

func runHookAt(selected provider, input io.Reader, getenv func(string) string, spawn func() error, invokedAt time.Time) error {
	if !configured(getenv) {
		return nil
	}
	raw, err := readBounded(input)
	if err != nil {
		return err
	}
	config := canopiadapter.AdapterConfig{
		MachineID:    getenv("CANOPI_MACHINE_ID"),
		MachineLabel: getenv("CANOPI_MACHINE_LABEL"),
		TaskTitle:    getenv("CANOPI_TASK_TITLE"),
		Repository:   getenv("CANOPI_REPOSITORY"),
	}
	var event protocol.Event
	var emit bool
	switch selected {
	case providerCodex:
		event, emit, err = canopiadapter.MapCodexHook(raw, config, invokedAt)
	case providerGrok:
		event, emit, err = canopiadapter.MapGrokHook(raw, config, invokedAt)
	default:
		return errors.New("provider command hooks are unsupported for this provider")
	}
	if err != nil {
		return err
	}
	if !emit {
		return nil
	}
	return enqueueAndKick(selected, event, getenv, spawn)
}

func runEmit(selected provider, input io.Reader, getenv func(string) string, spawn func() error) error {
	if !configured(getenv) {
		return nil
	}
	raw, err := readBounded(input)
	if err != nil {
		return err
	}
	event, err := protocol.DecodeEvent(strings.NewReader(string(raw)), 64<<10)
	if err != nil {
		return err
	}
	if event.Source != sourceForProvider(selected) {
		return errors.New("normalized event source does not match provider")
	}
	return enqueueAndKick(selected, event, getenv, spawn)
}

func readBounded(input io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(input, maxHookBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxHookBytes {
		return nil, errors.New("provider hook payload exceeds Canopi limit")
	}
	return raw, nil
}

func configured(getenv func(string) string) bool {
	return getenv("CANOPI_ENDPOINT") != "" && getenv("CANOPI_TOKEN_FILE") != "" && getenv("CANOPI_MACHINE_ID") != ""
}

func enqueueAndKick(selected provider, event protocol.Event, getenv func(string) string, spawn func() error) error {
	spool, err := deliverySpool(selected, getenv)
	if err != nil {
		return err
	}
	if err := spool.Enqueue(event); err != nil {
		_ = spawn()
		return err
	}
	_ = spawn()
	return nil
}

func spawnDetached(selected provider) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(context.Background(), executable, string(selected), "supervise") // #nosec G204,G702 -- the executable is this binary and the provider is validated by parseProvider.
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func relayHookDetached(selected provider) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(context.Background(), executable, string(selected), "hook") // #nosec G204,G702 -- the executable is this binary and the provider is validated by parseProvider.
	command.Stdin = os.Stdin
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func runDelivery(selected provider, getenv func(string) string) error {
	spool, err := deliverySpool(selected, getenv)
	if err != nil {
		return err
	}
	token, err := canopicredential.ReadToken(getenv("CANOPI_TOKEN_FILE"))
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 750 * time.Millisecond}
	return spool.Drain(context.Background(), func(ctx context.Context, event protocol.Event) error {
		return canopiadapter.Deliver(ctx, client, getenv("CANOPI_ENDPOINT"), token, event)
	})
}

func runSupervisor(selected provider, getenv func(string) string) error {
	spool, err := deliverySpool(selected, getenv)
	if err != nil {
		return err
	}
	token, err := canopicredential.ReadToken(getenv("CANOPI_TOKEN_FILE"))
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 750 * time.Millisecond}
	return spool.Serve(context.Background(), func(ctx context.Context, event protocol.Event) error {
		return canopiadapter.Deliver(ctx, client, getenv("CANOPI_ENDPOINT"), token, event)
	})
}

func deliverySpool(selected provider, getenv func(string) string) (canopiadapter.Spool, error) {
	directory := strings.TrimSpace(getenv("CANOPI_SPOOL_DIR"))
	if directory == "" {
		tokenFile := strings.TrimSpace(getenv("CANOPI_TOKEN_FILE"))
		if !filepath.IsAbs(tokenFile) {
			return canopiadapter.Spool{}, os.ErrInvalid
		}
		directory = filepath.Join(filepath.Dir(tokenFile), "canopi-"+string(selected)+"-spool")
	}
	return canopiadapter.Spool{Directory: directory}, nil
}

func sourceForProvider(selected provider) protocol.Source {
	switch selected {
	case providerCodex:
		return protocol.SourceCodex
	case providerGrok:
		return protocol.SourceGrokBuild
	case providerPi:
		return protocol.SourcePi
	default:
		return protocol.SourceOther
	}
}
