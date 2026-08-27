// canopi-claude-hook adapts Claude Code command hooks to Canopi events. The
// hook-facing process publishes a recoverable local queue entry before any
// detached delivery; all network I/O happens after it returns.
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"github.com/rock3r/punaro/internal/canopiadapter"
)

const maxHookBytes = 1 << 20

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "deliver":
			_ = runDelivery(os.Getenv)
			return
		case "supervise":
			_ = runSupervisor(os.Getenv)
			return
		case "prepare":
			if runPrepare(os.Getenv) != nil {
				os.Exit(1)
			}
			return
		}
	}
	if err := runHook(os.Stdin, os.Getenv, spawnDetached); err != nil {
		// The documented adapter configuration runs command hooks asynchronously,
		// so an unavailable local spool can never control Claude's action. A
		// non-zero result nevertheless ensures that only a fully synced queue
		// entry is acknowledged as a successful hook execution.
		os.Exit(1)
	}
}

func runPrepare(getenv func(string) string) error {
	spool, err := deliverySpool(getenv)
	if err != nil {
		return err
	}
	return spool.Prepare()
}

func runHook(input io.Reader, getenv func(string) string, spawn func() error) error {
	// Claude starts async hook processes at lifecycle boundaries. Capture the
	// process invocation time before input processing so a slow provider payload
	// cannot make an older lifecycle transition appear newer than one that follows.
	return runHookAt(input, getenv, spawn, time.Now())
}

func runHookAt(input io.Reader, getenv func(string) string, spawn func() error, invokedAt time.Time) error {
	if getenv("CANOPI_ENDPOINT") == "" || getenv("CANOPI_TOKEN_FILE") == "" || getenv("CANOPI_MACHINE_ID") == "" {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxHookBytes+1))
	if err != nil || len(raw) > maxHookBytes {
		if err != nil {
			return err
		}
		return errors.New("claude hook payload exceeds Canopi limit")
	}
	event, emit, err := canopiadapter.MapClaudeHook(raw, canopiadapter.AdapterConfig{
		MachineID:    getenv("CANOPI_MACHINE_ID"),
		MachineLabel: getenv("CANOPI_MACHINE_LABEL"),
		TaskTitle:    getenv("CANOPI_TASK_TITLE"),
		Repository:   getenv("CANOPI_REPOSITORY"),
	}, invokedAt)
	if err != nil {
		return err
	}
	if !emit {
		return nil // No lifecycle event is expected for this hook.
	}
	spool, err := deliverySpool(getenv)
	if err != nil {
		return err
	}
	if err := spool.Enqueue(event); err != nil {
		// The published-before-sync path can leave a recoverable target. Kick the
		// long-lived worker before reporting that the hook did not durably finish.
		_ = spawn()
		return err
	}
	// A launch error does not change the successful durable handoff; the service
	// manager owns restart of the long-lived supervisor.
	_ = spawn()
	return nil
}

func spawnDetached() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(context.Background(), executable, "supervise") // #nosec G204 -- os.Executable returns this already-running adapter binary; arguments are fixed.
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func runDelivery(getenv func(string) string) error {
	spool, err := deliverySpool(getenv)
	if err != nil {
		return err
	}
	tokenBytes, err := readProtectedToken(getenv("CANOPI_TOKEN_FILE"))
	if err != nil {
		return err
	}
	client, err := canopiadapter.NewDeliveryClient(getenv("CANOPI_TLS_CA_FILE"))
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(tokenBytes))
	return spool.Drain(context.Background(), func(ctx context.Context, event protocol.Event) error {
		return canopiadapter.Deliver(ctx, client, getenv("CANOPI_ENDPOINT"), token, event)
	})
}

func runSupervisor(getenv func(string) string) error {
	spool, err := deliverySpool(getenv)
	if err != nil {
		return err
	}
	tokenBytes, err := readProtectedToken(getenv("CANOPI_TOKEN_FILE"))
	if err != nil {
		return err
	}
	client, err := canopiadapter.NewDeliveryClient(getenv("CANOPI_TLS_CA_FILE"))
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(tokenBytes))
	return spool.Serve(context.Background(), func(ctx context.Context, event protocol.Event) error {
		return canopiadapter.Deliver(ctx, client, getenv("CANOPI_ENDPOINT"), token, event)
	})
}

func deliverySpool(getenv func(string) string) (canopiadapter.Spool, error) {
	directory := strings.TrimSpace(getenv("CANOPI_SPOOL_DIR"))
	if directory == "" {
		tokenFile := strings.TrimSpace(getenv("CANOPI_TOKEN_FILE"))
		if !filepath.IsAbs(tokenFile) {
			return canopiadapter.Spool{}, os.ErrInvalid
		}
		directory = filepath.Join(filepath.Dir(tokenFile), "canopi-claude-spool")
	}
	return canopiadapter.Spool{Directory: directory}, nil
}
