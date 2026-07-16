package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// CLIMailbox is a local process boundary around agent-mailbox. It deliberately
// permits only the group membership and send operations used by the adapter.
type CLIMailbox struct {
	binary string
	state  string
	group  string
	run    commandRunner
}

type commandRunner func(context.Context, []string, []byte) ([]byte, error)

// NewCLIMailbox configures the local group whose active memberships determine
// the only sessions advertised to Punaro.
func NewCLIMailbox(binary, stateDir, group string) (*CLIMailbox, error) {
	if strings.TrimSpace(binary) == "" || !strings.HasPrefix(group, "group/") {
		return nil, fmt.Errorf("agent-mailbox binary and group/ attachment address are required")
	}
	return newCLIMailbox(binary, stateDir, group, runAgentMailbox), nil
}

func newCLIMailbox(binary, stateDir, group string, runner commandRunner) *CLIMailbox {
	return &CLIMailbox{binary: binary, state: stateDir, group: group, run: func(ctx context.Context, args []string, stdin []byte) ([]byte, error) {
		base := make([]string, 0, len(args)+3)
		if stateDir != "" {
			base = append(base, "--state-dir", stateDir)
		}
		base = append(base, args...)
		return runner(ctx, append([]string{binary}, base...), stdin)
	}}
}

// Attached returns only active memberships. A group member that has detached
// disappears from the next advertisement without any remote command path.
func (m *CLIMailbox) Attached(ctx context.Context) ([]string, error) {
	output, err := m.run(ctx, []string{"group", "members", "--group", m.group, "--json"}, nil)
	if err != nil {
		return nil, fmt.Errorf("read local mailbox attachment group: %w", err)
	}
	var memberships []struct {
		Person string `json:"person"`
		Active bool   `json:"active"`
	}
	if err := json.Unmarshal(output, &memberships); err != nil {
		return nil, fmt.Errorf("decode local mailbox attachment group: %w", err)
	}
	endpoints := make([]string, 0, len(memberships))
	for _, membership := range memberships {
		if membership.Active && strings.TrimSpace(membership.Person) != "" {
			endpoints = append(endpoints, membership.Person)
		}
	}
	return endpoints, nil
}

// Send forwards one typed inert envelope to the local personal mailbox.
func (m *CLIMailbox) Send(ctx context.Context, endpoint string, message InboundMessage) error {
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("mailbox endpoint is required")
	}
	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode local mailbox envelope: %w", err)
	}
	_, err = m.run(ctx, []string{"send", "--to", endpoint, "--subject", "Punaro message", "--content-type", "application/vnd.punaro.message+json", "--schema-version", "1", "--body-file", "-", "--json"}, body)
	if err != nil {
		return fmt.Errorf("send local mailbox envelope: %w", err)
	}
	return nil
}

func runAgentMailbox(ctx context.Context, argv []string, stdin []byte) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("agent-mailbox command is required")
	}
	// #nosec G204 -- argv is assembled only from the local operator's adapter
	// configuration and fixed agent-mailbox subcommands; no relay or mailbox
	// body data can select the executable or command arguments.
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Stdin = bytes.NewReader(stdin)
	output, err := command.Output()
	if err != nil {
		// Do not include command output: a mailbox implementation might echo
		// untrusted body data in an error response.
		return nil, fmt.Errorf("agent-mailbox command failed: %w", err)
	}
	return output, nil
}
