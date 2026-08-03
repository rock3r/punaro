package adapter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

const invocationRuntimeTimeout = 30 * time.Second

// CommandInvoker invokes one operator-installed local runtime. The executable
// and all argument names are fixed locally; the relay supplies only opaque
// identifiers and the stable dedupe fence, never an executable or body.
type CommandInvoker struct{ executable *os.File }

// NewCommandInvoker validates an absolute, non-group/world-writable runtime
// executable before the adapter enables remote invocation handoffs.
func NewCommandInvoker(path string) (*CommandInvoker, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("invocation runtime command must be an absolute path")
	}
	executable, err := openPinnedInvocationExecutable(path)
	if err != nil {
		return nil, err
	}
	return &CommandInvoker{executable: executable}, nil
}

// Invoke starts one locally configured role under a stable fence. Exit zero
// means the runtime durably accepted that fence, not merely that it spawned a
// process. The runtime must make duplicate fences no-ops across its own crash
// boundary before returning success.
func (i *CommandInvoker) Invoke(ctx context.Context, invocation relay.Invocation) error {
	if i == nil || i.executable == nil || strings.TrimSpace(invocation.ID) == "" || strings.TrimSpace(invocation.ConversationID) == "" || strings.TrimSpace(invocation.TargetEndpoint) == "" || strings.TrimSpace(invocation.Fence) == "" {
		return fmt.Errorf("invalid local invocation handoff")
	}
	deadline, cancel := context.WithTimeout(ctx, invocationRuntimeTimeout)
	defer cancel()
	if err := runPinnedInvocationExecutable(deadline, i.executable, invocation); err != nil {
		return fmt.Errorf("local invocation runtime failed: %w", err)
	}
	return nil
}

var _ Invoker = (*CommandInvoker)(nil)
