//go:build windows

package adapter

import (
	"context"
	"fmt"
	"os"

	"github.com/rock3r/punaro/internal/relay"
)

func openPinnedInvocationExecutable(string) (*os.File, error) {
	return nil, fmt.Errorf("invocation runtime command is not supported on Windows")
}

func runPinnedInvocationExecutable(context.Context, *os.File, relay.Invocation) error {
	return fmt.Errorf("invocation runtime command is not supported on Windows")
}
