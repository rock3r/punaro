//go:build !windows

package adapter

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/rock3r/punaro/internal/relay"
)

// openPinnedInvocationExecutable rejects a symlink or writable ancestor, then
// keeps the verified inode open. The later exec uses that descriptor rather
// than resolving the configured pathname again.
func openPinnedInvocationExecutable(path string) (*os.File, error) {
	requestedInfo, err := os.Lstat(path)
	if err != nil || requestedInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("invocation runtime command must be a protected regular executable")
	}
	canonicalPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve invocation runtime command: %w", err)
	}
	for current := canonicalPath; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || !trustedInvocationPathOwner(info) {
			return nil, fmt.Errorf("invocation runtime command must have protected non-symlink path components")
		}
		if current == string(filepath.Separator) {
			break
		}
	}
	info, err := os.Lstat(canonicalPath)
	if err != nil || !info.Mode().IsRegular() || !trustedInvocationPathOwner(info) {
		return nil, fmt.Errorf("invocation runtime command must be a protected regular executable")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("invocation runtime command is not executable")
	}
	executable, err := os.Open(canonicalPath)
	if err != nil {
		return nil, fmt.Errorf("open invocation runtime command: %w", err)
	}
	openedInfo, err := executable.Stat()
	currentInfo, currentErr := os.Lstat(canonicalPath)
	if err != nil || currentErr != nil || currentInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, currentInfo) {
		_ = executable.Close()
		return nil, fmt.Errorf("invocation runtime command changed during validation")
	}
	return executable, nil
}

func trustedInvocationPathOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == uint32(os.Geteuid()) || stat.Uid == 0)
}

func runPinnedInvocationExecutable(ctx context.Context, executable *os.File, invocation relay.Invocation) error {
	// #nosec G204 -- /dev/fd/3 is a verified, already-open operator executable;
	// arguments are fixed flags with opaque server identifiers and no message body.
	command := exec.CommandContext(ctx, "/dev/fd/3", "invoke", "--invocation-id", invocation.ID, "--conversation", invocation.ConversationID, "--endpoint", invocation.TargetEndpoint, "--fence", invocation.Fence)
	command.ExtraFiles = []*os.File{executable}
	command.Stdout = nil
	command.Stderr = nil
	return command.Run()
}
