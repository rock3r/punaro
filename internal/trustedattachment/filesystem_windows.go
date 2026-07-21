//go:build windows

package trustedattachment

import "context"

func sameFilesystem(_, _ string) (bool, error) {
	// Windows is not a supported trusted-relay server platform. Keep the package
	// buildable for the repository-wide client cross-build; runtime wiring stays
	// Linux-only until the production image milestone.
	return true, nil
}

func lockArtifactFile(context.Context, string) (func() error, error) {
	// The trusted-relay server is unsupported on Windows; keep client-wide
	// cross-builds working without claiming cross-process locking semantics.
	return func() error { return nil }, nil
}
