//go:build !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFileDigestMatchesRejectsFIFOBeforeOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compose.operator.yaml")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := fileDigestMatches(t.Context(), path, strings.Repeat("a", 64))
	if !result.Known || result.OK {
		t.Fatalf("FIFO compose binding=%#v", result)
	}
}

func TestFileDigestMatchesHonorsDeadlineInIsolatedReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compose.operator.yaml")
	if err := os.WriteFile(path, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := serverDoctorFileDigest
	serverDoctorFileDigest = func(ctx context.Context, _ string) (string, bool) {
		<-ctx.Done()
		return "", false
	}
	t.Cleanup(func() { serverDoctorFileDigest = previous })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	result := fileDigestMatches(ctx, path, strings.Repeat("a", 64))
	if result.Known || time.Since(started) > time.Second {
		t.Fatalf("deadline result=%#v elapsed=%s", result, time.Since(started))
	}
}
