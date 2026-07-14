package main

import (
	"testing"

	"github.com/rock3r/punaro/internal/config"
)

func TestBuildRelayHandlerRejectsInvalidEnrollment(t *testing.T) {
	_, closeRelay, err := buildRelayHandler(config.Config{DataDir: t.TempDir(), RelayEnabled: true, RelayMachinesJSON: `[{"id":"machine-a","public_key":"invalid","endpoint_prefixes":["agent/"]}]`})
	if closeRelay != nil {
		t.Fatal("invalid relay configuration returned a closer")
	}
	if err == nil {
		t.Fatal("invalid enrollment enabled relay routes")
	}
}

func TestBuildDirectoryHandlerRequiresValidPrivateSnapshot(t *testing.T) {
	_, closeRelay, err := buildRelayHandler(config.Config{DataDir: t.TempDir(), RelayEnabled: true, RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeRelay.Close() })
	if _, err := buildDirectoryHandler(config.Config{DirectoryEnabled: true, DirectorySnapshotFile: "/does/not/exist", RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`}, closeRelay); err == nil {
		t.Fatal("missing snapshot source accepted")
	}
}
