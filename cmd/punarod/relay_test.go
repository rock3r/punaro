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
