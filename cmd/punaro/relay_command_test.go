package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/rock3r/punaro/internal/operator"
)

func TestRelayConfigureRequiresExplicitProtectedInputAndConfirmation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runRelayConfigure([]string{"--directory", "/install", "--relay-machines-file", "/private/machines.json"}, &stdout, &stderr, func(string, string) (operator.Installation, error) {
		t.Fatal("configure called without confirmation")
		return operator.Installation{}, nil
	}); code != 2 {
		t.Fatalf("code=%d", code)
	}
}

func TestRelayConfigurePublishesOnlyThroughOperator(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	configure := func(directory, file string) (operator.Installation, error) {
		called = directory == "/install" && file == "/private/machines.json"
		return operator.Installation{Directory: directory}, nil
	}
	if code := runRelayConfigure([]string{"--directory", "/install", "--relay-machines-file", "/private/machines.json", "--yes"}, &stdout, &stderr, configure); code != 0 || !called || !bytes.Contains(stdout.Bytes(), []byte(`"relay_configured"`)) {
		t.Fatalf("code=%d called=%t stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
	if code := runRelayConfigure([]string{"--directory", "/install", "--relay-machines-file", "/private/machines.json", "--yes"}, &stdout, &stderr, func(string, string) (operator.Installation, error) {
		return operator.Installation{}, errors.New("unsafe")
	}); code != 1 {
		t.Fatalf("code=%d", code)
	}
}
