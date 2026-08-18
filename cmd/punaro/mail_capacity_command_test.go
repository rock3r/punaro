package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/operator"
)

func TestMailReconcileCapacityCommandRequiresConfirmation(t *testing.T) {
	directory := testInstallation(t)
	called := false
	execute := func(operator.Installation) error {
		called = true
		return nil
	}
	var stdout, stderr bytes.Buffer
	if code := runMailReconcileCapacity([]string{"--directory", directory}, &stdout, &stderr, execute); code != 2 || called || !strings.Contains(stderr.String(), "requires --yes") {
		t.Fatalf("unconfirmed code=%d called=%t stderr=%q", code, called, stderr.String())
	}
	if code := runMailReconcileCapacity([]string{"--yes"}, &stdout, &stderr, execute); code != 2 || called {
		t.Fatalf("missing directory code=%d called=%t", code, called)
	}
}

func TestMailReconcileCapacityCommandRunsHostLocalRepair(t *testing.T) {
	directory := testInstallation(t)
	execute := func(installation operator.Installation) error {
		if installation.Directory != directory || installation.MailCutover != nil {
			t.Fatalf("installation=%#v", installation)
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	if code := runMailReconcileCapacity([]string{"--directory", directory, "--yes"}, &stdout, &stderr, execute); code != 0 || !strings.Contains(stdout.String(), `"capacity_reconciled"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestMailReconcileCapacityCommandFailsClosed(t *testing.T) {
	directory := testInstallation(t)
	execute := func(operator.Installation) error {
		return errors.New("counters drifted")
	}
	var stdout, stderr bytes.Buffer
	if code := runMailReconcileCapacity([]string{"--directory", directory, "--yes"}, &stdout, &stderr, execute); code != 1 || !strings.Contains(stderr.String(), "mail capacity reconciliation failed") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
