package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rock3r/punaro/internal/operator"
	"github.com/rock3r/punaro/internal/relay"
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
	if !bytes.Contains(stderr.Bytes(), []byte("rerun the exact command")) {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRelayRegisterRequiresConfirmationAndUsesOwnerWorkflow(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	register := func(directory, file string) (operator.Installation, error) {
		called = directory == "/install" && file == "/private/machine.json"
		return operator.Installation{Directory: directory}, nil
	}
	if code := runRelayRegister([]string{"--directory", "/install", "--machine-enrollment-file", "/private/machine.json"}, &stdout, &stderr, register); code != 2 || called {
		t.Fatalf("unconfirmed code=%d called=%t", code, called)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runRelayRegister([]string{"--directory", "/install", "--machine-enrollment-file", "/private/machine.json", "--yes"}, &stdout, &stderr, register); code != 0 || !called || !bytes.Contains(stdout.Bytes(), []byte(`"relay_machine_registered"`)) {
		t.Fatalf("code=%d called=%t stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
	if code := runRelayRegister([]string{"--directory", "/install", "--machine-enrollment-file", "/private/machine.json", "--yes"}, &stdout, &stderr, func(string, string) (operator.Installation, error) {
		return operator.Installation{}, errors.New("unsafe")
	}); code != 1 || !bytes.Contains(stderr.Bytes(), []byte("rerun the exact command")) {
		t.Fatalf("failure code=%d stderr=%q", code, stderr.String())
	}
}

func TestRelayReconcileCapacityRequiresConfirmation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	reconcile := func(string) (relay.QuotaCounters, error) {
		called = true
		return relay.QuotaCounters{}, nil
	}
	if code := runRelayReconcileCapacity([]string{"--directory", "/install"}, &stdout, &stderr, reconcile); code != 2 || called {
		t.Fatalf("unconfirmed code=%d called=%t", code, called)
	}
}

func TestRelayReconcileCapacityPublishesContentFreeOutcome(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	reconcile := func(directory string) (relay.QuotaCounters, error) {
		called = directory == "/install"
		return relay.QuotaCounters{Count: 3, Bytes: 12}, nil
	}
	if code := runRelayReconcileCapacity([]string{"--directory", "/install", "--yes"}, &stdout, &stderr, reconcile); code != 0 || !called || !bytes.Contains(stdout.Bytes(), []byte(`"capacity_reconciled"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"pending_count": 3`)) {
		t.Fatalf("code=%d called=%t stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
	if code := runRelayReconcileCapacity([]string{"--directory", "/install", "--yes"}, &stdout, &stderr, func(string) (relay.QuotaCounters, error) {
		return relay.QuotaCounters{}, errors.New("unsafe")
	}); code != 1 || !bytes.Contains(stderr.Bytes(), []byte("rerun the exact command")) {
		t.Fatalf("failure code=%d stderr=%q", code, stderr.String())
	}
}

func TestRelayListTerminalsPublishesContentFreePages(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	list := func(directory, after string, limit int) (relay.TerminalPage, error) {
		called = directory == "/install" && after == "cursor-1" && limit == 2
		return relay.TerminalPage{Terminals: []relay.TerminalRecord{{DeliveryID: "d1", MessageID: "m1", ConversationID: "c1", RecipientID: "r1", Sequence: 1, ClosedReason: relay.ClosedExpired}}, NextCursor: "d1"}, nil
	}
	if code := runRelayListTerminals([]string{"--directory", "/install", "--after", "cursor-1", "--limit", "2"}, &stdout, &stderr, list); code != 0 || !called || !bytes.Contains(stdout.Bytes(), []byte(`"closed_reason": "expired"`)) || bytes.Contains(stdout.Bytes(), []byte("body")) {
		t.Fatalf("code=%d called=%t stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
}

func TestRelayMaintainDeliveriesRequiresConfirmation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	maintain := func(string) (relay.MaintenanceResult, error) {
		called = true
		return relay.MaintenanceResult{}, nil
	}
	if code := runRelayMaintainDeliveries([]string{"--directory", "/install"}, &stdout, &stderr, maintain); code != 2 || called {
		t.Fatalf("unconfirmed code=%d called=%t", code, called)
	}
	if code := runRelayMaintainDeliveries([]string{"--directory", "/install", "--yes"}, &stdout, &stderr, func(string) (relay.MaintenanceResult, error) {
		return relay.MaintenanceResult{Expired: 1, Pruned: 0, Scanned: 1}, nil
	}); code != 0 || !bytes.Contains(stdout.Bytes(), []byte(`"deliveries_maintained"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"expired": 1`)) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestApplyInstallationRetentionHonorsDaemonEnvFile(t *testing.T) {
	directory := t.TempDir()
	want := relay.RetentionConfig{PendingMaxAgeSeconds: 90, TerminalRetentionSeconds: 180, MaintenanceBatch: 7}
	body := "PUNARO_RELAY_PENDING_MAX_AGE_SECONDS=90\nPUNARO_RELAY_TERMINAL_RETENTION_SECONDS=180\nPUNARO_RELAY_DELIVERY_MAINTENANCE_BATCH=7\n"
	if err := os.WriteFile(operator.EnvFile(directory), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"PUNARO_RELAY_PENDING_MAX_AGE_SECONDS",
		"PUNARO_RELAY_TERMINAL_RETENTION_SECONDS",
		"PUNARO_RELAY_DELIVERY_MAINTENANCE_BATCH",
	} {
		previous, present := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if present {
				_ = os.Setenv(key, previous)
				return
			}
			_ = os.Unsetenv(key)
		})
	}
	store := &recordingOperatorStore{}
	if err := applyInstallationRetention(directory, store); err != nil {
		t.Fatal(err)
	}
	if store.policy != want {
		t.Fatalf("policy=%#v want=%#v env=%s", store.policy, want, filepath.Base(operator.EnvFile(directory)))
	}
}

type recordingOperatorStore struct {
	policy relay.RetentionConfig
}

func (s *recordingOperatorStore) SetRetentionPolicy(cfg relay.RetentionConfig) error {
	s.policy = cfg
	return nil
}
