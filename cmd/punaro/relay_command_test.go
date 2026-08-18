package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestRelayListTerminalsIsReadOnlyAndContentFree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	list := func(directory string, input relay.TerminalListInput) (relay.TerminalListPage, error) {
		called = directory == "/install" && input.Limit == 2 && input.Cursor == "next"
		return relay.TerminalListPage{
			Terminals: []relay.DeliveryTerminal{{
				DeliveryID:     "delivery-1",
				MessageID:      "message-1",
				ConversationID: "conversation-1",
				RecipientID:    "agent/b",
				Sequence:       1,
				ClosedReason:   relay.ClosedReasonExpired,
			}},
			NextCursor: "later",
		}, nil
	}
	if code := runRelayListTerminals([]string{"--directory", "/install", "--limit", "2", "--cursor", "next", "--yes"}, &stdout, &stderr, list); code != 2 || called {
		t.Fatalf("unexpected --yes code=%d called=%t", code, called)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runRelayListTerminals([]string{"--directory", "/install", "--limit", "2", "--cursor", "next"}, &stdout, &stderr, list); code != 0 || !called {
		t.Fatalf("code=%d called=%t stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
	body := stdout.String()
	if !bytes.Contains(stdout.Bytes(), []byte(`"terminals_listed"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"closed_reason": "expired"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"next_cursor": "later"`)) {
		t.Fatalf("stdout=%q", body)
	}
	if strings.Contains(body, "body") || strings.Contains(body, "secret") {
		t.Fatalf("operator list leaked content: %s", body)
	}
	if code := runRelayListTerminals([]string{"--directory", "/install"}, &stdout, &stderr, func(string, relay.TerminalListInput) (relay.TerminalListPage, error) {
		return relay.TerminalListPage{}, errors.New("unsafe")
	}); code != 1 || !bytes.Contains(stderr.Bytes(), []byte("rerun the exact command")) {
		t.Fatalf("failure code=%d stderr=%q", code, stderr.String())
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
}

func TestRelayMaintainDeliveriesPublishesContentFreeOutcome(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	maintain := func(directory string) (relay.MaintenanceResult, error) {
		called = directory == "/install"
		return relay.MaintenanceResult{Expired: 2, Pruned: 1, Continuation: true}, nil
	}
	if code := runRelayMaintainDeliveries([]string{"--directory", "/install", "--yes"}, &stdout, &stderr, maintain); code != 0 || !called {
		t.Fatalf("code=%d called=%t stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
	body := stdout.String()
	if !bytes.Contains(stdout.Bytes(), []byte(`"deliveries_maintained"`)) || !bytes.Contains(stdout.Bytes(), []byte(`"expired": 2`)) || !bytes.Contains(stdout.Bytes(), []byte(`"continuation": true`)) {
		t.Fatalf("stdout=%q", body)
	}
	if strings.Contains(body, "body") {
		t.Fatalf("operator maintain leaked content: %s", body)
	}
	if code := runRelayMaintainDeliveries([]string{"--directory", "/install", "--yes"}, &stdout, &stderr, func(string) (relay.MaintenanceResult, error) {
		return relay.MaintenanceResult{}, errors.New("unsafe")
	}); code != 1 || !bytes.Contains(stderr.Bytes(), []byte("rerun the exact command")) {
		t.Fatalf("failure code=%d stderr=%q", code, stderr.String())
	}
}

func TestRelayUsesPostgresWhenEnabledWithoutCutover(t *testing.T) {
	if !relayUsesPostgres(operator.Installation{RelayEnabled: true}, "") {
		t.Fatal("relay-enabled installation did not select postgres")
	}
	if relayUsesPostgres(operator.Installation{}, "") {
		t.Fatal("sqlite-only installation selected postgres")
	}
	if !relayUsesPostgres(operator.Installation{}, "postgres") {
		t.Fatal("explicit postgres store was ignored")
	}
}

func TestRetentionPolicyFromInstallationEnvIgnoresProcessOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "punarod.env")
	if err := os.WriteFile(path, []byte("PUNARO_RELAY_PENDING_MAX_AGE_SECONDS=60\nPUNARO_RELAY_TERMINAL_RETENTION_SECONDS=120\nPUNARO_RELAY_DELIVERY_MAINTENANCE_BATCH=7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUNARO_RELAY_PENDING_MAX_AGE_SECONDS", "1")
	got, err := retentionPolicyFromEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := relay.RetentionConfig{PendingMaxAgeSeconds: 60, TerminalRetentionSeconds: 120, MaintenanceBatch: 7}
	if got != want {
		t.Fatalf("policy=%#v want %#v", got, want)
	}
}
