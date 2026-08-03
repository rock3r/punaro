package adapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

func TestSyncerFencesRuntimeInvokeAcrossLostOutcomeAcknowledgement(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	invocation := relay.Invocation{ID: "invoke-1", ConversationID: "conversation-1", TargetEndpoint: "agent/offline", TargetMachineID: "machine-a", Fence: "stable-fence", LeaseToken: "lease-1", LeaseGeneration: 1}
	relayClient := &fakeInvocationRelay{fakeRelay: fakeRelay{deliveries: map[string][]relay.Delivery{}}, invocations: []relay.Invocation{invocation}, reportErr: errors.New("lost response")}
	runtime := &fakeInvoker{}
	syncer := Syncer{Mailbox: &fakeMailbox{}, Relay: relayClient, Journal: journal, Invoker: runtime}
	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("lost outcome acknowledgement reported success")
	}
	if runtime.calls != 1 || runtime.fences[0] != "stable-fence" {
		t.Fatalf("runtime calls=%d fences=%#v", runtime.calls, runtime.fences)
	}
	relayClient.reportErr = nil
	invocation.LeaseToken, invocation.LeaseGeneration, invocation.RecoveryOnly = "lease-2", 2, true
	relayClient.invocations = []relay.Invocation{invocation}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.calls != 1 || len(relayClient.reports) != 2 || !relayClient.reports[1].accepted {
		t.Fatalf("runtime calls=%d reports=%#v", runtime.calls, relayClient.reports)
	}
	var retained int
	if err := journal.db.QueryRowContext(context.Background(), `SELECT count(*) FROM inbound_invocations`).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("retained invocation rows=%d err=%v", retained, err)
	}
}

func TestCommandInvokerRejectsSymlinkAndWritableAncestors(t *testing.T) {
	directory, err := os.MkdirTemp(".", ".invoke-runtime-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- test fixture directory must be owner-traversable.
		t.Fatal(err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(directory, "runtime")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- test executable must be executable by its owner.
		t.Fatal(err)
	}
	if _, err := NewCommandInvoker(command); err != nil {
		t.Fatalf("protected command rejected: %v", err)
	}
	symlink := filepath.Join(directory, "runtime-link")
	if err := os.Symlink(command, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCommandInvoker(symlink); err == nil {
		t.Fatal("symlinked command accepted")
	}
	if err := os.Chmod(directory, 0o777); err != nil { // #nosec G302 -- test constructs an intentionally unsafe ancestor.
		t.Fatal(err)
	}
	if _, err := NewCommandInvoker(command); err == nil {
		t.Fatal("command with writable ancestor accepted")
	}
}

func TestSyncerReportsFailedRuntimeHandoffForBoundedRelayRetry(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	relayClient := &fakeInvocationRelay{fakeRelay: fakeRelay{deliveries: map[string][]relay.Delivery{}}, invocations: []relay.Invocation{{ID: "invoke-1", ConversationID: "conversation-1", TargetEndpoint: "agent/offline", TargetMachineID: "machine-a", Fence: "stable-fence", LeaseToken: "lease-1", LeaseGeneration: 1}}}
	syncer := Syncer{Mailbox: &fakeMailbox{}, Relay: relayClient, Journal: journal, Invoker: &fakeInvoker{err: errors.New("runtime unavailable")}, Now: func() time.Time { return time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC) }}
	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("failed runtime handoff reported success")
	}
	if len(relayClient.reports) != 1 || relayClient.reports[0].accepted {
		t.Fatalf("reports=%#v", relayClient.reports)
	}
	var retained int
	if err := journal.db.QueryRowContext(context.Background(), `SELECT count(*) FROM inbound_invocations`).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("retained invocation rows=%d err=%v", retained, err)
	}
}

func TestSyncerPrunesTerminalJournalRowsAfterCrashRecoveryWindow(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	if _, err := journal.ensureInvocation("accepted", "accepted-fence", now.Add(-invocationJournalRetention-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := journal.markInvocationAccepted("accepted", "accepted-fence", now.Add(-invocationJournalRetention-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ensureInvocation("failed", "failed-fence", now.Add(-invocationJournalRetention-time.Second)); err != nil {
		t.Fatal(err)
	}
	syncer := Syncer{Journal: journal}
	if err := syncer.syncInvocations(context.Background(), &fakeInvocationRelay{fakeRelay: fakeRelay{deliveries: map[string][]relay.Delivery{}}}, now); err != nil {
		t.Fatal(err)
	}
	var retained int
	if err := journal.db.QueryRowContext(context.Background(), `SELECT count(*) FROM inbound_invocations`).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("retained invocation rows=%d err=%v", retained, err)
	}
}

func TestSyncerFinalRecoveryNeverReinvokesWithoutAcceptedJournal(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	invocation := relay.Invocation{ID: "invoke-1", ConversationID: "conversation-1", TargetEndpoint: "agent/offline", TargetMachineID: "machine-a", Fence: "stable-fence", LeaseToken: "lease-4", LeaseGeneration: 4, RecoveryOnly: true}
	relayClient := &fakeInvocationRelay{fakeRelay: fakeRelay{deliveries: map[string][]relay.Delivery{}}, invocations: []relay.Invocation{invocation}}
	runtime := &fakeInvoker{}
	syncer := Syncer{Mailbox: &fakeMailbox{}, Relay: relayClient, Journal: journal, Invoker: runtime}
	if err := syncer.SyncOnce(context.Background()); err == nil {
		t.Fatal("unconfirmed final recovery reported success")
	}
	if runtime.calls != 0 || len(relayClient.reports) != 1 || relayClient.reports[0].accepted {
		t.Fatalf("runtime calls=%d reports=%#v", runtime.calls, relayClient.reports)
	}
}

func TestSyncerDoesNotInvokeRoleThatAttachedDuringCycle(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mailbox := &fakeMailbox{onAttached: func(call int) []string {
		if call == 1 {
			return nil
		}
		return []string{"agent/recipient"}
	}}
	relayClient := &fakeInvocationRelay{fakeRelay: fakeRelay{deliveries: map[string][]relay.Delivery{}}, invocations: []relay.Invocation{{ID: "invoke-1", ConversationID: "conversation-1", TargetEndpoint: "agent/recipient", TargetMachineID: "machine-a", Fence: "stable-fence", LeaseToken: "lease-1", LeaseGeneration: 1}}}
	runtime := &fakeInvoker{}
	syncer := Syncer{Mailbox: mailbox, Relay: relayClient, Journal: journal, Invoker: runtime}
	if err := syncer.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.calls != 0 || len(relayClient.reports) != 1 || !relayClient.reports[0].accepted {
		t.Fatalf("runtime calls=%d reports=%#v", runtime.calls, relayClient.reports)
	}
}

type fakeInvoker struct {
	calls  int
	fences []string
	err    error
}

func (i *fakeInvoker) Invoke(_ context.Context, invocation relay.Invocation) error {
	i.calls++
	i.fences = append(i.fences, invocation.Fence)
	return i.err
}

type invocationReport struct {
	id       string
	accepted bool
}

type fakeInvocationRelay struct {
	fakeRelay
	invocations []relay.Invocation
	reports     []invocationReport
	reportErr   error
}

func (r *fakeInvocationRelay) LeaseInvocations(context.Context) ([]relay.Invocation, error) {
	return r.invocations, nil
}

func (r *fakeInvocationRelay) ReportInvocation(_ context.Context, invocation relay.Invocation, accepted bool) error {
	r.reports = append(r.reports, invocationReport{id: invocation.ID, accepted: accepted})
	return r.reportErr
}
