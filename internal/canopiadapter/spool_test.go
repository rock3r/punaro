package canopiadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

func spoolEvent(id string) protocol.Event {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	return protocol.Event{
		SpecVersion: protocol.SpecVersion, EventID: id, Source: protocol.SourceClaudeCode,
		Machine: protocol.Machine{ID: "machine-a", Label: "machine-a"}, SessionID: "session-a",
		AgentInstanceID: "agent-a", State: protocol.StateWorking, ActivityAt: now, EmittedAt: now,
		Task: protocol.Task{Title: "Example / task"},
	}
}

func TestSpoolRetainsFailedDeliveryAndRetriesSameEvent(t *testing.T) {
	spool := Spool{Directory: t.TempDir(), MaxEvents: 4, RetryMin: time.Millisecond, RetryMax: time.Millisecond}
	input := spoolEvent("event-stable")
	if err := spool.Enqueue(input); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	err := spool.Drain(ctx, func(context.Context, protocol.Event) error {
		attempts++
		cancel()
		return errors.New("collector unavailable")
	})
	if !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("failed Drain() = %v, attempts = %d", err, attempts)
	}
	if got, err := spool.Pending(); err != nil || got != 1 {
		t.Fatalf("Pending() after failure = %d, %v", got, err)
	}
	var delivered protocol.Event
	if err := spool.Drain(context.Background(), func(_ context.Context, event protocol.Event) error {
		delivered = event
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if delivered.EventID != input.EventID {
		t.Fatalf("retried event ID = %q, want %q", delivered.EventID, input.EventID)
	}
	if got, err := spool.Pending(); err != nil || got != 0 {
		t.Fatalf("Pending() after acknowledgement = %d, %v", got, err)
	}
}

func TestSpoolMovesPastRejectedEventWithoutDroppingIt(t *testing.T) {
	spool := Spool{Directory: t.TempDir(), MaxEvents: 4, RetryMin: time.Millisecond, RetryMax: time.Millisecond}
	if err := spool.Enqueue(spoolEvent("event-a")); err != nil {
		t.Fatal(err)
	}
	if err := spool.Enqueue(spoolEvent("event-b")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rejectedID := ""
	advanced := false
	attempts := 0
	err := spool.Drain(ctx, func(_ context.Context, event protocol.Event) error {
		attempts++
		if rejectedID == "" {
			rejectedID = event.EventID
			return errors.New("collector rejected event")
		}
		if event.EventID != rejectedID {
			advanced = true
			cancel()
			return nil
		}
		if attempts >= 3 {
			cancel()
		}
		return errors.New("collector rejected event")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Drain() error = %v", err)
	}
	if !advanced {
		t.Fatal("Drain() did not attempt the independent event after a rejection")
	}
	if got, err := spool.Pending(); err != nil || got != 1 {
		t.Fatalf("Pending() = %d, %v; want rejected event retained", got, err)
	}
}

func TestSpoolIsBoundedAndDuplicateEnqueueIsIdempotent(t *testing.T) {
	spool := Spool{Directory: t.TempDir(), MaxEvents: 1}
	if err := spool.Enqueue(spoolEvent("event-a")); err != nil {
		t.Fatal(err)
	}
	if err := spool.Enqueue(spoolEvent("event-a")); err != nil {
		t.Fatalf("duplicate Enqueue() error = %v", err)
	}
	if err := spool.Enqueue(spoolEvent("event-b")); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("overflow Enqueue() error = %v, want ErrSpoolFull", err)
	}
}

func TestSpoolEnqueueReclaimsTemporaryFileLeftByCrash(t *testing.T) {
	directory := t.TempDir()
	orphan := filepath.Join(directory, ".event-crashed.tmp")
	if err := os.WriteFile(orphan, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	spool := Spool{Directory: directory, MaxEvents: 1}
	if err := spool.Enqueue(spoolEvent("event-after-crash")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan temporary still exists: %v", err)
	}
}

func TestSpoolCleanupLeavesFreshPreLockPublisherAndReclaimsItAfterAbandonment(t *testing.T) {
	spool := Spool{Directory: t.TempDir(), MaxEvents: 16}
	if err := spool.ensureDirectory(); err != nil {
		t.Fatal(err)
	}
	temporary, err := os.CreateTemp(spool.Directory, ".contention-publishing-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	path := temporary.Name()
	if err := protectSpoolFile(path, temporary); err != nil {
		_ = temporary.Close()
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.removeOrphanTemporaries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("fresh pre-lock publisher was removed: %v", err)
	}
	abandonedAt := time.Now().Add(-2 * stagingAbandonmentAge)
	if err := os.Chtimes(path, abandonedAt, abandonedAt); err != nil {
		t.Fatal(err)
	}
	if err := spool.removeOrphanTemporaries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned pre-lock publisher still exists: %v", err)
	}
}

func TestWindowsSpoolSyncFlushesPublishedDirectoryEntry(t *testing.T) {
	payload, err := os.ReadFile("spool_sync_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	for _, required := range []string{"CreateFile", "FILE_FLAG_BACKUP_SEMANTICS", "FlushFileBuffers"} {
		if !strings.Contains(source, required) {
			t.Fatalf("Windows spool publication sync is missing %q", required)
		}
	}
}

func TestWindowsSpoolLocksUseExclusiveNoReparseOpens(t *testing.T) {
	payload, err := os.ReadFile("spool_file_lock_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	for _, required := range []string{"CREATE_NEW", "OPEN_EXISTING", "FILE_FLAG_OPEN_REPARSE_POINT", "FILE_ATTRIBUTE_REPARSE_POINT", "CreateMutex", "WaitForSingleObject", "LockOSThread", "GetFinalPathNameByHandle", "strings.ToLower"} {
		if !strings.Contains(source, required) {
			t.Fatalf("Windows spool lock open is missing %q", required)
		}
	}
}

func TestSpoolQueuedEventReadsAreBoundedBeforeAllocation(t *testing.T) {
	payload, err := os.ReadFile("spool.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(payload)
	if !strings.Contains(source, "io.LimitReader") || strings.Contains(source, "os.ReadFile(path)") {
		t.Fatal("queued event read is not bounded before allocation")
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxSpoolEventBytes+1); err != nil {
		t.Fatal(err)
	}
	spool := Spool{Directory: directory, MaxEvents: 1}
	delivered := false
	if err := spool.Drain(context.Background(), func(context.Context, protocol.Event) error {
		delivered = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if delivered {
		t.Fatal("oversized queued event was delivered")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized queued event was not removed: %v", err)
	}
}

func TestSpoolRejectsUnprotectedPreexistingEvent(t *testing.T) {
	directory := t.TempDir()
	payload, err := json.Marshal(spoolEvent("foreign-event"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "foreign.json")
	// #nosec G306 -- deliberately shared permissions model an entry planted before startup.
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- deliberately unsafe test fixture.
		t.Fatal(err)
	}
	delivered := false
	spool := Spool{Directory: directory, MaxEvents: 1}
	legitimate := spoolEvent("legitimate-event")
	if err := spool.Enqueue(legitimate); err != nil {
		t.Fatalf("Enqueue() behind planted entry = %v", err)
	}
	if err := spool.Drain(context.Background(), func(_ context.Context, event protocol.Event) error {
		if event.EventID != legitimate.EventID {
			t.Fatalf("delivered planted event %q", event.EventID)
		}
		delivered = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !delivered {
		t.Fatal("legitimate event behind planted entry was not delivered")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unprotected pre-existing spool event was not removed: %v", err)
	}
}

func TestSpoolRecoversDrainLockLeftByCrashedWorker(t *testing.T) {
	directory := t.TempDir()
	spool := Spool{Directory: directory, MaxEvents: 1}
	if err := spool.Enqueue(spoolEvent("event-a")); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(directory, ".drain.lock")
	if err := os.WriteFile(lock, []byte("crashed"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-3 * time.Minute)
	if err := os.Chtimes(lock, stale, stale); err != nil {
		t.Fatal(err)
	}
	delivered := 0
	if err := spool.Drain(context.Background(), func(context.Context, protocol.Event) error {
		delivered++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if delivered != 1 {
		t.Fatalf("delivered = %d, want 1 after stale lock recovery", delivered)
	}
}

func TestSpoolSupervisorDeliversEventEnqueuedAfterStartup(t *testing.T) {
	spool := Spool{Directory: t.TempDir(), MaxEvents: 2, RetryMin: time.Millisecond, RetryMax: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	delivered := make(chan protocol.Event, 1)
	done := make(chan error, 1)
	go func() {
		done <- spool.Serve(ctx, func(_ context.Context, event protocol.Event) error {
			delivered <- event
			cancel()
			return nil
		})
	}()
	time.Sleep(20 * time.Millisecond)
	if err := spool.Enqueue(spoolEvent("event-after-start")); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-delivered:
		if event.EventID != "event-after-start" {
			t.Fatalf("delivered event = %q", event.EventID)
		}
	case <-time.After(time.Second):
		t.Fatal("supervised spool did not wake for a newly enqueued event")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve() error = %v", err)
	}
}

func TestEnqueueWaitsForActiveLockAndPersistsAfterRelease(t *testing.T) {
	directory := t.TempDir()
	lock := filepath.Join(directory, ".enqueue.lock")
	release, err := acquireSpoolLock(context.Background(), lock)
	if err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-3 * time.Second)
	if err := os.Chtimes(lock, stale, stale); err != nil {
		release()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	spool := Spool{Directory: directory, MaxEvents: 1}
	go func() { done <- spool.Enqueue(spoolEvent("event-after-contention")) }()
	select {
	case err := <-done:
		release()
		t.Fatalf("Enqueue() returned before active lock release: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Enqueue() after lock release = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Enqueue() did not resume after lock release")
	}
	if got, err := spool.Pending(); err != nil || got != 1 {
		t.Fatalf("Pending() after contention = %d, %v; want 1", got, err)
	}
}

func TestEnqueueUsesDurableContentionLaneBeforeProviderDeadline(t *testing.T) {
	directory := t.TempDir()
	release, err := acquireSpoolLock(context.Background(), filepath.Join(directory, ".enqueue.lock"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	spool := Spool{Directory: directory, MaxEvents: 1, EnqueueLockTimeout: 20 * time.Millisecond}
	go func() { done <- spool.Enqueue(spoolEvent("event-via-contention-lane")) }()
	select {
	case err := <-done:
		if err != nil {
			release()
			t.Fatalf("Enqueue() contention fallback = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		release()
		t.Fatal("Enqueue() exceeded the bounded contention wait")
	}
	if err := spool.Enqueue(spoolEvent("contention-lane-overflow")); !errors.Is(err, ErrSpoolFull) {
		release()
		t.Fatalf("second contention event = %v, want ErrSpoolFull", err)
	}
	release()
	if got, err := spool.Pending(); err != nil || got != 1 {
		t.Fatalf("Pending() after contention fallback = %d, %v; want 1", got, err)
	}
	delivered := ""
	if err := spool.Drain(context.Background(), func(_ context.Context, event protocol.Event) error {
		delivered = event.EventID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if delivered != "event-via-contention-lane" {
		t.Fatalf("contention delivery = %q", delivered)
	}
}

func TestConcurrentFallbacksDoNotRemoveARepairedContentionSlot(t *testing.T) {
	for iteration := 0; iteration < 25; iteration++ {
		directory := t.TempDir()
		spool := Spool{Directory: directory, MaxEvents: 1}
		if err := spool.ensureDirectory(); err != nil {
			t.Fatal(err)
		}
		slot := filepath.Join(directory, ".contention-000000.json")
		if err := os.WriteFile(slot, []byte("corrupt"), 0o600); err != nil {
			t.Fatal(err)
		}
		events := []protocol.Event{spoolEvent("contender-a"), spoolEvent("contender-b")}
		payloads := make([][]byte, len(events))
		for index, event := range events {
			payload, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			payloads[index] = payload
		}
		start := make(chan struct{})
		results := make(chan struct {
			id  string
			err error
		}, len(events))
		for index, event := range events {
			go func(event protocol.Event, payload []byte) {
				<-start
				results <- struct {
					id  string
					err error
				}{event.EventID, spool.enqueueContention(context.Background(), event, payload)}
			}(event, payloads[index])
		}
		close(start)
		succeeded := ""
		for range events {
			result := <-results
			if result.err == nil {
				if succeeded != "" {
					t.Fatalf("iteration %d: both fallback publications reported success", iteration)
				}
				succeeded = result.id
				continue
			}
			if !errors.Is(result.err, ErrSpoolFull) {
				t.Fatalf("iteration %d: fallback error = %v", iteration, result.err)
			}
		}
		if succeeded == "" {
			t.Fatalf("iteration %d: no fallback publication succeeded", iteration)
		}
		if got, err := spool.Pending(); err != nil || got != 1 {
			t.Fatalf("iteration %d: Pending() = %d, %v; want 1", iteration, got, err)
		}
		delivered := ""
		if err := spool.Drain(context.Background(), func(_ context.Context, event protocol.Event) error {
			delivered = event.EventID
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if delivered != succeeded {
			t.Fatalf("iteration %d: delivered %q, successful publisher was %q", iteration, delivered, succeeded)
		}
	}
}

func TestInvalidCleanupRechecksBeforeRemovingAValidReplacement(t *testing.T) {
	directory := t.TempDir()
	spool := Spool{Directory: directory, MaxEvents: 1}
	if err := spool.ensureDirectory(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, ".contention-000000.json")
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	stalePayload, err := readPrivateSpoolFile(path, maxSpoolEventBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.DecodeEvent(bytes.NewReader(stalePayload), maxSpoolEventBytes); err == nil {
		t.Fatal("corrupt fixture unexpectedly decoded")
	}
	// The stale drainer observation happened before the replacement below.
	replacement := spoolEvent("replacement-event")
	payload, err := json.Marshal(replacement)
	if err != nil {
		t.Fatal(err)
	}
	matched, created, occupied, err := spool.publishIntoContentionSlot(context.Background(), path, replacement.EventID, payload)
	if err != nil || matched || !created || occupied {
		t.Fatalf("publish replacement = matched %v, created %v, occupied %v, err %v", matched, created, occupied, err)
	}
	if err := spool.removeInvalidQueuedSpoolFile(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	delivered := ""
	if err := spool.Drain(context.Background(), func(_ context.Context, event protocol.Event) error {
		delivered = event.EventID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if delivered != replacement.EventID {
		t.Fatalf("delivered replacement = %q, want %q", delivered, replacement.EventID)
	}
}

func TestEnqueueLockedStopsBeforeMaintenanceWhenPrimaryBudgetExpires(t *testing.T) {
	spool := Spool{Directory: t.TempDir(), MaxEvents: 16}
	if err := spool.ensureDirectory(); err != nil {
		t.Fatal(err)
	}
	input := spoolEvent("expired-primary-budget")
	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := spool.enqueueLocked(ctx, input, payload); !errors.Is(err, context.Canceled) {
		t.Fatalf("enqueueLocked() = %v, want context cancellation", err)
	}
	if pending, err := spool.Pending(); err != nil || pending != 0 {
		t.Fatalf("Pending() = %d, %v; want no partially published event", pending, err)
	}
}

func TestProviderEnqueueBudgetsStayBelowClaudeHookDeadline(t *testing.T) {
	if providerEnqueueBudget >= 2*time.Second {
		t.Fatalf("provider enqueue budget = %s, must remain below Claude's two-second hook deadline", providerEnqueueBudget)
	}
	if maxPrimaryLaneBudget >= providerEnqueueBudget {
		t.Fatalf("primary budget = %s, must leave time for the durable contention lane", maxPrimaryLaneBudget)
	}
}

func TestSpoolOperationReturnsWhenHookDeadlineExpires(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	operationDone := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	startedAt := time.Now()
	err := runSpoolOperation(ctx, func() error {
		close(started)
		<-release
		close(operationDone)
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runSpoolOperation() = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(startedAt); elapsed > 500*time.Millisecond {
		t.Fatalf("deadline-bounded spool operation took %s", elapsed)
	}
	<-started
	close(release)
	select {
	case <-operationDone:
	case <-time.After(time.Second):
		t.Fatal("blocked spool operation did not finish after release")
	}
}
