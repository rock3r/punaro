package canopiadapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

func TestActiveEnqueueLockIsHeartbeatedAndNotReclaimed(t *testing.T) {
	directory := t.TempDir()
	lock := filepath.Join(directory, ".enqueue.lock")
	release, err := acquireSpoolLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	stale := time.Now().Add(-3 * time.Second)
	if err := os.Chtimes(lock, stale, stale); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	secondRelease, err := acquireSpoolLock(lock)
	if err == nil {
		secondRelease()
		t.Fatal("active enqueue lock was reclaimed")
	}
}
