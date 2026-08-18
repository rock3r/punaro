package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	punarorelease "github.com/rock3r/punaro/internal/release"
)

func TestRunHoldsLeaseUntilSupervisorExits(t *testing.T) {
	if dir := os.Getenv("PUNARO_BOOTSTRAP_RUN_LEASE_PROBE"); dir != "" {
		if _, err := acquireRunLease(dir); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, RunRequest{
			Directory:     dir,
			HealthTimeout: 20 * time.Millisecond,
			Start: func(ctx context.Context, _ ChildSpec) (Process, error) {
				close(started)
				return blockingProcess(ctx), nil
			},
		})
	}()
	select {
	case <-started:
	case err := <-errCh:
		t.Fatalf("run exited early: %v", err)
	case <-time.After(time.Second):
		t.Fatal("run did not start")
	}
	probe := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestRunHoldsLeaseUntilSupervisorExits$") // #nosec G204,G702 -- same test binary.
	probe.Env = append(os.Environ(), "PUNARO_BOOTSTRAP_RUN_LEASE_PROBE="+dir)
	if err := probe.Run(); err == nil || probe.ProcessState.ExitCode() != 3 {
		t.Fatalf("active run did not hold the lease: err=%v code=%v", err, probe.ProcessState)
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	released := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestRunHoldsLeaseUntilSupervisorExits$") // #nosec G204,G702 -- same test binary.
	released.Env = append(os.Environ(), "PUNARO_BOOTSTRAP_RUN_LEASE_PROBE="+dir)
	if err := released.Run(); err != nil {
		t.Fatalf("run lease was not released: %v", err)
	}
}

func TestRunClearsPIDFileOnExit(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, RunRequest{
			Directory:     dir,
			HealthTimeout: 20 * time.Millisecond,
			afterPrepare: func() {
				if err := writeRunPID(dir, os.Getpid(), os.Args[0]); err != nil {
					t.Error(err)
				}
			},
			Start: func(ctx context.Context, spec ChildSpec) (Process, error) {
				if err := writeReady(spec.Env); err != nil {
					return nil, err
				}
				close(started)
				return blockingProcess(ctx), nil
			},
		})
	}()
	select {
	case <-started:
	case err := <-errCh:
		t.Fatalf("run exited early: %v", err)
	case <-time.After(time.Second):
		t.Fatal("run did not start")
	}
	if _, err := os.Stat(filepath.Join(dir, runPIDFile)); err != nil {
		t.Fatalf("run.pid missing during run: %v", err)
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, runPIDFile)); !os.IsNotExist(err) {
		t.Fatal("run.pid survived supervisor exit")
	}
}

func TestRunExitsWhenSameIdentityRepairReplacesCurrent(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	digest := payloadDigest("current-adapter")
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 40 * time.Millisecond,
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			go func() {
				time.Sleep(30 * time.Millisecond)
				current := filepath.Join(dir, currentSlot)
				_ = os.WriteFile(filepath.Join(current, artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)), []byte("repaired-adapter"), 0o600)
				writeSlotRecordGeneration(t, current, "v0.1.0", 1, digest, 1)
			}()
			return blockingProcess(context.Background()), nil
		},
	})
	if !errors.Is(err, errSlotChanged) {
		t.Fatalf("same-identity repair err=%v", err)
	}
}

func TestRunTreatsCanceledStartAsCleanShutdown(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := Run(ctx, RunRequest{
		Directory:     dir,
		HealthTimeout: 40 * time.Millisecond,
		afterPrepare:  cancel,
		Start: func(ctx context.Context, _ ChildSpec) (Process, error) {
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatalf("canceled start err=%v", err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("canceled start entered recovery-only")
	}
}

func TestFailOrRollbackKeepsRecoveryWhenCatalogTimesOut(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	err := failOrRollback(context.Background(), RunRequest{
		Directory: dir,
		Origin:    "https://127.0.0.1:1/releases",
		Keys:      map[string]ed25519.PublicKey{"k": make(ed25519.PublicKey, ed25519.PublicKeySize)},
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	}, startOrDefault(RunRequest{}), slotState{Release: "v0.2.0", Sequence: 2, ManifestSHA256: payloadDigest("current-adapter")}, recoveryUnhealthy)
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("timed-out catalog rollback err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("timed-out catalog rollback did not enter recovery-only")
	}
}

func TestRollbackIfAllowedAbortsWhenContextCanceled(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	origin := newSignedOrigin(t, originSpec{payload: "current-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	allowPreviousInCatalog(t, origin, "v0.1.0", 1, payloadDigest("previous-adapter"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	unlocked, _, err := rollbackIfAllowed(ctx, RunRequest{
		Directory: dir,
		Origin:    origin.URL,
		Keys:      origin.Keys,
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	}, slotState{Release: "v0.2.0", Sequence: 2, ManifestSHA256: payloadDigest("current-adapter")})
	if unlocked || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled rollback unlocked=%v err=%v", unlocked, err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("canceled rollback entered recovery-only")
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || status.Previous != "v0.1.0" {
		t.Fatalf("canceled rollback mutated slots status=%#v", status)
	}
}

func TestRunRequiresCurrentAdapter(t *testing.T) {
	dir := privateDir(t)
	err := Run(context.Background(), RunRequest{Directory: dir, HealthTimeout: time.Millisecond})
	if err == nil {
		t.Fatal("run without a current adapter succeeded")
	}
}

func TestRunWaitsInRecoveryUntilItIsCleared(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	writeRecoveryOnly(t, dir)
	noticed := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(context.Background(), RunRequest{
			Directory:    dir,
			WaitRecovery: true,
			OnRecoveryOnly: func() {
				select {
				case noticed <- struct{}{}:
				default:
				}
			},
			Start: func(context.Context, ChildSpec) (Process, error) {
				t.Error("started while recovery-only")
				return finishedProcess(nil), nil
			},
		})
	}()
	select {
	case <-noticed:
	case err := <-errCh:
		t.Fatalf("recovery wait exited early: %v", err)
	case <-time.After(time.Second):
		t.Fatal("recovery wait did not start")
	}
	if err := clearRecovery(dir); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, errSlotChanged) {
			t.Fatalf("recovery cleared err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("recovery wait did not exit after publication")
	}
}

func TestRunLeavesRecoveryWaitOnCancel(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	writeRecoveryOnly(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, RunRequest{
			Directory:    dir,
			WaitRecovery: true,
			Start: func(context.Context, ChildSpec) (Process, error) {
				t.Error("started while recovery-only")
				return finishedProcess(nil), nil
			},
		})
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrRecoveryOnly) {
			t.Fatalf("canceled recovery wait err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled recovery wait did not return")
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("cancel cleared recovery-only")
	}
}

func TestRunRefusesRecoveryOnly(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "healthy-adapter")
	writeRecoveryOnly(t, dir)
	err := Run(context.Background(), RunRequest{Directory: dir, HealthTimeout: time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "recovery-only") {
		t.Fatalf("recovery-only run err=%v", err)
	}
}

func TestRunKeepsAliveUnenrolledCurrent(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, RunRequest{
			Directory:     dir,
			HealthTimeout: 20 * time.Millisecond,
			Start: func(ctx context.Context, spec ChildSpec) (Process, error) {
				close(started)
				if spec.Path != runningAdapterPath(dir) {
					t.Errorf("started %s", spec.Path)
				}
				if readyPathFromEnv(spec.Env) != filepath.Join(dir, readyFile) {
					t.Errorf("ready env=%v", spec.Env)
				}
				return blockingProcess(ctx), nil
			},
		})
	}()
	select {
	case <-started:
	case err := <-errCh:
		t.Fatalf("run exited early: %v", err)
	case <-time.After(time.Second):
		t.Fatal("run did not start the current adapter")
	}
	time.Sleep(40 * time.Millisecond)
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("unenrolled current entered recovery-only")
	}
}

func TestRunEntersRecoveryWhenPreviousSlotIsCorrupt(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	previous := filepath.Join(dir, previousSlot)
	if err := os.Mkdir(previous, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(previous, slotRecord), []byte(`{"schema":1`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 20 * time.Millisecond,
		Start: func(context.Context, ChildSpec) (Process, error) {
			return blockingProcess(context.Background()), nil
		},
	})
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("corrupt previous err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("corrupt previous did not enter recovery-only")
	}
}

func TestRunEntersRecoveryWhenCurrentSlotMissing(t *testing.T) {
	dir := privateDir(t)
	err := Run(context.Background(), RunRequest{Directory: dir, HealthTimeout: time.Millisecond})
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("missing current err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("missing current did not enter recovery-only")
	}
}

func TestRunStartsSnapshotWhenCurrentSlotChanges(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	var startedPath string
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 40 * time.Millisecond,
		afterPrepare: func() {
			if err := os.Rename(filepath.Join(dir, currentSlot), filepath.Join(dir, previousSlot)); err != nil {
				t.Fatal(err)
			}
			writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "next-adapter")
		},
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			startedPath = spec.Path
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			return finishedProcess(nil), nil
		},
	})
	if !errors.Is(err, errSlotChanged) {
		t.Fatalf("snapshot after publish err=%v", err)
	}
	if startedPath != "" {
		t.Fatalf("started %s after current changed", startedPath)
	}
}

func TestRunExitsWhenCurrentChangesAfterReady(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	var child *fakeProcess
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 40 * time.Millisecond,
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			go func() {
				time.Sleep(30 * time.Millisecond)
				_ = os.Rename(filepath.Join(dir, currentSlot), filepath.Join(dir, previousSlot))
				next := filepath.Join(dir, currentSlot)
				_ = os.Mkdir(next, 0o700)
				_ = os.WriteFile(filepath.Join(next, artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)), []byte("next-adapter"), 0o600)
				writeSlotRecord(t, next, "v0.2.0", 2, payloadDigest("next-adapter"))
			}()
			child = blockingProcess(context.Background()).(*fakeProcess)
			return child, nil
		},
	})
	if !errors.Is(err, errSlotChanged) {
		t.Fatalf("post-ready slot change err=%v", err)
	}
	if child == nil || !child.stopped.Load() {
		t.Fatal("slot change did not request a graceful stop")
	}
	if child.killed.Load() {
		t.Fatal("slot change force-killed a child that stopped")
	}
}

func TestRunTreatsInvalidRecoveryAsRecoveryOnly(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	if err := os.WriteFile(filepath.Join(dir, recoveryFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), RunRequest{
		Directory: dir,
		Start: func(context.Context, ChildSpec) (Process, error) {
			t.Fatal("started with invalid recovery record")
			return finishedProcess(nil), nil
		},
	})
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("invalid recovery err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("invalid recovery did not stay recovery-only")
	}
}

func TestRunExitsWhenCurrentChangesDuringReadyWindow(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	var child *fakeProcess
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 200 * time.Millisecond,
		HealthWindow:  200 * time.Millisecond,
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			go func() {
				time.Sleep(30 * time.Millisecond)
				_ = os.Rename(filepath.Join(dir, currentSlot), filepath.Join(dir, previousSlot))
				next := filepath.Join(dir, currentSlot)
				_ = os.Mkdir(next, 0o700)
				_ = os.WriteFile(filepath.Join(next, artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)), []byte("next-adapter"), 0o600)
				writeSlotRecord(t, next, "v0.2.0", 2, payloadDigest("next-adapter"))
			}()
			child = blockingProcess(context.Background()).(*fakeProcess)
			return child, nil
		},
	})
	if !errors.Is(err, errSlotChanged) {
		t.Fatalf("ready-window slot change err=%v", err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("ready-window slot change entered recovery-only")
	}
	if child == nil || !child.stopped.Load() {
		t.Fatal("ready-window slot change did not request a graceful stop")
	}
	if child.killed.Load() {
		t.Fatal("ready-window slot change force-killed a child that stopped")
	}
}

func TestRunExitsWhenCurrentChangesDuringHealth(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	var child *fakeProcess
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 200 * time.Millisecond,
		Start: func(context.Context, ChildSpec) (Process, error) {
			go func() {
				time.Sleep(30 * time.Millisecond)
				_ = os.Rename(filepath.Join(dir, currentSlot), filepath.Join(dir, previousSlot))
				next := filepath.Join(dir, currentSlot)
				_ = os.Mkdir(next, 0o700)
				_ = os.WriteFile(filepath.Join(next, artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)), []byte("next-adapter"), 0o600)
				writeSlotRecord(t, next, "v0.2.0", 2, payloadDigest("next-adapter"))
			}()
			child = blockingProcess(context.Background()).(*fakeProcess)
			return child, nil
		},
	})
	if !errors.Is(err, errSlotChanged) {
		t.Fatalf("health-window slot change err=%v", err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("health-window slot change entered recovery-only")
	}
	if child == nil || !child.stopped.Load() {
		t.Fatal("health-window slot change did not request a graceful stop")
	}
	if child.killed.Load() {
		t.Fatal("health-window slot change force-killed a child that stopped")
	}
}

func TestRunEntersRecoveryWhenKeysFileInvalid(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	if err := os.WriteFile(filepath.Join(dir, directoryKeysFile), []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), RunRequest{
		Directory: dir,
		Start: func(context.Context, ChildSpec) (Process, error) {
			t.Fatal("started with invalid keys")
			return finishedProcess(nil), nil
		},
	})
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("invalid keys err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("invalid keys did not enter recovery-only")
	}
}

func TestRunDoesNotStartAfterPreparedSlotChanged(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	var started bool
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 40 * time.Millisecond,
		afterPrepare: func() {
			if err := os.Rename(filepath.Join(dir, currentSlot), filepath.Join(dir, previousSlot)); err != nil {
				t.Fatal(err)
			}
			writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "next-adapter")
		},
		Start: func(context.Context, ChildSpec) (Process, error) {
			started = true
			return finishedProcess(nil), nil
		},
	})
	if !errors.Is(err, errSlotChanged) {
		t.Fatalf("prepared slot change err=%v", err)
	}
	if started {
		t.Fatal("started adapter after current slot changed")
	}
	if recoveryOnly(t, dir) {
		t.Fatal("prepared slot change entered recovery-only")
	}
}

func TestFailIfSlotChangedWhenCurrentMissing(t *testing.T) {
	dir := privateDir(t)
	err := failIfSlotChanged(dir, slotState{Release: "v0.1.0", Sequence: 1, ManifestSHA256: payloadDigest("current-adapter")})
	if !errors.Is(err, errSlotChanged) {
		t.Fatalf("missing current err=%v", err)
	}
}

func TestEnterRecoveryOnlyRefusesWhenSlotChanged(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "next-adapter")
	err := enterRecoveryOnly(dir, recoveryUnhealthy, slotState{Release: "v0.1.0", Sequence: 1, ManifestSHA256: payloadDigest("current-adapter")})
	if !errors.Is(err, errSlotChanged) {
		t.Fatalf("enter recovery err=%v", err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("stale identity wrote recovery-only")
	}
}

func TestRunDoesNotEnterRecoveryWhenCurrentSlotChanged(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 40 * time.Millisecond,
		Start: func(context.Context, ChildSpec) (Process, error) {
			if err := os.Rename(filepath.Join(dir, currentSlot), filepath.Join(dir, previousSlot)); err != nil {
				return nil, err
			}
			writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "next-adapter")
			return finishedProcess(errors.New("adapter exited")), nil
		},
	})
	if !errors.Is(err, errSlotChanged) {
		t.Fatalf("concurrent publish err=%v", err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("concurrent publish entered recovery-only")
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || status.Previous != "v0.1.0" {
		t.Fatalf("status=%#v", status)
	}
}

func TestRunFailsWhenHealthyChildExits(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 20 * time.Millisecond,
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			return finishedProcess(nil), nil
		},
	})
	if !errors.Is(err, errChildExited) {
		t.Fatalf("healthy child exit err=%v", err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("unexpected healthy exit entered recovery-only")
	}
}

func TestRunEntersRecoveryWhenJournalIsUnreadable(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	if err := os.WriteFile(filepath.Join(dir, journalFile), []byte(`{"schema":1`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run(context.Background(), RunRequest{
		Directory: dir,
		Start: func(context.Context, ChildSpec) (Process, error) {
			t.Fatal("started with an unreadable journal")
			return finishedProcess(nil), nil
		},
	})
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("unreadable journal err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("unreadable journal did not enter recovery-only")
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFile)); !os.IsNotExist(err) {
		t.Fatal("unreadable journal was not quarantined")
	}
}

func TestStatusQuarantinesMalformedJournalIntoRecovery(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	if err := os.WriteFile(filepath.Join(dir, journalFile), []byte(`{"schema":1`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Status(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFile)); !os.IsNotExist(err) {
		t.Fatal("malformed journal survived status")
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("status did not park after a malformed journal")
	}
}

func TestUpdateSucceedsAfterMalformedJournalRecovery(t *testing.T) {
	dir := privateDir(t)
	if err := os.WriteFile(filepath.Join(dir, journalFile), []byte(`{"schema":1`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRecoveryOnly(t, dir)
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	if _, err := Update(Request{
		Directory: dir,
		Origin:    origin.URL,
		Keys:      origin.Keys,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("signed update left recovery-only after a malformed journal")
	}
	if _, err := os.Lstat(filepath.Join(dir, journalFile)); !os.IsNotExist(err) {
		t.Fatal("malformed journal survived a signed update")
	}
}

func TestRunClearsHealthDirectoryBeforeStart(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	if err := os.Mkdir(filepath.Join(dir, readyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	var started bool
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 20 * time.Millisecond,
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			started = true
			if _, err := os.Lstat(filepath.Join(dir, readyFile)); !os.IsNotExist(err) {
				t.Errorf("ready path still present: %v", err)
			}
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			return finishedProcess(nil), nil
		},
	})
	if !errors.Is(err, errChildExited) {
		t.Fatalf("cleared health start err=%v", err)
	}
	if !started {
		t.Fatal("did not start after clearing health directory")
	}
}

func TestRunRejectsExpiredCatalogOnRollback(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	start := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	origin := newSignedOrigin(t, originSpec{
		payload:         "current-adapter",
		goos:            runtime.GOOS,
		goarch:          runtime.GOARCH,
		release:         "v0.2.0",
		sequence:        2,
		catalogSequence: 2,
		expiresAt:       start.Add(time.Second),
	})
	allowPreviousInCatalog(t, origin, "v0.1.0", 1, payloadDigest("previous-adapter"))
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		Keys:          origin.Keys,
		HealthTimeout: 1200 * time.Millisecond,
		Now:           start,
		Start: func(context.Context, ChildSpec) (Process, error) {
			return blockingProcess(context.Background()), nil
		},
	})
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("expired catalog rollback err=%v", err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || !status.RecoveryOnly {
		t.Fatalf("status=%#v", status)
	}
}

func TestRunEntersRecoveryWhenFirstSlotHealthIsInvalid(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "current-adapter")
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 40 * time.Millisecond,
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			if err := os.WriteFile(readyPathFromEnv(spec.Env), []byte(`{"schema":2,"status":"healthy"}`), 0o600); err != nil {
				return nil, err
			}
			return blockingProcess(context.Background()), nil
		},
	})
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("invalid first-slot health err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("invalid first-slot health did not enter recovery-only")
	}
}

func TestRunRecoversWhenCurrentExitsBeforeReady(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "broken-adapter")
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 50 * time.Millisecond,
		Start: func(context.Context, ChildSpec) (Process, error) {
			return finishedProcess(errors.New("adapter exited")), nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "recovery-only") {
		t.Fatalf("broken current err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("broken current did not enter recovery-only")
	}
}

func TestRunRollsBackUnhealthyCurrentWhenCatalogAllowsPrevious(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	origin := newSignedOrigin(t, originSpec{payload: "current-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	allowPreviousInCatalog(t, origin, "v0.1.0", 1, payloadDigest("previous-adapter"))
	catalog, err := fetchVerifiedCatalog(context.Background(), Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if !catalog.Allows("v0.1.0", 1, payloadDigest("previous-adapter")) {
		t.Fatalf("catalog does not allow previous: %+v", catalog)
	}

	var starts int
	err = Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		Keys:          origin.Keys,
		HealthTimeout: 40 * time.Millisecond,
		Now:           time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			starts++
			if starts == 1 {
				return blockingProcess(context.Background()), nil
			}
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			return finishedProcess(nil), nil
		},
	})
	if !errors.Is(err, errChildExited) {
		t.Fatalf("rollback start err=%v", err)
	}
	if starts != 2 {
		t.Fatalf("starts=%d", starts)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.Previous != "v0.2.0" || status.RecoveryOnly {
		t.Fatalf("status=%#v", status)
	}
}

func TestRunLoadsKeysFromDirectory(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	origin := newSignedOrigin(t, originSpec{payload: "current-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	allowPreviousInCatalog(t, origin, "v0.1.0", 1, payloadDigest("previous-adapter"))
	keys, err := punarorelease.EncodePublicKeys(testKeyID, origin.Keys[testKeyID])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, directoryKeysFile), keys, 0o600); err != nil {
		t.Fatal(err)
	}
	var starts int
	if err := Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		HealthTimeout: 40 * time.Millisecond,
		Now:           time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			starts++
			if starts == 1 {
				return blockingProcess(context.Background()), nil
			}
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			return finishedProcess(nil), nil
		},
	}); !errors.Is(err, errChildExited) {
		t.Fatalf("directory keys start err=%v", err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.RecoveryOnly {
		t.Fatalf("status=%#v", status)
	}
}

func TestRunRejectsStaleCatalogSequenceOnRollback(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	origin := newSignedOrigin(t, originSpec{payload: "previous-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.1.0", sequence: 1, catalogSequence: 1})
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		Keys:          origin.Keys,
		HealthTimeout: 20 * time.Millisecond,
		Now:           time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Start: func(context.Context, ChildSpec) (Process, error) {
			return blockingProcess(context.Background()), nil
		},
	})
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("stale catalog rollback err=%v", err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || !status.RecoveryOnly {
		t.Fatalf("status=%#v", status)
	}
}

func TestRunEntersRecoveryWhenCatalogDisallowsPrevious(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	origin := newSignedOrigin(t, originSpec{payload: "current-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		Keys:          origin.Keys,
		HealthTimeout: 20 * time.Millisecond,
		Now:           time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Start: func(context.Context, ChildSpec) (Process, error) {
			return blockingProcess(context.Background()), nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "recovery-only") {
		t.Fatalf("disallowed previous err=%v", err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.2.0" || !status.RecoveryOnly {
		t.Fatalf("status=%#v", status)
	}
}

func TestRunEntersRecoveryWhenKeysMissingAndPreviousExists(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		HealthTimeout: 20 * time.Millisecond,
		Start: func(context.Context, ChildSpec) (Process, error) {
			return blockingProcess(context.Background()), nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "recovery-only") {
		t.Fatalf("missing keys err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("missing keys did not enter recovery-only")
	}
}

func TestRunDoesNotUndoSuccessfulRollbackOnLaterRestart(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	origin := newSignedOrigin(t, originSpec{payload: "current-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	allowPreviousInCatalog(t, origin, "v0.1.0", 1, payloadDigest("previous-adapter"))
	var starts int
	if err := Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		Keys:          origin.Keys,
		HealthTimeout: 40 * time.Millisecond,
		Now:           time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			starts++
			if starts == 1 {
				return blockingProcess(context.Background()), nil
			}
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			return finishedProcess(nil), nil
		},
	}); !errors.Is(err, errChildExited) {
		t.Fatalf("first rollback err=%v", err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.Previous != "v0.2.0" || status.RecoveryOnly {
		t.Fatalf("after rollback status=%#v", status)
	}
	err = Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		Keys:          origin.Keys,
		HealthTimeout: 20 * time.Millisecond,
		Now:           time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Start: func(context.Context, ChildSpec) (Process, error) {
			return finishedProcess(errors.New("adapter exited")), nil
		},
	})
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("later restart err=%v", err)
	}
	status, err = Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.Previous != "v0.2.0" || !status.RecoveryOnly {
		t.Fatalf("later restart undid rollback status=%#v", status)
	}
}

func TestRunAllowsRollbackAfterLaterSignedUpdate(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	origin := newSignedOrigin(t, originSpec{payload: "current-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	allowPreviousInCatalog(t, origin, "v0.1.0", 1, payloadDigest("previous-adapter"))
	var starts int
	if err := Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		Keys:          origin.Keys,
		HealthTimeout: 40 * time.Millisecond,
		Now:           time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			starts++
			if starts == 1 {
				return blockingProcess(context.Background()), nil
			}
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			return finishedProcess(nil), nil
		},
	}); !errors.Is(err, errChildExited) {
		t.Fatalf("first update rollback err=%v", err)
	}
	if err := os.RemoveAll(filepath.Join(dir, previousSlot)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, currentSlot), filepath.Join(dir, previousSlot)); err != nil {
		t.Fatal(err)
	}
	writeAdapterSlot(t, dir, currentSlot, "v0.3.0", 3, "next-adapter")
	writeAccepted(t, dir, "v0.3.0", 3, 3, payloadDigest("next-adapter"))
	origin = newSignedOrigin(t, originSpec{payload: "next-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.3.0", sequence: 3, catalogSequence: 3})
	allowPreviousInCatalog(t, origin, "v0.1.0", 1, payloadDigest("previous-adapter"))
	starts = 0
	if err := Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		Keys:          origin.Keys,
		HealthTimeout: 40 * time.Millisecond,
		Now:           time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			starts++
			if starts == 1 {
				return blockingProcess(context.Background()), nil
			}
			if err := writeReady(spec.Env); err != nil {
				return nil, err
			}
			return finishedProcess(nil), nil
		},
	}); !errors.Is(err, errChildExited) {
		t.Fatalf("later update rollback err=%v", err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.Previous != "v0.3.0" || status.RecoveryOnly {
		t.Fatalf("post-update rollback status=%#v", status)
	}
}

func TestRunRollsBackOnlyOnce(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	origin := newSignedOrigin(t, originSpec{payload: "current-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	allowPreviousInCatalog(t, origin, "v0.1.0", 1, payloadDigest("previous-adapter"))
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		Keys:          origin.Keys,
		HealthTimeout: 20 * time.Millisecond,
		Now:           time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Start: func(context.Context, ChildSpec) (Process, error) {
			return finishedProcess(errors.New("adapter exited")), nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "recovery-only") {
		t.Fatalf("double failure err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("second failure did not enter recovery-only")
	}
}

func TestRunRejectsReadySymlink(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, previousSlot, "v0.1.0", 1, "previous-adapter")
	writeAdapterSlot(t, dir, currentSlot, "v0.2.0", 2, "current-adapter")
	writeAccepted(t, dir, "v0.2.0", 2, 2, strings.Repeat("c", 64))
	origin := newSignedOrigin(t, originSpec{payload: "current-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH, release: "v0.2.0", sequence: 2, catalogSequence: 2})
	err := Run(context.Background(), RunRequest{
		Directory:     dir,
		Origin:        origin.URL,
		Keys:          origin.Keys,
		HealthTimeout: 40 * time.Millisecond,
		Now:           time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
		Start: func(_ context.Context, spec ChildSpec) (Process, error) {
			ready := readyPathFromEnv(spec.Env)
			target := filepath.Join(filepath.Dir(ready), "elsewhere")
			if err := os.WriteFile(target, []byte(`{"schema":1,"status":"healthy"}`), 0o600); err != nil {
				return nil, err
			}
			if err := os.Symlink(target, ready); err != nil {
				return nil, err
			}
			return blockingProcess(context.Background()), nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "recovery-only") {
		t.Fatalf("symlink ready err=%v", err)
	}
}

func TestSeedCheckoutRefusesInvalidRecoveryOnSignedSlot(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "signed-adapter")
	if err := os.WriteFile(filepath.Join(dir, recoveryFile), []byte(`{"schema":1`), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter := filepath.Join(t.TempDir(), "punaro-adapter")
	if err := os.WriteFile(adapter, []byte("checkout-adapter"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := SeedLocalCheckout(dir, adapter)
	if err == nil || !strings.Contains(err.Error(), "recovery-only") {
		t.Fatalf("invalid recovery seed err=%v", err)
	}
}

func TestSeedCheckoutRefusesSignedRecoveryOnly(t *testing.T) {
	dir := privateDir(t)
	writeAdapterSlot(t, dir, currentSlot, "v0.1.0", 1, "signed-adapter")
	writeRecoveryOnly(t, dir)
	adapter := filepath.Join(t.TempDir(), "punaro-adapter")
	if err := os.WriteFile(adapter, []byte("checkout-adapter"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := SeedLocalCheckout(dir, adapter)
	if err == nil || !strings.Contains(err.Error(), "recovery-only") {
		t.Fatalf("signed recovery seed err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("refused seed cleared recovery-only")
	}
}

func TestSeedLocalCheckoutClearsRecoveryOnly(t *testing.T) {
	dir := privateDir(t)
	writeRecoveryOnly(t, dir)
	adapter := filepath.Join(t.TempDir(), "punaro-adapter")
	if err := os.WriteFile(adapter, []byte("checkout-adapter"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SeedLocalCheckout(dir, adapter); err != nil {
		t.Fatal(err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("seed left recovery-only")
	}
}

func TestSeedLocalCheckoutLeavesSignedHistoryUnblocked(t *testing.T) {
	dir := privateDir(t)
	adapter := filepath.Join(t.TempDir(), "punaro-adapter")
	if err := os.WriteFile(adapter, []byte("checkout-adapter"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SeedLocalCheckout(dir, adapter); err != nil {
		t.Fatal(err)
	}
	origin := newSignedOrigin(t, originSpec{payload: "signed-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH})
	result, err := Update(Request{
		Directory: dir,
		Origin:    origin.URL,
		Keys:      origin.Keys,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Release != "v0.1.0" || result.Sequence != 1 {
		t.Fatalf("result=%#v", result)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.Previous != localCheckoutRelease {
		t.Fatalf("status=%#v", status)
	}
}

func TestSeedLocalCheckoutPreservesSignedAcceptedState(t *testing.T) {
	dir := privateDir(t)
	origin := newSignedOrigin(t, originSpec{payload: "signed-adapter", goos: runtime.GOOS, goarch: runtime.GOARCH})
	if _, err := Update(Request{
		Directory: dir,
		Origin:    origin.URL,
		Keys:      origin.Keys,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	writeAdapterSlot(t, dir, previousSlot, localCheckoutRelease, 1, "old-checkout")
	if _, err := Rollback(dir); err != nil {
		t.Fatal(err)
	}
	adapter := filepath.Join(t.TempDir(), "punaro-adapter")
	if err := os.WriteFile(adapter, []byte("new-checkout"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SeedLocalCheckout(dir, adapter); err != nil {
		t.Fatal(err)
	}
	accepted, err := loadAccepted(dir)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Release != "v0.1.0" || accepted.ReleaseSequence != 1 {
		t.Fatalf("accepted=%#v", accepted)
	}
}

func TestUpdatePersistsDirectoryKeys(t *testing.T) {
	dir := privateDir(t)
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	if _, err := Update(Request{
		Directory: dir,
		Origin:    origin.URL,
		Keys:      origin.Keys,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadDirectoryKeys(dir)
	if err != nil || len(loaded) != 1 {
		t.Fatalf("persisted keys=%v err=%v", loaded, err)
	}
}

func TestUpdateClearsRecoveryOnly(t *testing.T) {
	dir := privateDir(t)
	writeRecoveryOnly(t, dir)
	origin := newSignedOrigin(t, originSpec{payload: testArtifact, goos: runtime.GOOS, goarch: runtime.GOARCH})
	if _, err := Update(Request{
		Directory: dir,
		Origin:    origin.URL,
		Keys:      origin.Keys,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		Now:       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	if recoveryOnly(t, dir) {
		t.Fatal("successful update left recovery-only")
	}
}

func TestRunEntersRecoveryWhenCurrentAdapterMissing(t *testing.T) {
	dir := privateDir(t)
	current := filepath.Join(dir, currentSlot)
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSlotRecord(t, current, "v0.1.0", 1, strings.Repeat("a", 64))
	err := Run(context.Background(), RunRequest{
		Directory: dir,
		Start: func(context.Context, ChildSpec) (Process, error) {
			t.Fatal("launched without an adapter")
			return finishedProcess(nil), nil
		},
	})
	if !errors.Is(err, ErrRecoveryOnly) {
		t.Fatalf("missing adapter err=%v", err)
	}
	if !recoveryOnly(t, dir) {
		t.Fatal("missing adapter did not enter recovery-only")
	}
}

func TestRunDoesNotLaunchUnexpectedNames(t *testing.T) {
	dir := privateDir(t)
	current := filepath.Join(dir, currentSlot)
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, "not-an-adapter"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSlotRecord(t, current, "v0.1.0", 1, strings.Repeat("a", 64))
	err := Run(context.Background(), RunRequest{
		Directory: dir,
		Start: func(context.Context, ChildSpec) (Process, error) {
			t.Fatal("launched an unexpected child")
			return finishedProcess(nil), nil
		},
	})
	if err == nil {
		t.Fatal("missing adapter name was launched")
	}
}

func writeAdapterSlot(t *testing.T, directory, slot, release string, sequence int64, payload string) {
	t.Helper()
	path := filepath.Join(directory, slot)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(payload))
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(path, artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH)), []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSlotRecord(t, path, release, sequence, digest)
}

func writeSlotRecord(t *testing.T, slotDir, release string, sequence int64, digest string) {
	writeSlotRecordGeneration(t, slotDir, release, sequence, digest, 0)
}

func writeSlotRecordGeneration(t *testing.T, slotDir, release string, sequence int64, digest string, generation int64) {
	t.Helper()
	body, err := json.Marshal(slotState{Schema: 1, Release: release, Sequence: sequence, ManifestSHA256: digest, Generation: generation})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slotDir, slotRecord), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeAccepted(t *testing.T, directory, release string, sequence, catalogSequence int64, digest string) {
	t.Helper()
	if err := saveAccepted(directory, acceptedState{
		Schema:          1,
		Release:         release,
		ReleaseSequence: sequence,
		CatalogSequence: catalogSequence,
		ManifestSHA256:  digest,
	}); err != nil {
		t.Fatal(err)
	}
}

func writeRecoveryOnly(t *testing.T, directory string) {
	t.Helper()
	if err := enterRecoveryOnly(directory, "candidate-unhealthy", slotState{}); err != nil {
		t.Fatal(err)
	}
}

func recoveryOnly(t *testing.T, directory string) bool {
	t.Helper()
	recovery, err := loadRecovery(directory)
	if err != nil {
		t.Fatal(err)
	}
	return recovery.Mode == recoveryMode
}

func runningAdapterPath(directory string) string {
	return filepath.Join(directory, runningSlot, artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH))
}

func payloadDigest(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func readyPathFromEnv(env []string) string {
	prefix := readyEnv + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix)
		}
	}
	return ""
}

func writeReady(env []string) error {
	path := readyPathFromEnv(env)
	if path == "" {
		return errors.New("ready path missing")
	}
	return os.WriteFile(path, []byte(`{"schema":1,"status":"healthy"}`), 0o600)
}

func allowPreviousInCatalog(t *testing.T, origin *signedOrigin, release string, sequence int64, digest string) {
	t.Helper()
	currentBody := origin.Files[punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile]
	current, err := punarorelease.ParseCatalog(currentBody)
	if err != nil {
		t.Fatal(err)
	}
	current.MinimumSafeSequence = 1
	current.Releases = append(current.Releases, punarorelease.CatalogRelease{
		Release:        release,
		Sequence:       sequence,
		ManifestPath:   release + "/" + punarorelease.ReleaseManifestFile,
		ManifestLength: 32,
		ManifestSHA256: digest,
	})
	body, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := punarorelease.Sign(body, testKeyID, origin.priv)
	if err != nil {
		t.Fatal(err)
	}
	sigJSON, err := punarorelease.EncodeEnvelope(sig)
	if err != nil {
		t.Fatal(err)
	}
	origin.Files[punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogFile] = body
	origin.Files[punarorelease.CatalogReleaseName+"/"+punarorelease.CatalogSignatureFile] = sigJSON
}

type fakeProcess struct {
	done    chan struct{}
	err     error
	once    sync.Once
	stopped atomic.Bool
	killed  atomic.Bool
}

func blockingProcess(ctx context.Context) Process {
	proc := &fakeProcess{done: make(chan struct{})}
	go func() {
		<-ctx.Done()
		proc.finish(ctx.Err())
	}()
	return proc
}

func finishedProcess(err error) Process {
	proc := &fakeProcess{done: make(chan struct{})}
	proc.finish(err)
	return proc
}

func (proc *fakeProcess) Wait() error {
	<-proc.done
	return proc.err
}

func (proc *fakeProcess) Stop() error {
	proc.stopped.Store(true)
	proc.finish(errors.New("stopped"))
	return nil
}

func (proc *fakeProcess) Kill() error {
	proc.killed.Store(true)
	proc.finish(errors.New("killed"))
	return nil
}

func (proc *fakeProcess) Done() <-chan struct{} {
	return proc.done
}

func (proc *fakeProcess) Err() error {
	select {
	case <-proc.done:
		return proc.err
	default:
		return nil
	}
}

func (proc *fakeProcess) finish(err error) {
	proc.once.Do(func() {
		proc.err = err
		close(proc.done)
	})
}
