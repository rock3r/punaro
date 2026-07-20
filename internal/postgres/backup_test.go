package postgres

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestNewUpdateBackupSourceRequiresExactUpdateIdentity(t *testing.T) {
	database := &Database{db: &sql.DB{}}
	dump := func(context.Context, string, string, string) error { return nil }
	if _, err := NewUpdateBackupSource(database, "owner.dsn", "invalid", dump); err == nil {
		t.Fatal("invalid update identity accepted")
	}
	if source, err := NewUpdateBackupSource(database, "owner.dsn", "019b4eb0-21f8-7d93-84df-10e6cf05ce53", dump); err != nil || source.updateID == "" {
		t.Fatalf("valid update source=%#v err=%v", source, err)
	}
}

func TestBackupSnapshotFinisherRetriesFailedReleaseAsAbort(t *testing.T) {
	stopCalls := 0
	var finalized []bool
	finisher := &backupSnapshotFinisher{
		stop: func() error {
			stopCalls++
			return nil
		},
		finalize: func(_ context.Context, verified bool) (bool, error) {
			finalized = append(finalized, verified)
			return len(finalized) > 1, nil
		},
	}

	if err := finisher.Finish(context.Background(), true); err == nil {
		t.Fatal("verified release failure unexpectedly succeeded")
	}
	if err := finisher.Finish(context.Background(), false); err != nil {
		t.Fatalf("abort retry failed: %v", err)
	}
	if stopCalls != 1 || !reflect.DeepEqual(finalized, []bool{true, false}) {
		t.Fatalf("stop=%d finalizations=%v", stopCalls, finalized)
	}
}

func TestBackupSnapshotFinisherIsIdempotentAfterRelease(t *testing.T) {
	stopCalls := 0
	finalizeCalls := 0
	finisher := &backupSnapshotFinisher{
		stop: func() error {
			stopCalls++
			return nil
		},
		finalize: func(_ context.Context, verified bool) (bool, error) {
			finalizeCalls++
			if !verified {
				t.Fatal("completed verified release was downgraded")
			}
			return true, nil
		},
	}

	if err := finisher.Finish(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if err := finisher.Finish(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if stopCalls != 1 || finalizeCalls != 1 {
		t.Fatalf("stop=%d finalize=%d", stopCalls, finalizeCalls)
	}
}

func TestBackupSnapshotFinisherSerializesConcurrentFinish(t *testing.T) {
	releaseStarted := make(chan struct{})
	allowRelease := make(chan struct{})
	var mu sync.Mutex
	var finalized []bool
	finisher := &backupSnapshotFinisher{
		stop: func() error { return nil },
		finalize: func(_ context.Context, verified bool) (bool, error) {
			mu.Lock()
			finalized = append(finalized, verified)
			mu.Unlock()
			close(releaseStarted)
			<-allowRelease
			return true, nil
		},
	}
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- finisher.Finish(context.Background(), true) }()
	<-releaseStarted
	go func() { secondDone <- finisher.Finish(context.Background(), false) }()
	close(allowRelease)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(finalized, []bool{true}) {
		t.Fatalf("finalize attempts=%v", finalized)
	}
}

func TestBackupSnapshotFinisherForcesUnverifiedReleaseAfterStopFailure(t *testing.T) {
	wantErr := errors.New("snapshot shutdown failed")
	verified := true
	finisher := &backupSnapshotFinisher{
		stop: func() error { return wantErr },
		finalize: func(_ context.Context, value bool) (bool, error) {
			verified = value
			return true, nil
		},
	}
	if err := finisher.Finish(context.Background(), true); !errors.Is(err, wantErr) {
		t.Fatalf("finish error=%v, want %v", err, wantErr)
	}
	if verified {
		t.Fatal("failed snapshot shutdown was released as verified")
	}
}

func TestBackupSnapshotFinisherReconcilesAmbiguousRelease(t *testing.T) {
	openCalls := 0
	closeCalls := 0
	confirmed, err := finalizeBackupGCFence(context.Background(), func(openCtx context.Context, _ string) (backupFenceSession, error) {
		openCalls++
		if _, ok := openCtx.Deadline(); !ok {
			t.Fatal("fence session open is not time-bounded")
		}
		return &fakeBackupFenceSession{
			release: func(context.Context, string, string, bool) (bool, error) {
				return false, errors.New("response lost")
			},
			reconcile: func(_ context.Context, _, _ string, verified bool) (bool, error) {
				if !verified {
					t.Fatal("verified release reconciliation changed intent")
				}
				return true, nil
			},
			close: func() error {
				closeCalls++
				return nil
			},
		}, nil
	}, "owner.dsn", "token", "snapshot", true)
	if err != nil || !confirmed || openCalls != 1 || closeCalls != 1 {
		t.Fatalf("confirmed=%t err=%v open=%d close=%d", confirmed, err, openCalls, closeCalls)
	}
}

func TestBackupSnapshotFinisherClosesEveryFailedAttempt(t *testing.T) {
	openCalls := 0
	closeCalls := 0
	openSession := func(context.Context, string) (backupFenceSession, error) {
		openCalls++
		return &fakeBackupFenceSession{
			release: func(context.Context, string, string, bool) (bool, error) {
				return false, errors.New("release unavailable")
			},
			reconcile: func(context.Context, string, string, bool) (bool, error) {
				return false, errors.New("reconciliation unavailable")
			},
			close: func() error {
				closeCalls++
				return nil
			},
		}, nil
	}
	finisher := &backupSnapshotFinisher{
		stop: func() error { return nil },
		finalize: func(ctx context.Context, verified bool) (bool, error) {
			return finalizeBackupGCFence(ctx, openSession, "owner.dsn", "token", "snapshot", verified)
		},
	}
	if err := finisher.Finish(context.Background(), true); err == nil {
		t.Fatal("verified release failure unexpectedly succeeded")
	}
	if err := finisher.Finish(context.Background(), false); err == nil {
		t.Fatal("abort release failure unexpectedly succeeded")
	}
	if openCalls != 2 || closeCalls != 2 {
		t.Fatalf("open=%d close=%d", openCalls, closeCalls)
	}
}

func TestBackupSnapshotFinisherKeepsCloseFailureTerminal(t *testing.T) {
	closeCalls := 0
	openCalls := 0
	finisher := &backupSnapshotFinisher{
		stop: func() error { return nil },
		finalize: func(ctx context.Context, verified bool) (bool, error) {
			return finalizeBackupGCFence(ctx, func(context.Context, string) (backupFenceSession, error) {
				openCalls++
				return &fakeBackupFenceSession{
					release: func(context.Context, string, string, bool) (bool, error) { return true, nil },
					reconcile: func(context.Context, string, string, bool) (bool, error) {
						t.Fatal("successful release was reconciled")
						return false, nil
					},
					close: func() error {
						closeCalls++
						return errors.New("close failed")
					},
				}, nil
			}, "owner.dsn", "token", "snapshot", verified)
		},
	}
	firstErr := finisher.Finish(context.Background(), true)
	secondErr := finisher.Finish(context.Background(), false)
	if firstErr == nil || firstErr.Error() != secondErr.Error() || openCalls != 1 || closeCalls != 1 {
		t.Fatalf("first=%v second=%v open=%d close=%d", firstErr, secondErr, openCalls, closeCalls)
	}
}

type fakeBackupFenceSession struct {
	release   func(context.Context, string, string, bool) (bool, error)
	reconcile func(context.Context, string, string, bool) (bool, error)
	close     func() error
}

func (session *fakeBackupFenceSession) Release(ctx context.Context, token, snapshotID string, verified bool) (bool, error) {
	return session.release(ctx, token, snapshotID, verified)
}

func (session *fakeBackupFenceSession) Reconcile(ctx context.Context, token, snapshotID string, verified bool) (bool, error) {
	return session.reconcile(ctx, token, snapshotID, verified)
}

func (session *fakeBackupFenceSession) Close() error { return session.close() }

func TestValidateCursorRejectsAbandonedTimelineAndFutureSequence(t *testing.T) {
	current := InstallationState{InstallationID: "installation", TimelineID: "restored", ChangeSequence: 20}
	tests := []struct {
		name   string
		cursor InstallationState
		want   error
	}{
		{name: "current", cursor: InstallationState{InstallationID: "installation", TimelineID: "restored", ChangeSequence: 20}},
		{name: "earlier current timeline", cursor: InstallationState{InstallationID: "installation", TimelineID: "restored", ChangeSequence: 10}},
		{name: "abandoned pre-restore timeline", cursor: InstallationState{InstallationID: "installation", TimelineID: "before", ChangeSequence: 30}, want: ErrCursorTimelineChanged},
		{name: "other installation", cursor: InstallationState{InstallationID: "other", TimelineID: "restored", ChangeSequence: 10}, want: ErrCursorTimelineChanged},
		{name: "future same timeline", cursor: InstallationState{InstallationID: "installation", TimelineID: "restored", ChangeSequence: 21}, want: ErrCursorFromFuture},
		{name: "negative", cursor: InstallationState{InstallationID: "installation", TimelineID: "restored", ChangeSequence: -1}, want: ErrCursorFromFuture},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateCursor(current, test.cursor)
			if !errors.Is(err, test.want) {
				t.Fatalf("ValidateCursor() error=%v, want %v", err, test.want)
			}
		})
	}
}
