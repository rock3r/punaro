package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	punarorelease "github.com/rock3r/punaro/internal/release"
)

func TestRunRequiresCurrentAdapter(t *testing.T) {
	dir := privateDir(t)
	err := Run(context.Background(), RunRequest{Directory: dir, HealthTimeout: time.Millisecond})
	if err == nil {
		t.Fatal("run without a current adapter succeeded")
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
				if spec.Path != adapterPath(dir, currentSlot) {
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
	catalog, err := fetchVerifiedCatalog(Request{Directory: dir, Origin: origin.URL, Keys: origin.Keys, Now: time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)})
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
	if err != nil {
		t.Fatal(err)
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
	}); err != nil {
		t.Fatal(err)
	}
	status, err := Status(dir)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "v0.1.0" || status.RecoveryOnly {
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
	t.Helper()
	body, err := json.Marshal(slotState{Schema: 1, Release: release, Sequence: sequence, ManifestSHA256: digest})
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
	if err := enterRecoveryOnly(directory, "candidate-unhealthy"); err != nil {
		t.Fatal(err)
	}
}

func recoveryOnly(t *testing.T, directory string) bool {
	t.Helper()
	status, err := Status(directory)
	if err != nil {
		t.Fatal(err)
	}
	return status.RecoveryOnly
}

func adapterPath(directory, slot string) string {
	return filepath.Join(directory, slot, artifactName("punaro-adapter", runtime.GOOS, runtime.GOARCH))
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
	done chan struct{}
	err  error
	once sync.Once
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

func (proc *fakeProcess) Kill() error {
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
