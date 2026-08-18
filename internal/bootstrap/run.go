package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	punarorelease "github.com/rock3r/punaro/internal/release"
)

const (
	readyFile            = "health.json"
	recoveryFile         = "recovery.json"
	readyEnv             = "PUNARO_BOOTSTRAP_READY_FILE"
	localCheckoutRelease = punarorelease.LocalCheckoutRelease
	// DefaultHealthTimeout is the RFC bound for candidate hello/ready.
	DefaultHealthTimeout = 60 * time.Second
	// DefaultHealthWindow is how long a ready child must remain alive.
	DefaultHealthWindow    = time.Second
	childStopTimeout       = 2 * time.Second
	maxReadyBytes          = 256
	adapterComponent       = "punaro-adapter"
	recoveryMode           = "recovery-only"
	recoveryUnhealthy      = "candidate-unhealthy"
	recoveryPreviousFailed = "previous-unhealthy"
	recoveryCurrentExited  = "current-exited"
	directoryKeysFile      = "release.pub"
)

// ErrRecoveryOnly means normal child restarts are disabled until host-local recovery.
var ErrRecoveryOnly = errors.New("bootstrap is recovery-only")

// RunRequest starts the current-slot adapter and applies one-shot rollback.
type RunRequest struct {
	Directory      string
	Origin         string
	Keys           map[string]ed25519.PublicKey
	GOOS           string
	GOARCH         string
	Now            time.Time
	HTTP           fetcher
	HealthTimeout  time.Duration
	HealthWindow   time.Duration
	Start          func(context.Context, ChildSpec) (Process, error)
	WaitRecovery   bool
	OnRecoveryOnly func()
	afterPrepare   func()
	clockStart     time.Time
}

// ChildSpec is the closed-list adapter launch. Release metadata cannot add
// arguments or environment assignments.
type ChildSpec struct {
	Path string
	Env  []string
}

// Process is one supervised child.
type Process interface {
	Wait() error
	Stop() error
	Kill() error
	Done() <-chan struct{}
	Err() error
}

type readyRecord struct {
	Schema int64  `json:"schema"`
	Status string `json:"status"`
}

type recoveryState struct {
	Schema int64  `json:"schema"`
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
}

// Run starts the current-slot adapter with the host-local protected
// configuration the child already loads. It does not read adapter credentials.
// After a previous slot exists, the new current must become healthy within the
// timeout or it is rolled back once when the fresh catalog still lists that
// previous release. Otherwise run enters recovery-only and, when
// WaitRecovery is set, stays parked until that marker is cleared.
func Run(ctx context.Context, request RunRequest) error {
	if err := request.normalizeRun(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := prepareDirectory(request.Directory); err != nil {
		return err
	}
	unlockRun, err := acquireRunLease(request.Directory)
	if err != nil {
		return err
	}
	defer func() {
		clearRunPID(request.Directory)
		unlockRun()
	}()
	err = superviseRun(ctx, request)
	clearRunPID(request.Directory)
	if !request.WaitRecovery || !errors.Is(err, ErrRecoveryOnly) {
		return err
	}
	if request.OnRecoveryOnly != nil {
		request.OnRecoveryOnly()
	}
	return waitRecoveryCleared(ctx, request.Directory)
}

func superviseRun(ctx context.Context, request RunRequest) error {
	identity, adapter, err := prepareRun(&request)
	if errors.Is(err, errNoAdapter) {
		hadPrevious, prevErr := request.hasPrevious(identity)
		if prevErr != nil {
			if recErr := enterRecoveryOnly(request.Directory, recoveryCurrentExited, identity); recErr != nil {
				return recErr
			}
			return ErrRecoveryOnly
		}
		return failCurrent(ctx, request, startOrDefault(request), identity, hadPrevious, errChildExited)
	}
	if err != nil {
		return err
	}
	if request.afterPrepare != nil {
		request.afterPrepare()
	}
	if err := failIfSlotChanged(request.Directory, identity); err != nil {
		return err
	}
	hadPrevious, err := request.hasPrevious(identity)
	if err != nil {
		if recErr := enterRecoveryOnly(request.Directory, recoveryCurrentExited, identity); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	start := startOrDefault(request)
	child, err := startAdapter(ctx, request, start, adapter)
	if err != nil {
		if ctx.Err() != nil {
			return nil //nolint:nilerr // SIGINT/SIGTERM before the child starts is a clean supervisor stop
		}
		return failCurrent(ctx, request, start, identity, hadPrevious, errChildExited)
	}
	requireHealth := hadPrevious && !currentGenerationIsHealthy(request.Directory, identity)
	if err := waitHealth(ctx, request, child, identity, requireHealth); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return waitChild(ctx, request, child, identity)
		}
		_ = stopChild(child)
		if errors.Is(err, errSlotChanged) {
			return err
		}
		return failCurrent(ctx, request, start, identity, hadPrevious, err)
	}
	return superviseHealthyChild(ctx, request, child, identity)
}

func waitRecoveryCleared(ctx context.Context, directory string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ErrRecoveryOnly
		}
		recovery, err := loadRecovery(directory)
		if err == nil && recovery.Mode != recoveryMode {
			return errSlotChanged
		}
		select {
		case <-ctx.Done():
			return ErrRecoveryOnly
		case <-ticker.C:
		}
	}
}

func (request *RunRequest) normalizeRun() error {
	if request.Directory == "" || !filepath.IsAbs(request.Directory) {
		return errors.New("bootstrap directory is invalid")
	}
	if request.Origin == "" {
		request.Origin = punarorelease.GitHubReleaseOrigin
	}
	if request.GOOS == "" {
		request.GOOS = runtime.GOOS
	}
	if request.GOARCH == "" {
		request.GOARCH = runtime.GOARCH
	}
	if request.Now.IsZero() {
		request.Now = time.Now().UTC()
	}
	if request.HealthTimeout <= 0 {
		request.HealthTimeout = DefaultHealthTimeout
	}
	if request.HealthWindow < 0 {
		request.HealthWindow = DefaultHealthWindow
	}
	if request.clockStart.IsZero() {
		request.clockStart = time.Now()
	}
	return nil
}

func prepareRun(request *RunRequest) (slotState, string, error) {
	if err := prepareDirectory(request.Directory); err != nil {
		return slotState{}, "", err
	}
	unlock, err := lockDirectory(request.Directory)
	if err != nil {
		return slotState{}, "", err
	}
	defer unlock()
	if err := recoverJournal(request.Directory); err != nil {
		if recErr := writeRecoveryRecord(request.Directory, recoveryCurrentExited); recErr != nil {
			return slotState{}, "", recErr
		}
		return slotState{}, "", ErrRecoveryOnly
	}
	if recovery, err := loadRecovery(request.Directory); err != nil {
		if recErr := writeRecoveryRecord(request.Directory, recoveryCurrentExited); recErr != nil {
			return slotState{}, "", recErr
		}
		return slotState{}, "", ErrRecoveryOnly
	} else if recovery.Mode == recoveryMode {
		return slotState{}, "", ErrRecoveryOnly
	}
	if len(request.Keys) == 0 {
		keys, err := loadDirectoryKeys(request.Directory)
		if err != nil {
			if recErr := writeRecoveryRecord(request.Directory, recoveryCurrentExited); recErr != nil {
				return slotState{}, "", recErr
			}
			return slotState{}, "", ErrRecoveryOnly
		}
		request.Keys = keys
	}
	current := filepath.Join(request.Directory, currentSlot)
	if err := requireRealDir(current); err != nil {
		if recErr := writeRecoveryRecord(request.Directory, recoveryCurrentExited); recErr != nil {
			return slotState{}, "", recErr
		}
		return slotState{}, "", ErrRecoveryOnly
	}
	identity, err := readSlot(current)
	if err != nil {
		if recErr := writeRecoveryRecord(request.Directory, recoveryCurrentExited); recErr != nil {
			return slotState{}, "", recErr
		}
		return slotState{}, "", ErrRecoveryOnly
	}
	if err := observeGeneration(request.Directory, identity.Generation); err != nil {
		return slotState{}, "", err
	}
	adapter, err := snapshotAdapter(request.Directory, current, request.GOOS, request.GOARCH)
	if err != nil {
		return identity, "", err
	}
	if err := removeReadyFile(request.Directory); err != nil {
		return slotState{}, "", err
	}
	return identity, adapter, nil
}

func snapshotAdapter(directory, slotDir, goos, goarch string) (string, error) {
	src, err := adapterBinary(slotDir, goos, goarch)
	if err != nil {
		return "", errNoAdapter
	}
	body, err := os.ReadFile(src) // #nosec G304 -- snapshot is copied from the locked current slot.
	if err != nil {
		return "", errNoAdapter
	}
	running := filepath.Join(directory, runningSlot)
	if err := os.RemoveAll(running); err != nil {
		return "", err
	}
	if err := os.Mkdir(running, 0o700); err != nil {
		return "", err
	}
	dest := filepath.Join(running, artifactName(adapterComponent, goos, goarch))
	if err := writeAtomic(dest, body, 0o755); err != nil {
		return "", err
	}
	return dest, nil
}

func (request RunRequest) hasPrevious(current slotState) (bool, error) {
	previous, err := readOptionalSlot(filepath.Join(request.Directory, previousSlot))
	if err != nil {
		return false, err
	}
	if previous.Release == "" {
		return false, nil
	}
	return previous.Release != current.Release || previous.Sequence != current.Sequence || previous.ManifestSHA256 != current.ManifestSHA256, nil
}

func (request RunRequest) currentNow() time.Time {
	if request.clockStart.IsZero() {
		return request.Now
	}
	return request.Now.Add(time.Since(request.clockStart))
}

func removeReadyFile(directory string) error {
	path := filepath.Join(directory, readyFile)
	if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
		return errors.New("bootstrap ready file is invalid")
	}
	return nil
}

func startAdapter(ctx context.Context, request RunRequest, start func(context.Context, ChildSpec) (Process, error), adapter string) (Process, error) {
	ready := filepath.Join(request.Directory, readyFile)
	child, err := start(ctx, ChildSpec{Path: adapter, Env: withReadyEnv(ready)})
	if err != nil {
		return nil, err
	}
	if proc, ok := child.(*osProcess); ok && proc.cmd != nil && proc.cmd.Process != nil {
		if err := writeRunPID(request.Directory, proc.cmd.Process.Pid, adapter); err != nil {
			_ = stopChild(child)
			return nil, err
		}
	}
	return child, nil
}

type runPIDRecord struct {
	Schema int64  `json:"schema"`
	PID    int    `json:"pid"`
	Path   string `json:"path"`
}

func writeRunPID(directory string, pid int, path string) error {
	if pid <= 0 || path == "" {
		return nil
	}
	body, err := json.Marshal(runPIDRecord{Schema: 1, PID: pid, Path: path})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(directory, runPIDFile), body, 0o600)
}

func loadRunPID(directory string) (runPIDRecord, error) {
	body, err := os.ReadFile(filepath.Join(directory, runPIDFile)) // #nosec G304,G703 -- run pid file is a fixed child of the bootstrap directory.
	if os.IsNotExist(err) {
		return runPIDRecord{}, nil
	}
	if err != nil {
		return runPIDRecord{}, err
	}
	var record runPIDRecord
	if json.Unmarshal(body, &record) != nil || record.Schema != 1 || record.PID <= 0 {
		return runPIDRecord{}, errors.New("bootstrap run is already active")
	}
	return record, nil
}

func clearRunPID(directory string) {
	_ = os.Remove(filepath.Join(directory, runPIDFile)) // #nosec G703 -- run pid file is a fixed child of the bootstrap directory.
}

func terminateStaleRun(directory string) error {
	record, err := loadRunPID(directory)
	if err != nil {
		return err
	}
	if record.PID == 0 {
		return nil
	}
	switch matchProcessImage(record.PID, record.Path) {
	case processImageGone, processImageMismatch:
		clearRunPID(directory)
		return nil
	case processImageMatch:
		proc, err := os.FindProcess(record.PID)
		if err != nil || proc == nil {
			return errors.New("bootstrap run is already active")
		}
		if runtime.GOOS != "windows" {
			_ = proc.Signal(syscall.SIGTERM)
			if waitStaleProcessGone(record) {
				clearRunPID(directory)
				return nil
			}
		}
		_ = proc.Kill()
		if waitStaleProcessGone(record) {
			clearRunPID(directory)
			return nil
		}
		return errors.New("bootstrap run is already active")
	default:
		return errors.New("bootstrap run is already active")
	}
}

func waitStaleProcessGone(record runPIDRecord) bool {
	deadline := time.Now().Add(childStopTimeout)
	for {
		switch matchProcessImage(record.PID, record.Path) {
		case processImageGone, processImageMismatch:
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type processImageResult int

const (
	processImageUnknown processImageResult = iota
	processImageMatch
	processImageMismatch
	processImageGone
)

func matchProcessImage(pid int, recorded string) processImageResult {
	if pid <= 0 {
		return processImageUnknown
	}
	live, err := processImagePath(pid)
	if errors.Is(err, errProcessImageGone) {
		return processImageGone
	}
	if recorded == "" || err != nil || live == "" {
		return processImageUnknown
	}
	if sameImagePath(live, recorded) {
		return processImageMatch
	}
	return processImageMismatch
}

func sameImagePath(live, recorded string) bool {
	live = strings.TrimSuffix(live, " (deleted)")
	if filepath.Clean(live) == filepath.Clean(recorded) {
		return true
	}
	liveEval, liveErr := filepath.EvalSymlinks(live)
	recordedEval, recordedErr := filepath.EvalSymlinks(recorded)
	if liveErr == nil && recordedErr == nil && liveEval == recordedEval {
		return true
	}
	liveInfo, liveStatErr := os.Lstat(live)             // #nosec G703 -- compared recorded adapter image.
	recordedInfo, recordedStatErr := os.Lstat(recorded) // #nosec G703 -- compared recorded adapter image.
	return liveStatErr == nil && recordedStatErr == nil && os.SameFile(liveInfo, recordedInfo)
}

var (
	errChildExited         = errors.New("bootstrap child exited")
	errNoAdapter           = errors.New("bootstrap has no current adapter")
	errSlotChanged         = errors.New("bootstrap slot changed")
	errProcessImageGone    = errors.New("bootstrap process image is gone")
	errProcessImageUnknown = errors.New("bootstrap process image is unverifiable")
)

func startOrDefault(request RunRequest) func(context.Context, ChildSpec) (Process, error) {
	if request.Start != nil {
		return request.Start
	}
	return startOSProcess
}

func waitHealth(ctx context.Context, request RunRequest, child Process, started slotState, required bool) error {
	deadline := time.Now().Add(request.HealthTimeout)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := failIfSlotChanged(request.Directory, started); err != nil {
			return err
		}
		status, err := readReadyFile(filepath.Join(request.Directory, readyFile))
		switch {
		case err == nil && status == "healthy":
			return waitHealthWindow(ctx, request, child, started)
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return err
		}
		select {
		case <-child.Done():
			return errChildExited
		default:
		}
		if time.Now().After(deadline) {
			if required {
				return errors.New("bootstrap child is unhealthy")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-child.Done():
			return errChildExited
		case <-ticker.C:
		}
	}
}

func failCurrent(ctx context.Context, request RunRequest, start func(context.Context, ChildSpec) (Process, error), started slotState, hadPrevious bool, cause error) error {
	if hadPrevious {
		return failOrRollback(ctx, request, start, started, recoveryUnhealthy)
	}
	reason := recoveryCurrentExited
	if !errors.Is(cause, errChildExited) {
		reason = recoveryUnhealthy
	}
	if recErr := enterRecoveryOnly(request.Directory, reason, started); recErr != nil {
		return recErr
	}
	return ErrRecoveryOnly
}

func snapshotRolledAdapter(request RunRequest, rolled slotState) (string, error) {
	if err := prepareDirectory(request.Directory); err != nil {
		return "", err
	}
	unlock, err := lockDirectory(request.Directory)
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := failIfSlotChanged(request.Directory, rolled); err != nil {
		return "", err
	}
	return snapshotAdapter(request.Directory, filepath.Join(request.Directory, currentSlot), request.GOOS, request.GOARCH)
}

func failIfSlotChanged(directory string, started slotState) error {
	current, err := readOptionalSlot(filepath.Join(directory, currentSlot))
	if err != nil {
		return err
	}
	if current.Release == "" {
		if started.Release != "" {
			return errSlotChanged
		}
		return nil
	}
	if current.Release != started.Release || current.Sequence != started.Sequence || current.ManifestSHA256 != started.ManifestSHA256 || current.Generation != started.Generation {
		return errSlotChanged
	}
	return nil
}

func failOrRollback(ctx context.Context, request RunRequest, start func(context.Context, ChildSpec) (Process, error), started slotState, reason string) error {
	unlocked, rolled, err := rollbackIfAllowed(ctx, request, started)
	if ctx.Err() != nil {
		return nil //nolint:nilerr // supervisor stop during catalog-gated rollback is a clean exit
	}
	if errors.Is(err, errSlotChanged) {
		return err
	}
	if !unlocked || err != nil {
		if recErr := enterRecoveryOnly(request.Directory, reason, started); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	adapter, err := snapshotRolledAdapter(request, rolled)
	if err != nil {
		if recErr := enterRecoveryOnly(request.Directory, recoveryPreviousFailed, rolled); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	if err := removeReadyFile(request.Directory); err != nil {
		return err
	}
	child, err := startAdapter(ctx, request, start, adapter)
	if err != nil {
		if ctx.Err() != nil {
			return nil //nolint:nilerr // SIGINT/SIGTERM before the rolled child starts is a clean supervisor stop
		}
		if recErr := enterRecoveryOnly(request.Directory, recoveryPreviousFailed, rolled); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	if err := waitHealth(ctx, request, child, rolled, true); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return waitChild(ctx, request, child, rolled)
		}
		_ = stopChild(child)
		if errors.Is(err, errSlotChanged) {
			return err
		}
		if recErr := enterRecoveryOnly(request.Directory, recoveryPreviousFailed, rolled); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	return superviseHealthyChild(ctx, request, child, rolled)
}

func superviseHealthyChild(ctx context.Context, request RunRequest, child Process, started slotState) error {
	if status, err := readReadyFile(filepath.Join(request.Directory, readyFile)); err == nil && status == "healthy" {
		if err := rememberHealthyGeneration(request.Directory, started); err != nil {
			_ = stopChild(child)
			return err
		}
	}
	return waitChild(ctx, request, child, started)
}

func waitChild(ctx context.Context, request RunRequest, child Process, started slotState) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-child.Done():
			if ctx.Err() != nil {
				return nil //nolint:nilerr // SIGINT/SIGTERM is a clean supervisor stop
			}
			if err := child.Wait(); err != nil {
				return err
			}
			return errChildExited
		case <-ticker.C:
			if started.Release == "" {
				continue
			}
			if err := failIfSlotChanged(request.Directory, started); err != nil {
				_ = stopChild(child)
				return err
			}
		}
	}
}

func stopChild(child Process) error {
	_ = child.Stop()
	timer := time.NewTimer(childStopTimeout)
	defer timer.Stop()
	select {
	case <-child.Done():
		return child.Wait()
	case <-timer.C:
		_ = child.Kill()
		<-child.Done()
		return child.Wait()
	}
}

func waitHealthWindow(ctx context.Context, request RunRequest, child Process, started slotState) error {
	if request.HealthWindow <= 0 {
		return nil
	}
	timer := time.NewTimer(request.HealthWindow)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-child.Done():
			return errChildExited
		case <-ticker.C:
			if err := failIfSlotChanged(request.Directory, started); err != nil {
				return err
			}
		case <-timer.C:
			select {
			case <-child.Done():
				return errChildExited
			default:
				return nil
			}
		}
	}
}

func rollbackIfAllowed(ctx context.Context, request RunRequest, started slotState) (bool, slotState, error) {
	if err := ctx.Err(); err != nil {
		return false, slotState{}, err
	}
	if err := prepareDirectory(request.Directory); err != nil {
		return false, slotState{}, err
	}
	unlock, err := lockDirectory(request.Directory)
	if err != nil {
		return false, slotState{}, err
	}
	defer unlock()
	if err := recoverJournal(request.Directory); err != nil {
		return false, slotState{}, err
	}
	current, err := readSlot(filepath.Join(request.Directory, currentSlot))
	if err != nil {
		return false, slotState{}, err
	}
	if current.Release != started.Release || current.Sequence != started.Sequence || current.ManifestSHA256 != started.ManifestSHA256 || current.Generation != started.Generation {
		return false, slotState{}, errSlotChanged
	}
	previous, err := readSlot(filepath.Join(request.Directory, previousSlot))
	if err != nil {
		return false, slotState{}, err
	}
	if previous.Release == localCheckoutRelease {
		return false, slotState{}, errors.New("catalog does not allow the release")
	}
	if blocked, err := blocksAutoRollback(request.Directory, previous); err != nil {
		return false, slotState{}, err
	} else if blocked {
		return false, slotState{}, errors.New("automatic rollback already used")
	}
	if len(request.Keys) == 0 {
		return false, slotState{}, errors.New("bootstrap has no embedded release keys")
	}
	accepted, err := loadAccepted(request.Directory)
	if err != nil {
		return false, slotState{}, err
	}
	catalog, err := fetchVerifiedCatalog(ctx, Request{
		Directory: request.Directory,
		Origin:    request.Origin,
		Keys:      request.Keys,
		Now:       request.currentNow(),
		HTTP:      request.HTTP,
	})
	if err != nil {
		return false, slotState{}, err
	}
	if err := ctx.Err(); err != nil {
		return false, slotState{}, err
	}
	if accepted.CatalogSequence > 0 && catalog.Sequence < accepted.CatalogSequence {
		return false, slotState{}, errors.New("release catalog sequence downgrade")
	}
	if !catalog.Allows(previous.Release, previous.Sequence, previous.ManifestSHA256) {
		return false, slotState{}, errors.New("catalog does not allow the release")
	}
	if err := ctx.Err(); err != nil {
		return false, slotState{}, err
	}
	if err := writeJournal(request.Directory, journal{
		Schema:          1,
		Phase:           "rolling-back",
		Release:         previous.Release,
		Sequence:        previous.Sequence,
		CatalogSequence: catalog.Sequence,
		ManifestSHA256:  previous.ManifestSHA256,
	}); err != nil {
		return false, slotState{}, err
	}
	if err := completeRollback(request.Directory, previous); err != nil {
		return false, slotState{}, err
	}
	if catalog.Sequence > accepted.CatalogSequence {
		accepted.CatalogSequence = catalog.Sequence
		if err := saveAccepted(request.Directory, accepted); err != nil {
			return false, slotState{}, err
		}
	}
	if err := saveAutoRollback(request.Directory, started); err != nil {
		return false, slotState{}, err
	}
	if err := clearJournal(request.Directory); err != nil {
		return false, slotState{}, err
	}
	return true, previous, nil
}

func adapterBinary(slotDir, goos, goarch string) (string, error) {
	name := artifactName(adapterComponent, goos, goarch)
	path := filepath.Join(slotDir, name)
	info, err := os.Lstat(path) // #nosec G703 -- name is the closed-list adapter artifact.
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("bootstrap has no current adapter")
	}
	return path, nil
}

func readReadyFile(path string) (string, error) {
	info, err := os.Lstat(path) // #nosec G703 -- ready file is a fixed child of the bootstrap directory.
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxReadyBytes {
		return "", errors.New("bootstrap ready file is invalid")
	}
	body, err := os.ReadFile(path) // #nosec G304 -- ready file is a fixed child of the bootstrap directory.
	if err != nil {
		return "", errors.New("bootstrap ready file is invalid")
	}
	if err := rejectDuplicateJSONFields(body); err != nil {
		return "", errors.New("bootstrap ready file is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var record readyRecord
	if err := decoder.Decode(&record); err != nil {
		return "", errors.New("bootstrap ready file is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("bootstrap ready file is invalid")
	}
	if record.Schema != 1 || record.Status != "healthy" {
		return "", errors.New("bootstrap ready file is invalid")
	}
	return record.Status, nil
}

func persistDirectoryKeys(directory string, keys map[string]ed25519.PublicKey) error {
	if len(keys) == 0 {
		return nil
	}
	body, err := punarorelease.EncodePublicKeySet(keys)
	if err != nil {
		return errors.New("bootstrap keys file is invalid")
	}
	return writeAtomic(filepath.Join(directory, directoryKeysFile), body, 0o600)
}

func loadDirectoryKeys(directory string) (map[string]ed25519.PublicKey, error) {
	path := filepath.Join(directory, directoryKeysFile)
	info, err := os.Lstat(path) // #nosec G703 -- keys file is a fixed child of the bootstrap directory.
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("bootstrap keys file is invalid")
	}
	body, err := os.ReadFile(path) // #nosec G304 -- keys file is a fixed child of the bootstrap directory.
	if err != nil {
		return nil, errors.New("bootstrap keys file is invalid")
	}
	keys, err := punarorelease.ParsePublicKeys(body)
	if err != nil || len(keys) == 0 {
		return nil, errors.New("bootstrap keys file is invalid")
	}
	return keys, nil
}

func loadRecovery(directory string) (recoveryState, error) {
	body, err := os.ReadFile(filepath.Join(directory, recoveryFile)) // #nosec G304 -- recovery record is a fixed child of the bootstrap directory.
	if os.IsNotExist(err) {
		return recoveryState{}, nil
	}
	if err != nil {
		return recoveryState{}, errors.New("bootstrap recovery state is invalid")
	}
	if err := rejectDuplicateJSONFields(body); err != nil {
		return recoveryState{}, errors.New("bootstrap recovery state is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var record recoveryState
	if err := decoder.Decode(&record); err != nil {
		return recoveryState{}, errors.New("bootstrap recovery state is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return recoveryState{}, errors.New("bootstrap recovery state is invalid")
	}
	if record.Schema != 1 || record.Mode != recoveryMode || record.Reason == "" {
		return recoveryState{}, errors.New("bootstrap recovery state is invalid")
	}
	return record, nil
}

func clearRecovery(directory string) error {
	if err := os.RemoveAll(filepath.Join(directory, recoveryFile)); err != nil {
		return err
	}
	return syncDir(directory)
}

func writeRecoveryRecord(directory, reason string) error {
	body, err := json.Marshal(recoveryState{Schema: 1, Mode: recoveryMode, Reason: reason})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(directory, recoveryFile), body, 0o600)
}

func enterRecoveryOnly(directory, reason string, started slotState) error {
	if err := prepareDirectory(directory); err != nil {
		return err
	}
	unlock, err := lockDirectory(directory)
	if err != nil {
		return err
	}
	defer unlock()
	if started.Release != "" {
		if err := failIfSlotChanged(directory, started); err != nil {
			return err
		}
	}
	return writeRecoveryRecord(directory, reason)
}

// SeedLocalCheckout publishes a host-local adapter from a reviewed checkout
// into the current slot. It is not a signed update and cannot be used as an
// automatic rollback target.
func SeedLocalCheckout(directory, adapterPath string) error {
	if directory == "" || !filepath.IsAbs(directory) || adapterPath == "" || !filepath.IsAbs(adapterPath) {
		return errors.New("bootstrap directory is invalid")
	}
	if _, err := os.Lstat(directory); err == nil {
		if err := requireTrustedSeedDirectory(directory); err != nil {
			return err
		}
	} else if err := prepareDirectory(directory); err != nil {
		return err
	}
	unlock, err := lockDirectory(directory)
	if err != nil {
		return err
	}
	defer unlock()
	if err := recoverRepairableJournal(directory); err != nil {
		return err
	}
	current := filepath.Join(directory, currentSlot)
	if exists, err := existsRealDir(current); err != nil {
		return err
	} else if exists {
		slot, err := readSlot(current)
		if err == nil && slot.Release != localCheckoutRelease {
			recovery, recErr := loadRecovery(directory)
			if recErr != nil || recovery.Mode == recoveryMode {
				return errors.New("bootstrap is recovery-only; use a signed update")
			}
			return nil
		}
	}
	info, err := os.Lstat(adapterPath) // #nosec G703 -- operator-selected checkout adapter.
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("bootstrap adapter is invalid")
	}
	body, err := os.ReadFile(adapterPath) // #nosec G304 -- operator-selected checkout adapter.
	if err != nil {
		return errors.New("bootstrap adapter is invalid")
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	candidate := filepath.Join(directory, candidateSlot)
	if err := os.RemoveAll(candidate); err != nil {
		return err
	}
	if err := os.Mkdir(candidate, 0o700); err != nil {
		return err
	}
	name := artifactName(adapterComponent, runtime.GOOS, runtime.GOARCH)
	if err := writeAtomic(filepath.Join(candidate, name), body, 0o755); err != nil {
		return err
	}
	record, err := json.Marshal(slotState{Schema: 1, Release: localCheckoutRelease, Sequence: 1, ManifestSHA256: digest})
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(candidate, slotRecord), record, 0o600); err != nil {
		return err
	}
	if err := writeJournal(directory, journal{
		Schema:         1,
		Phase:          "seeding",
		Release:        localCheckoutRelease,
		Sequence:       1,
		ManifestSHA256: digest,
	}); err != nil {
		return err
	}
	if err := replaceCurrent(directory, localCheckoutRelease, 1, digest); err != nil {
		return err
	}
	return finishSeed(directory, journal{
		Schema:         1,
		Phase:          "seeding",
		Release:        localCheckoutRelease,
		Sequence:       1,
		ManifestSHA256: digest,
	})
}

func withReadyEnv(ready string) []string {
	prefix := readyEnv + "="
	env := os.Environ()
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+ready)
}

func startOSProcess(ctx context.Context, spec ChildSpec) (Process, error) {
	if spec.Path == "" || !filepath.IsAbs(spec.Path) {
		return nil, errors.New("bootstrap adapter is invalid")
	}
	cmd := exec.CommandContext(ctx, spec.Path) // #nosec G204,G702 -- closed-list current-slot adapter path.
	cmd.Env = spec.Env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if runtime.GOOS == "windows" {
			return cmd.Process.Kill()
		}
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return newOSProcess(cmd), nil
}

type osProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func newOSProcess(cmd *exec.Cmd) *osProcess {
	proc := &osProcess{cmd: cmd, done: make(chan struct{})}
	go func() {
		proc.err = cmd.Wait()
		close(proc.done)
	}()
	return proc
}

func (proc *osProcess) Wait() error {
	<-proc.done
	return proc.err
}

func (proc *osProcess) Stop() error {
	if proc.cmd.Process == nil {
		return nil
	}
	if runtime.GOOS == "windows" {
		return proc.cmd.Process.Kill()
	}
	return proc.cmd.Process.Signal(syscall.SIGTERM)
}

func (proc *osProcess) Kill() error {
	if proc.cmd.Process == nil {
		return nil
	}
	return proc.cmd.Process.Kill()
}

func (proc *osProcess) Done() <-chan struct{} { return proc.done }

func (proc *osProcess) Err() error {
	select {
	case <-proc.done:
		return proc.err
	default:
		return nil
	}
}
