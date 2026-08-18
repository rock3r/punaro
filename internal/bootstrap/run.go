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
	Directory     string
	Origin        string
	Keys          map[string]ed25519.PublicKey
	GOOS          string
	GOARCH        string
	Now           time.Time
	HTTP          fetcher
	HealthTimeout time.Duration
	HealthWindow  time.Duration
	Start         func(context.Context, ChildSpec) (Process, error)
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
// previous release. Otherwise run enters recovery-only and does not restart.
func Run(ctx context.Context, request RunRequest) error {
	if err := request.normalizeRun(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	identity, adapter, err := prepareRun(&request)
	if errors.Is(err, errNoAdapter) {
		if request.hasPrevious(identity) {
			return failOrRollback(ctx, request, startOrDefault(request), identity, recoveryUnhealthy)
		}
		if recErr := enterRecoveryOnly(request.Directory, recoveryCurrentExited); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	if err != nil {
		return err
	}
	start := startOrDefault(request)
	child, err := startAdapter(ctx, request, start, adapter)
	if err != nil {
		if request.hasPrevious(identity) {
			return failOrRollback(ctx, request, start, identity, recoveryUnhealthy)
		}
		if recErr := enterRecoveryOnly(request.Directory, recoveryCurrentExited); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	if err := waitHealth(ctx, request, child, request.hasPrevious(identity)); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		_ = child.Kill()
		<-child.Done()
		if request.hasPrevious(identity) {
			return failOrRollback(ctx, request, start, identity, recoveryUnhealthy)
		}
		reason := recoveryCurrentExited
		if !errors.Is(err, errChildExited) {
			reason = recoveryUnhealthy
		}
		if recErr := enterRecoveryOnly(request.Directory, reason); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	return waitChild(ctx, child)
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
		return slotState{}, "", err
	}
	if len(request.Keys) == 0 {
		keys, err := loadDirectoryKeys(request.Directory)
		if err != nil {
			return slotState{}, "", err
		}
		request.Keys = keys
	}
	if recovery, err := loadRecovery(request.Directory); err != nil {
		return slotState{}, "", err
	} else if recovery.Mode == recoveryMode {
		return slotState{}, "", ErrRecoveryOnly
	}
	current := filepath.Join(request.Directory, currentSlot)
	if err := requireRealDir(current); err != nil {
		return slotState{}, "", errors.New("bootstrap has no current adapter")
	}
	identity, err := readSlot(current)
	if err != nil {
		if recErr := writeRecoveryRecord(request.Directory, recoveryCurrentExited); recErr != nil {
			return slotState{}, "", recErr
		}
		return slotState{}, "", ErrRecoveryOnly
	}
	adapter, err := adapterBinary(current, request.GOOS, request.GOARCH)
	if err != nil {
		return identity, "", errNoAdapter
	}
	if err := os.Remove(filepath.Join(request.Directory, readyFile)); err != nil && !os.IsNotExist(err) {
		return slotState{}, "", errors.New("bootstrap ready file is invalid")
	}
	return identity, adapter, nil
}

func (request RunRequest) hasPrevious(current slotState) bool {
	previous, err := readOptionalSlot(filepath.Join(request.Directory, previousSlot))
	if err != nil || previous.Release == "" {
		return false
	}
	return previous.Release != current.Release || previous.Sequence != current.Sequence || previous.ManifestSHA256 != current.ManifestSHA256
}

func startAdapter(ctx context.Context, request RunRequest, start func(context.Context, ChildSpec) (Process, error), adapter string) (Process, error) {
	ready := filepath.Join(request.Directory, readyFile)
	child, err := start(ctx, ChildSpec{Path: adapter, Env: withReadyEnv(ready)})
	if err != nil {
		return nil, err
	}
	return child, nil
}

var (
	errChildExited = errors.New("bootstrap child exited")
	errNoAdapter   = errors.New("bootstrap has no current adapter")
)

func startOrDefault(request RunRequest) func(context.Context, ChildSpec) (Process, error) {
	if request.Start != nil {
		return request.Start
	}
	return startOSProcess
}

func waitHealth(ctx context.Context, request RunRequest, child Process, required bool) error {
	deadline := time.Now().Add(request.HealthTimeout)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, err := readReadyFile(filepath.Join(request.Directory, readyFile))
		switch {
		case err == nil && status == "healthy":
			return waitHealthWindow(ctx, request, child)
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

func failOrRollback(ctx context.Context, request RunRequest, start func(context.Context, ChildSpec) (Process, error), started slotState, reason string) error {
	unlocked, _, err := rollbackIfAllowed(request, started)
	if !unlocked || err != nil {
		if recErr := enterRecoveryOnly(request.Directory, reason); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	adapter, err := adapterBinary(filepath.Join(request.Directory, currentSlot), request.GOOS, request.GOARCH)
	if err != nil {
		if recErr := enterRecoveryOnly(request.Directory, recoveryPreviousFailed); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	if err := os.Remove(filepath.Join(request.Directory, readyFile)); err != nil && !os.IsNotExist(err) {
		return errors.New("bootstrap ready file is invalid")
	}
	child, err := startAdapter(ctx, request, start, adapter)
	if err != nil {
		if recErr := enterRecoveryOnly(request.Directory, recoveryPreviousFailed); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	if err := waitHealth(ctx, request, child, true); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		_ = child.Kill()
		<-child.Done()
		if recErr := enterRecoveryOnly(request.Directory, recoveryPreviousFailed); recErr != nil {
			return recErr
		}
		return ErrRecoveryOnly
	}
	return waitChild(ctx, child)
}

func waitChild(ctx context.Context, child Process) error {
	err := child.Wait()
	if ctx.Err() == nil {
		return err
	}
	return nil //nolint:nilerr // SIGINT/SIGTERM is a clean supervisor stop
}

func waitHealthWindow(ctx context.Context, request RunRequest, child Process) error {
	if request.HealthWindow <= 0 {
		return nil
	}
	timer := time.NewTimer(request.HealthWindow)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-child.Done():
		return errChildExited
	case <-timer.C:
		select {
		case <-child.Done():
			return errChildExited
		default:
			return nil
		}
	}
}

func rollbackIfAllowed(request RunRequest, started slotState) (bool, slotState, error) {
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
	if current.Release != started.Release || current.Sequence != started.Sequence || current.ManifestSHA256 != started.ManifestSHA256 {
		return false, slotState{}, errors.New("bootstrap slot changed")
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
	catalog, err := fetchVerifiedCatalog(Request{
		Directory: request.Directory,
		Origin:    request.Origin,
		Keys:      request.Keys,
		Now:       request.Now,
		HTTP:      request.HTTP,
	})
	if err != nil {
		return false, slotState{}, err
	}
	if accepted.CatalogSequence > 0 && catalog.Sequence < accepted.CatalogSequence {
		return false, slotState{}, errors.New("release catalog sequence downgrade")
	}
	if !catalog.Allows(previous.Release, previous.Sequence, previous.ManifestSHA256) {
		return false, slotState{}, errors.New("catalog does not allow the release")
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
	err := os.Remove(filepath.Join(directory, recoveryFile))
	if err != nil && !os.IsNotExist(err) {
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

func enterRecoveryOnly(directory, reason string) error {
	if err := prepareDirectory(directory); err != nil {
		return err
	}
	unlock, err := lockDirectory(directory)
	if err != nil {
		return err
	}
	defer unlock()
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
	if err := recoverJournal(directory); err != nil {
		return err
	}
	current := filepath.Join(directory, currentSlot)
	if exists, err := existsRealDir(current); err != nil {
		return err
	} else if exists {
		slot, err := readSlot(current)
		if err == nil && slot.Release != localCheckoutRelease {
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
	accepted, err := loadAccepted(directory)
	if err != nil {
		return err
	}
	if accepted.Release == "" || accepted.Release == localCheckoutRelease {
		if err := saveAccepted(directory, acceptedState{
			Schema:          1,
			Release:         localCheckoutRelease,
			ReleaseSequence: 1,
			CatalogSequence: 1,
			ManifestSHA256:  digest,
		}); err != nil {
			return err
		}
	}
	if err := clearRecovery(directory); err != nil {
		return err
	}
	return clearJournal(directory)
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
