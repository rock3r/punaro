package canopiadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

const (
	defaultMaxSpoolEvents = 4_096
	maxSpoolEventBytes    = 64 << 10
	spoolLockAttempts     = 10
	spoolLockDelay        = 5 * time.Millisecond
	supervisorPoll        = 250 * time.Millisecond
)

// ErrSpoolFull reports that the bounded durable adapter queue is full.
var ErrSpoolFull = errors.New("canopi adapter spool is full")

// Spool durably queues privacy-safe normalized events before detached delivery.
type Spool struct {
	Directory string
	MaxEvents int
	RetryMin  time.Duration
	RetryMax  time.Duration
}

// Enqueue durably records an event. Re-enqueueing the same event ID is harmless.
func (s Spool) Enqueue(event protocol.Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	config, err := s.normalized()
	if err != nil {
		return err
	}
	if err := config.ensureDirectory(); err != nil {
		return err
	}
	release, err := acquireSpoolLock(filepath.Join(config.Directory, ".enqueue.lock"))
	if err != nil {
		return err
	}
	defer release()
	if err := config.removeOrphanTemporaries(); err != nil {
		return err
	}
	target := config.eventPath(event.EventID)
	if _, err := os.Lstat(target); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	files, err := config.eventFiles()
	if err != nil {
		return err
	}
	if len(files) >= config.MaxEvents {
		return ErrSpoolFull
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(payload) > maxSpoolEventBytes {
		return errors.New("normalized Canopi event exceeds spool limit")
	}
	temporary, err := os.CreateTemp(config.Directory, ".event-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryName, target); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return syncDirectory(config.Directory)
}

// Pending returns the number of durable events awaiting acknowledgement.
func (s Spool) Pending() (int, error) {
	config, err := s.normalized()
	if err != nil {
		return 0, err
	}
	if err := config.ensureDirectory(); err != nil {
		return 0, err
	}
	files, err := config.eventFiles()
	return len(files), err
}

// Drain retries queued events with stable IDs until acknowledged or canceled.
// A cross-process lock ensures one detached delivery process drains a spool.
func (s Spool) Drain(ctx context.Context, deliver func(context.Context, protocol.Event) error) error {
	if deliver == nil {
		return errors.New("canopi spool delivery function is required")
	}
	config, err := s.normalized()
	if err != nil {
		return err
	}
	if err := config.ensureDirectory(); err != nil {
		return err
	}
	for {
		release, acquired, err := tryAcquireDrainLock(filepath.Join(config.Directory, ".drain.lock"))
		if err != nil {
			return err
		}
		if !acquired {
			return nil
		}
		err = config.drainLocked(ctx, deliver)
		release()
		if err != nil {
			return err
		}
		pending, err := config.Pending()
		if err != nil || pending == 0 {
			return err
		}
	}
}

// Serve continuously wakes the durable queue and is intended to run under the
// host service manager. A cross-process lease keeps repeated hook kick-starts
// from creating more than one active supervisor.
func (s Spool) Serve(ctx context.Context, deliver func(context.Context, protocol.Event) error) error {
	if deliver == nil {
		return errors.New("canopi spool delivery function is required")
	}
	config, err := s.normalized()
	if err != nil {
		return err
	}
	if err := config.ensureDirectory(); err != nil {
		return err
	}
	release, acquired, err := tryAcquireSupervisorLock(filepath.Join(config.Directory, ".supervisor.lock"))
	if err != nil || !acquired {
		return err
	}
	defer release()
	for {
		if err := config.Drain(ctx, deliver); err != nil {
			return err
		}
		timer := time.NewTimer(supervisorPoll)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s Spool) normalized() (Spool, error) {
	if strings.TrimSpace(s.Directory) == "" || !filepath.IsAbs(s.Directory) {
		return Spool{}, errors.New("canopi spool directory must be absolute")
	}
	if s.MaxEvents == 0 {
		s.MaxEvents = defaultMaxSpoolEvents
	}
	if s.MaxEvents <= 0 || s.MaxEvents > 100_000 {
		return Spool{}, errors.New("canopi spool capacity must be between 1 and 100000")
	}
	if s.RetryMin == 0 {
		s.RetryMin = 250 * time.Millisecond
	}
	if s.RetryMax == 0 {
		s.RetryMax = 30 * time.Second
	}
	if s.RetryMin <= 0 || s.RetryMax < s.RetryMin {
		return Spool{}, errors.New("invalid canopi spool retry policy")
	}
	return s, nil
}

func (s Spool) ensureDirectory() error {
	if err := os.MkdirAll(s.Directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(s.Directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("canopi spool directory must be a private real directory")
	}
	return secureSpoolDirectory(s.Directory, info)
}

func (s Spool) eventPath(eventID string) string {
	digest := sha256.Sum256([]byte(eventID))
	return filepath.Join(s.Directory, hex.EncodeToString(digest[:])+".json")
}

func (s Spool) removeOrphanTemporaries() error {
	directory, err := os.Open(s.Directory) // #nosec G304 -- Directory is the validated private spool.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	removed := false
	for {
		names, readErr := directory.Readdirnames(128)
		for _, name := range names {
			if !strings.HasPrefix(name, ".event-") || !strings.HasSuffix(name, ".tmp") {
				continue
			}
			path := filepath.Join(s.Directory, name)
			info, statErr := os.Lstat(path)
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			if statErr != nil {
				return statErr
			}
			if !info.Mode().IsRegular() {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			removed = true
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if removed {
		return syncDirectory(s.Directory)
	}
	return nil
}

func (s Spool) eventFiles() ([]string, error) {
	entries, err := os.ReadDir(s.Directory)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, filepath.Join(s.Directory, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

func (s Spool) drainLocked(ctx context.Context, deliver func(context.Context, protocol.Event) error) error {
	backoff := s.RetryMin
	for {
		files, err := s.eventFiles()
		if err != nil {
			return err
		}
		if len(files) == 0 {
			return nil
		}
		hadFailure := false
		for _, path := range files {
			payload, err := os.ReadFile(path) // #nosec G304 -- eventFiles returns entries from the configured private spool.
			if err != nil {
				return err
			}
			event, err := protocol.DecodeEvent(strings.NewReader(string(payload)), maxSpoolEventBytes)
			if err != nil {
				_ = os.Remove(path)
				continue
			}
			attemptCtx, cancel := context.WithTimeout(ctx, time.Second)
			err = deliver(attemptCtx, event)
			cancel()
			if err != nil {
				hadFailure = true
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := syncDirectory(s.Directory); err != nil {
				return err
			}
		}
		if !hadFailure {
			backoff = s.RetryMin
			continue
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
		backoff *= 2
		if backoff > s.RetryMax {
			backoff = s.RetryMax
		}
	}
}

func acquireSpoolLock(path string) (func(), error) {
	file, err := openSpoolLockFile(path)
	if err != nil {
		return nil, err
	}
	for range spoolLockAttempts {
		acquired, lockErr := tryLockSpoolFile(file)
		if lockErr != nil {
			_ = file.Close()
			return nil, lockErr
		}
		if acquired {
			return spoolLockRelease(file), nil
		}
		time.Sleep(spoolLockDelay)
	}
	_ = file.Close()
	return nil, errors.New("canopi spool is busy")
}

func tryAcquireDrainLock(path string) (func(), bool, error) {
	return tryAcquireRecoverableLock(path)
}

func tryAcquireSupervisorLock(path string) (func(), bool, error) {
	return tryAcquireRecoverableLock(path)
}

func tryAcquireRecoverableLock(path string) (func(), bool, error) {
	file, err := openSpoolLockFile(path)
	if err != nil {
		return nil, false, err
	}
	acquired, err := tryLockSpoolFile(file)
	if err != nil || !acquired {
		_ = file.Close()
		return func() {}, false, err
	}
	return spoolLockRelease(file), true, nil
}

func openSpoolLockFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- path is inside the configured private spool.
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func spoolLockRelease(file *os.File) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = unlockSpoolFile(file)
			_ = file.Close()
		})
	}
}
