package canopiadapter

import (
	"bytes"
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
	if err := protectSpoolFile(temporaryName, temporary); err != nil {
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
	removed := false
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.Directory, entry.Name())
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !privateSpoolFile(path, info) {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			removed = true
			continue
		}
		files = append(files, path)
	}
	if removed {
		if err := syncDirectory(s.Directory); err != nil {
			return nil, err
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
			payload, err := readPrivateSpoolFile(path, maxSpoolEventBytes)
			if err != nil {
				if removeErr := s.removeQueuedSpoolFile(path); removeErr != nil {
					return removeErr
				}
				continue
			}
			event, err := protocol.DecodeEvent(bytes.NewReader(payload), maxSpoolEventBytes)
			if err != nil {
				if removeErr := s.removeQueuedSpoolFile(path); removeErr != nil {
					return removeErr
				}
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

func readPrivateSpoolFile(path string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !privateSpoolFile(path, before) {
		return nil, errors.New("queued Canopi event must be a private current-user-owned regular file")
	}
	file, err := openSpoolEventFile(path)
	if err != nil {
		return nil, errors.New("queued Canopi event must be a private current-user-owned regular file")
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !privateSpoolFile(path, after) {
		return nil, errors.New("queued Canopi event changed while opening")
	}
	if after.Size() > maxBytes {
		return nil, errors.New("queued Canopi event exceeds size limit")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(payload)) > maxBytes {
		return nil, errors.New("invalid queued Canopi event")
	}
	return payload, nil
}

func (s Spool) removeQueuedSpoolFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(s.Directory)
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
	for range 2 {
		file, err := createSpoolLockFile(path)
		if err == nil {
			if err := protectSpoolFile(path, file); err != nil {
				_ = file.Close()
				_ = os.Remove(path)
				return nil, err
			}
			return file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		before, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !privateSpoolFile(path, before) {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			if err := syncDirectory(filepath.Dir(path)); err != nil {
				return nil, err
			}
			continue
		}
		file, err = openExistingSpoolLockFile(path)
		if err != nil {
			return nil, err
		}
		after, err := file.Stat()
		if err != nil || !os.SameFile(before, after) || !privateSpoolFile(path, after) {
			_ = file.Close()
			return nil, errors.New("canopi spool lock changed while opening")
		}
		return file, nil
	}
	return nil, errors.New("cannot replace unprotected Canopi spool lock")
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
