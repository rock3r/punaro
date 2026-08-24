package canopiadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	defaultEnqueueWait    = 250 * time.Millisecond
	providerEnqueueBudget = 1750 * time.Millisecond
	maxPrimaryLaneBudget  = 750 * time.Millisecond
	enqueueLockPoll       = 5 * time.Millisecond
	supervisorPoll        = 250 * time.Millisecond
	stagingAbandonmentAge = time.Minute
)

// ErrSpoolFull reports that the bounded durable adapter queue is full.
var ErrSpoolFull = errors.New("canopi adapter spool is full")

// Spool durably queues privacy-safe normalized events before detached delivery.
type Spool struct {
	Directory string
	MaxEvents int
	RetryMin  time.Duration
	RetryMax  time.Duration
	// EnqueueLockTimeout bounds the primary lane before contention fallback.
	EnqueueLockTimeout time.Duration
	syncFile           func(*os.File) error
}

// Enqueue durably records an event. Re-enqueueing the same event ID is harmless.
func (s Spool) Enqueue(event protocol.Event) error {
	operationCtx, cancelOperation := context.WithTimeout(context.Background(), providerEnqueueBudget)
	defer cancelOperation()
	if err := event.Validate(); err != nil {
		return err
	}
	config, err := s.normalized()
	if err != nil {
		return err
	}
	if err := config.requirePreparedDirectory(); err != nil {
		return err
	}
	if err := contextErr(operationCtx); err != nil {
		return err
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(payload) > maxSpoolEventBytes {
		return errors.New("normalized Canopi event exceeds spool limit")
	}
	primaryCtx, cancelPrimary := context.WithTimeout(operationCtx, config.EnqueueLockTimeout)
	release, err := acquireSpoolLock(primaryCtx, filepath.Join(config.Directory, ".enqueue.lock"))
	if err == nil {
		err = config.enqueueLocked(primaryCtx, event, payload)
		release()
	}
	cancelPrimary()
	if err == nil {
		return nil
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return err
	}
	return config.enqueueContention(operationCtx, event, payload)
}

// Prepare creates and protects the spool before provider hooks are enabled.
func (s Spool) Prepare() error {
	config, err := s.normalized()
	if err != nil {
		return err
	}
	return config.ensureDirectory()
}

func (s Spool) enqueueLocked(ctx context.Context, event protocol.Event, payload []byte) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := s.removeOrphanTemporaries(ctx); err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	target := s.eventPath(event.EventID)
	match, occupied, err := queuedSpoolEventMatches(target, event.EventID)
	if err == nil && match {
		return nil
	}
	if err != nil && occupied {
		if err := s.removeInvalidQueuedSpoolFile(ctx, target); err != nil {
			return err
		}
		match, occupied, err = queuedSpoolEventMatches(target, event.EventID)
		if err == nil && match {
			return nil
		}
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if occupied {
		return ErrSpoolFull
	}
	if s.primaryEventCapacity() == 0 {
		return s.enqueueContention(ctx, event, payload)
	}
	if match, err := s.contentionEventExists(ctx, event.EventID); err != nil {
		return err
	} else if match {
		return nil
	}
	files, err := s.eventFiles(ctx)
	if err != nil {
		return err
	}
	primaryCount := 0
	for _, path := range files {
		if !strings.HasPrefix(filepath.Base(path), ".contention-") {
			primaryCount++
		}
	}
	if primaryCount >= s.primaryEventCapacity() {
		return s.enqueueContention(ctx, event, payload)
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.Directory, ".event-*.tmp")
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
	if err := os.Link(temporaryName, target); err != nil && !errors.Is(err, os.ErrExist) {
		_ = temporary.Close()
		return err
	}
	if err := s.syncSpoolFile(temporary); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return syncDirectory(s.Directory)
}

func (s Spool) enqueueContention(ctx context.Context, event protocol.Event, payload []byte) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	match, occupied, err := queuedSpoolEventMatches(s.eventPath(event.EventID), event.EventID)
	if err == nil && match {
		return nil
	}
	if err != nil && occupied {
		if removeErr := s.removeInvalidQueuedSpoolFile(ctx, s.eventPath(event.EventID)); removeErr != nil {
			return removeErr
		}
		match, occupied, err = queuedSpoolEventMatches(s.eventPath(event.EventID), event.EventID)
		if err == nil && match {
			return nil
		}
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if occupied {
		return ErrSpoolFull
	}
	slots := s.contentionSlotCount()
	digest := sha256.Sum256([]byte(event.EventID))
	start := 0
	for _, value := range digest[:8] {
		start = (start*256 + int(value)) % slots
	}
	for offset := range slots {
		if err := contextErr(ctx); err != nil {
			return err
		}
		slot := (start + offset) % slots
		path := filepath.Join(s.Directory, fmt.Sprintf(".contention-%06d.json", slot))
		matched, created, occupied, err := s.publishIntoContentionSlot(ctx, path, event.EventID, payload)
		if err != nil {
			return err
		}
		if matched || created {
			return nil
		}
		if occupied {
			continue
		}
		match, _, err := queuedSpoolEventMatches(path, event.EventID)
		if err == nil && match {
			return nil
		}
	}
	return ErrSpoolFull
}

func (s Spool) publishIntoContentionSlot(ctx context.Context, path, eventID string, payload []byte) (matched, created, occupied bool, err error) {
	err = withSpoolRepairLock(ctx, path, func() error {
		var inspectErr error
		matched, occupied, inspectErr = queuedSpoolEventMatches(path, eventID)
		if inspectErr != nil {
			before, statErr := os.Lstat(path)
			switch {
			case errors.Is(statErr, os.ErrNotExist):
				occupied = false
			case statErr != nil:
				return statErr
			default:
				removed, removeErr := removeSpoolFileIfSame(path, before)
				if removeErr != nil {
					return removeErr
				}
				if removed {
					if syncErr := syncDirectory(s.Directory); syncErr != nil {
						return syncErr
					}
				}
				occupied = !removed
			}
		}
		if matched || occupied {
			return nil
		}
		created, inspectErr = s.publishContentionEvent(ctx, path, payload)
		return inspectErr
	})
	return matched, created, occupied, err
}

func (s Spool) contentionEventExists(ctx context.Context, eventID string) (bool, error) {
	for slot := range s.contentionSlotCount() {
		if err := contextErr(ctx); err != nil {
			return false, err
		}
		path := filepath.Join(s.Directory, fmt.Sprintf(".contention-%06d.json", slot))
		match := false
		err := withSpoolRepairLock(ctx, path, func() error {
			var occupied bool
			var inspectErr error
			match, occupied, inspectErr = queuedSpoolEventMatches(path, eventID)
			if inspectErr == nil || !occupied {
				return inspectErr
			}
			before, statErr := os.Lstat(path)
			if errors.Is(statErr, os.ErrNotExist) {
				return nil
			}
			if statErr != nil {
				return statErr
			}
			removed, removeErr := removeSpoolFileIfSame(path, before)
			if removeErr != nil || !removed {
				return removeErr
			}
			return syncDirectory(s.Directory)
		})
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

func (s Spool) contentionSlotCount() int {
	slots := s.MaxEvents / 16
	if slots < 1 {
		slots = 1
	}
	if slots > 256 {
		slots = 256
	}
	return slots
}

func (s Spool) primaryEventCapacity() int {
	return s.MaxEvents - s.contentionSlotCount()
}

func queuedSpoolEventMatches(path, eventID string) (match, occupied bool, err error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	} else if err != nil {
		return false, false, err
	}
	payload, err := readPrivateSpoolFile(path, maxSpoolEventBytes)
	if err != nil {
		return false, true, err
	}
	event, err := protocol.DecodeEvent(bytes.NewReader(payload), maxSpoolEventBytes)
	if err != nil {
		return false, true, err
	}
	return event.EventID == eventID, true, nil
}

func (s Spool) publishContentionEvent(ctx context.Context, target string, payload []byte) (created bool, err error) {
	// The pre-lock name is outside the ordinary cleanup namespace. Once the
	// inode is locked, renaming it makes ownership visible to cleanup atomically.
	temporary, err := os.CreateTemp(s.Directory, ".contention-publishing-*.tmp")
	if err != nil {
		return false, err
	}
	temporaryName := temporary.Name()
	locked := false
	defer func() {
		if locked {
			_ = unlockSpoolFile(temporary)
		}
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}()
	if err := protectSpoolFile(temporaryName, temporary); err != nil {
		return false, err
	}
	if err := lockSpoolFile(temporary); err != nil {
		return false, err
	}
	locked = true
	cleanupName := filepath.Join(s.Directory, strings.Replace(filepath.Base(temporaryName), ".contention-publishing-", ".contention-event-", 1))
	if err := os.Rename(temporaryName, cleanupName); err != nil {
		return false, err
	}
	temporaryName = cleanupName
	if _, err := temporary.Write(payload); err != nil {
		return false, err
	}
	linkErr := os.Link(temporaryName, target)
	if linkErr != nil && !errors.Is(linkErr, os.ErrExist) {
		return false, linkErr
	}
	if err := s.syncSpoolFile(temporary); err != nil {
		return false, err
	}
	if err := os.Remove(temporaryName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := syncDirectory(s.Directory); err != nil {
		return false, err
	}
	return linkErr == nil, nil
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
	files, err := config.eventFiles(context.Background())
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
	return config.drainPrepared(ctx, deliver)
}

func (s Spool) drainPrepared(ctx context.Context, deliver func(context.Context, protocol.Event) error) error {
	for {
		release, acquired, err := tryAcquireDrainLock(filepath.Join(s.Directory, ".drain.lock"))
		if err != nil {
			return err
		}
		if !acquired {
			return nil
		}
		err = s.drainLocked(ctx, deliver)
		release()
		if err != nil {
			return err
		}
		files, err := s.eventFiles(ctx)
		pending := len(files)
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
	directoryIdentity, err := spoolDirectoryIdentity(config.Directory)
	if err != nil {
		return err
	}
	release, acquired, err := tryAcquireSupervisorLock(filepath.Join(config.Directory, ".supervisor.lock"))
	if err != nil || !acquired {
		return err
	}
	defer release()
	for {
		if err := validateSpoolDirectoryIdentity(config.Directory, directoryIdentity); err != nil {
			return fmt.Errorf("Canopi spool directory changed while supervisor was running: %w", err)
		}
		if err := config.drainPrepared(ctx, deliver); err != nil {
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
	if err := validateSpoolDirectoryAncestors(s.Directory); err != nil {
		return Spool{}, err
	}
	canonicalDirectory, err := canonicalSpoolDirectory(s.Directory)
	if err == nil {
		s.Directory = canonicalDirectory
	} else if !errors.Is(err, os.ErrNotExist) {
		return Spool{}, err
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
	if s.EnqueueLockTimeout == 0 {
		s.EnqueueLockTimeout = defaultEnqueueWait
	}
	if s.EnqueueLockTimeout <= 0 || s.EnqueueLockTimeout > maxPrimaryLaneBudget {
		return Spool{}, errors.New("canopi primary enqueue budget must be at most 750 milliseconds")
	}
	if s.syncFile == nil {
		s.syncFile = func(file *os.File) error { return file.Sync() }
	}
	return s, nil
}

func contextErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
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
	if err := secureSpoolDirectory(s.Directory, info); err != nil {
		return err
	}
	return prepareSpoolRepairCoordinator(s.Directory)
}

func (s Spool) requirePreparedDirectory() error {
	_, err := spoolDirectoryIdentity(s.Directory)
	return err
}

func spoolDirectoryIdentity(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("canopi spool is not prepared: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !privateSpoolDirectory(path, info) {
		return nil, errors.New("canopi spool is not a prepared private real directory")
	}
	return info, nil
}

func validateSpoolDirectoryIdentity(path string, expected os.FileInfo) error {
	current, err := spoolDirectoryIdentity(path)
	if err != nil {
		return err
	}
	if !os.SameFile(expected, current) {
		return errors.New("prepared Canopi spool directory was replaced")
	}
	return nil
}

func (s Spool) eventPath(eventID string) string {
	digest := sha256.Sum256([]byte(eventID))
	return filepath.Join(s.Directory, hex.EncodeToString(digest[:])+".json")
}

func (s Spool) removeOrphanTemporaries(ctx context.Context) error {
	directory, err := os.Open(s.Directory) // #nosec G304 -- Directory is the validated private spool.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	removed := false
	for {
		if err := contextErr(ctx); err != nil {
			return err
		}
		names, readErr := directory.Readdirnames(128)
		for _, name := range names {
			if err := contextErr(ctx); err != nil {
				return err
			}
			ordinaryTemporary := strings.HasPrefix(name, ".event-") || strings.HasPrefix(name, ".contention-event-")
			publishingTemporary := strings.HasPrefix(name, ".contention-publishing-")
			if (!ordinaryTemporary && !publishingTemporary) || !strings.HasSuffix(name, ".tmp") {
				continue
			}
			path := filepath.Join(s.Directory, name)
			before, statErr := os.Lstat(path)
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			if statErr != nil {
				return statErr
			}
			// A publisher locks before renaming into the ordinary cleanup
			// namespace. Only a pre-lock file older than the provider lifetime
			// can be an abandoned crash remnant.
			if publishingTemporary && time.Since(before.ModTime()) < stagingAbandonmentAge {
				continue
			}
			if !privateSpoolFile(path, before) {
				removedNow, err := removeSpoolFileIfSame(path, before)
				if err != nil {
					return err
				}
				removed = removed || removedNow
				continue
			}
			file, err := openSpoolEventFile(path)
			if err != nil {
				return err
			}
			after, err := file.Stat()
			if err != nil || !os.SameFile(before, after) || !privateSpoolFile(path, after) {
				_ = file.Close()
				return errors.New("queued Canopi temporary changed while opening")
			}
			acquired, err := tryLockSpoolFile(file)
			if err != nil {
				_ = file.Close()
				return err
			}
			if !acquired {
				_ = file.Close()
				continue
			}
			removedNow, err := removeSpoolFileIfSame(path, after)
			if err != nil {
				_ = unlockSpoolFile(file)
				_ = file.Close()
				return err
			}
			_ = unlockSpoolFile(file)
			_ = file.Close()
			removed = removed || removedNow
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

func (s Spool) eventFiles(ctx context.Context) ([]string, error) {
	directory, err := os.Open(s.Directory) // #nosec G304 -- Directory is the validated private spool.
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	files := make([]string, 0, s.MaxEvents)
	removed := false
	for {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			if err := contextErr(ctx); err != nil {
				return nil, err
			}
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
				removedNow := false
				err := withSpoolRepairLock(ctx, path, func() error {
					current, statErr := os.Lstat(path)
					if errors.Is(statErr, os.ErrNotExist) {
						return nil
					}
					if statErr != nil || privateSpoolFile(path, current) {
						return statErr
					}
					var removeErr error
					removedNow, removeErr = removeSpoolFileIfSame(path, current)
					return removeErr
				})
				if err != nil {
					return nil, err
				}
				removed = removed || removedNow
				continue
			}
			files = append(files, path)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
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
		files, err := s.eventFiles(ctx)
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
				if removeErr := s.removeInvalidQueuedSpoolFile(ctx, path); removeErr != nil {
					return removeErr
				}
				continue
			}
			event, err := protocol.DecodeEvent(bytes.NewReader(payload), maxSpoolEventBytes)
			if err != nil {
				if removeErr := s.removeInvalidQueuedSpoolFile(ctx, path); removeErr != nil {
					return removeErr
				}
				continue
			}
			if err := syncPrivateSpoolFile(path, s.syncSpoolFile); err != nil {
				hadFailure = true
				continue
			}
			if err := syncDirectory(s.Directory); err != nil {
				hadFailure = true
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

func syncPrivateSpoolFile(path string, syncFile func(*os.File) error) error {
	before, err := os.Lstat(path)
	if err != nil || !privateSpoolFile(path, before) {
		return errors.New("queued Canopi event must be a private current-user-owned regular file")
	}
	file, err := openSpoolEventFileForSync(path)
	if err != nil {
		return errors.New("queued Canopi event must be a private current-user-owned regular file")
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !privateSpoolFile(path, after) {
		return errors.New("queued Canopi event changed while opening for sync")
	}
	return syncFile(file)
}

func (s Spool) syncSpoolFile(file *os.File) error {
	if s.syncFile != nil {
		return s.syncFile(file)
	}
	return file.Sync()
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

func (s Spool) removeInvalidQueuedSpoolFile(ctx context.Context, path string) error {
	return withSpoolRepairLock(ctx, path, func() error {
		before, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		payload, readErr := readPrivateSpoolFile(path, maxSpoolEventBytes)
		if readErr == nil {
			_, readErr = protocol.DecodeEvent(bytes.NewReader(payload), maxSpoolEventBytes)
		}
		if readErr == nil {
			return nil
		}
		removed, err := removeSpoolFileIfSame(path, before)
		if err != nil || !removed {
			return err
		}
		return syncDirectory(s.Directory)
	})
}

func acquireSpoolLock(ctx context.Context, path string) (func(), error) {
	file, err := openSpoolLockFile(ctx, path)
	if err != nil {
		return nil, err
	}
	for {
		acquired, err := tryLockSpoolFile(file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		if acquired {
			return spoolLockRelease(file), nil
		}
		timer := time.NewTimer(enqueueLockPoll)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func tryAcquireDrainLock(path string) (func(), bool, error) {
	return tryAcquireRecoverableLock(path)
}

func tryAcquireSupervisorLock(path string) (func(), bool, error) {
	return tryAcquireRecoverableLock(path)
}

func tryAcquireRecoverableLock(path string) (func(), bool, error) {
	file, err := openSpoolLockFile(context.Background(), path)
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

func openSpoolLockFile(ctx context.Context, path string) (*os.File, error) {
	for range 4 {
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
			err := withSpoolRepairLock(ctx, path, func() error {
				current, err := os.Lstat(path)
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				if err != nil || privateSpoolFile(path, current) {
					return err
				}
				removed, err := removeSpoolFileIfSame(path, current)
				if err != nil || !removed {
					return err
				}
				return syncDirectory(filepath.Dir(path))
			})
			if err != nil {
				return nil, err
			}
			continue
		}
		file, err = openExistingSpoolLockFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		after, err := file.Stat()
		if err != nil || !os.SameFile(before, after) || !privateSpoolFile(path, after) {
			_ = file.Close()
			if err == nil && !os.SameFile(before, after) {
				continue
			}
			return nil, errors.New("canopi spool lock changed while opening")
		}
		return file, nil
	}
	return nil, errors.New("cannot replace unprotected Canopi spool lock")
}

func removeSpoolFileIfSame(path string, inspected os.FileInfo) (bool, error) {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !os.SameFile(inspected, current) {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
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
