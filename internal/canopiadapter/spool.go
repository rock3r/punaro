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
	enqueueLockPoll       = 5 * time.Millisecond
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
	// EnqueueLockTimeout bounds the primary lane below the provider hook deadline.
	EnqueueLockTimeout time.Duration
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
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(payload) > maxSpoolEventBytes {
		return errors.New("normalized Canopi event exceeds spool limit")
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), config.EnqueueLockTimeout)
	defer cancel()
	release, err := acquireSpoolLock(waitCtx, filepath.Join(config.Directory, ".enqueue.lock"))
	if errors.Is(err, context.DeadlineExceeded) {
		return config.enqueueContention(event, payload)
	}
	if err != nil {
		return err
	}
	defer release()
	return config.enqueueLocked(event, payload)
}

func (s Spool) enqueueLocked(event protocol.Event, payload []byte) error {
	if err := s.removeOrphanTemporaries(); err != nil {
		return err
	}
	target := s.eventPath(event.EventID)
	match, occupied, err := queuedSpoolEventMatches(target, event.EventID)
	if err == nil && match {
		return nil
	}
	if err != nil && occupied {
		if err := s.removeQueuedSpoolFile(target); err != nil {
			return err
		}
		occupied = false
	} else if err != nil {
		return err
	}
	if occupied {
		return ErrSpoolFull
	}
	if s.primaryEventCapacity() == 0 {
		return s.enqueueContention(event, payload)
	}
	if match, err := s.contentionEventExists(event.EventID); err != nil {
		return err
	} else if match {
		return nil
	}
	files, err := s.eventFiles()
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
		return ErrSpoolFull
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
	return syncDirectory(s.Directory)
}

func (s Spool) enqueueContention(event protocol.Event, payload []byte) error {
	match, occupied, err := queuedSpoolEventMatches(s.eventPath(event.EventID), event.EventID)
	if err == nil && match {
		return nil
	}
	if err != nil && occupied {
		if removeErr := s.removeQueuedSpoolFile(s.eventPath(event.EventID)); removeErr != nil {
			return removeErr
		}
		occupied = false
	} else if err != nil {
		return err
	}
	if occupied {
		return ErrSpoolFull
	}
	files, err := s.eventFiles()
	if err != nil {
		return err
	}
	primaryCount := 0
	for _, path := range files {
		if !strings.HasPrefix(filepath.Base(path), ".contention-") {
			primaryCount++
		}
	}
	if primaryCount > s.primaryEventCapacity() {
		return ErrSpoolFull
	}
	slots := s.contentionSlotCount()
	digest := sha256.Sum256([]byte(event.EventID))
	start := 0
	for _, value := range digest[:8] {
		start = (start*256 + int(value)) % slots
	}
	for offset := range slots {
		slot := (start + offset) % slots
		path := filepath.Join(s.Directory, fmt.Sprintf(".contention-%06d.json", slot))
		match, occupied, err := queuedSpoolEventMatches(path, event.EventID)
		if err != nil {
			if removeErr := s.removeQueuedSpoolFile(path); removeErr != nil {
				return removeErr
			}
			occupied = false
		}
		if match {
			return nil
		}
		if occupied {
			continue
		}
		created, err := s.publishContentionEvent(path, payload)
		if err != nil {
			return err
		}
		if created {
			return nil
		}
		match, _, err = queuedSpoolEventMatches(path, event.EventID)
		if err == nil && match {
			return nil
		}
	}
	return ErrSpoolFull
}

func (s Spool) contentionEventExists(eventID string) (bool, error) {
	for slot := range s.contentionSlotCount() {
		path := filepath.Join(s.Directory, fmt.Sprintf(".contention-%06d.json", slot))
		match, _, err := queuedSpoolEventMatches(path, eventID)
		if err != nil {
			if removeErr := s.removeQueuedSpoolFile(path); removeErr != nil {
				return false, removeErr
			}
			continue
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

func (s Spool) publishContentionEvent(target string, payload []byte) (created bool, err error) {
	temporary, err := os.CreateTemp(s.Directory, ".contention-event-*.tmp")
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
	if _, err := temporary.Write(payload); err != nil {
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		return false, err
	}
	linkErr := os.Link(temporaryName, target)
	if linkErr != nil && !errors.Is(linkErr, os.ErrExist) {
		return false, linkErr
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
	if s.EnqueueLockTimeout == 0 {
		s.EnqueueLockTimeout = defaultEnqueueWait
	}
	if s.EnqueueLockTimeout <= 0 || s.EnqueueLockTimeout >= 2*time.Second {
		return Spool{}, errors.New("canopi enqueue lock timeout must be below two seconds")
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
			if (!strings.HasPrefix(name, ".event-") && !strings.HasPrefix(name, ".contention-event-")) || !strings.HasSuffix(name, ".tmp") {
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
			if !privateSpoolFile(path, before) {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				removed = true
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
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				_ = unlockSpoolFile(file)
				_ = file.Close()
				return err
			}
			_ = unlockSpoolFile(file)
			_ = file.Close()
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

func acquireSpoolLock(ctx context.Context, path string) (func(), error) {
	file, err := openSpoolLockFile(path)
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
