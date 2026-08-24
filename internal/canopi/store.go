// Package canopi maintains normalized agent state and renders the panel view.
package canopi

import (
	"bytes"
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
	maxRememberedEventIDs             = 50_000
	defaultMaxStateBytes        int64 = 8 << 20
	minMaxStateBytes            int64 = 2 << 10
	maxMaxStateBytes            int64 = 64 << 20
	persistedStateEnvelopeBytes       = 512
)

var (
	// ErrLiveRecordLimit reports bounded admission of a new agent identity.
	ErrLiveRecordLimit = errors.New("canopi live record limit reached")
	// ErrFutureActivity reports an untrusted activity timestamp beyond allowed skew.
	ErrFutureActivity = errors.New("canopi activity timestamp is too far in the future")
	// ErrStateByteLimit reports bounded aggregate serialized state admission.
	ErrStateByteLimit = errors.New("canopi serialized state byte limit reached")
	// ErrStateStoreLocked reports another collector using the same state file.
	ErrStateStoreLocked = errors.New("canopi state file is already in use")
)

// Config controls lifecycle expiry and completed-agent retention.
type Config struct {
	WorkingTTL     time.Duration
	DoneRetention  time.Duration
	MaxLiveRecords int
	MaxStateBytes  int64
	MaxFutureSkew  time.Duration
}

// DefaultConfig returns the production MVP retention settings.
func DefaultConfig() Config {
	return Config{
		WorkingTTL:     30 * time.Minute,
		DoneRetention:  2 * time.Hour,
		MaxLiveRecords: 2_048,
		MaxStateBytes:  defaultMaxStateBytes,
		MaxFutureSkew:  5 * time.Minute,
	}
}

func (c Config) normalized() (Config, error) {
	defaults := DefaultConfig()
	if c.MaxLiveRecords == 0 {
		c.MaxLiveRecords = defaults.MaxLiveRecords
	}
	if c.MaxFutureSkew == 0 {
		c.MaxFutureSkew = defaults.MaxFutureSkew
	}
	if c.MaxStateBytes == 0 {
		c.MaxStateBytes = defaults.MaxStateBytes
	}
	if c.WorkingTTL <= 0 {
		return Config{}, errors.New("working TTL must be positive")
	}
	if c.DoneRetention <= 0 {
		return Config{}, errors.New("done retention must be positive")
	}
	if c.MaxLiveRecords <= 0 || c.MaxLiveRecords > 100_000 {
		return Config{}, errors.New("max live records must be between 1 and 100000")
	}
	if c.MaxStateBytes < minMaxStateBytes || c.MaxStateBytes > maxMaxStateBytes {
		return Config{}, fmt.Errorf("max state bytes must be between %d and %d", minMaxStateBytes, maxMaxStateBytes)
	}
	if c.MaxFutureSkew <= 0 || c.MaxFutureSkew > time.Hour {
		return Config{}, errors.New("max future skew must be between zero and one hour")
	}
	return c, nil
}

// ApplyResult describes how one event affected current state.
type ApplyResult struct {
	Applied   bool `json:"applied"`
	Duplicate bool `json:"duplicate"`
	Stale     bool `json:"stale"`
}

// Totals reports current agent counts by display state.
type Totals struct {
	Waiting int `json:"waiting"`
	Done    int `json:"done"`
	Working int `json:"working"`
}

// Snapshot is an ordered, point-in-time view of current agent state.
type Snapshot struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Revision    uint64           `json:"revision"`
	Totals      Totals           `json:"totals"`
	Agents      []protocol.Event `json:"agents"`
}

// Store applies idempotent lifecycle events and optionally persists them.
type Store struct {
	mu        sync.Mutex
	config    Config
	records   map[string]protocol.Event
	seen      map[string]struct{}
	seenOrder []string
	revision  uint64
	now       func() time.Time
	persist   func(persistedStore) error
	release   func() error
	closeOnce sync.Once
	closeErr  error
}

type persistedStore struct {
	Revision  uint64           `json:"revision"`
	Records   []protocol.Event `json:"records"`
	SeenOrder []string         `json:"seen_event_ids"`
}

// NewStore constructs an in-memory store with validated configuration.
func NewStore(config Config) *Store {
	normalized, err := config.normalized()
	if err != nil {
		panic(err)
	}
	return &Store{
		config:  normalized,
		records: make(map[string]protocol.Event),
		seen:    make(map[string]struct{}),
		now:     time.Now,
		persist: func(persistedStore) error { return nil },
	}
}

// OpenStore opens or creates an atomically persisted state store.
func OpenStore(path string, config Config) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("state path must be absolute and clean")
	}
	normalized, err := config.normalized()
	if err != nil {
		return nil, err
	}
	if err := prepareStateDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("protect Canopi state directory: %w", err)
	}
	if err := prepareStateRepairCoordinator(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("prepare Canopi state repair coordinator: %w", err)
	}
	pinnedPath, err := canonicalStatePath(path)
	if err != nil {
		return nil, fmt.Errorf("pin Canopi state path: %w", err)
	}
	store := NewStore(normalized)
	store.persist = func(state persistedStore) error {
		return persistStore(pinnedPath, state, normalized.MaxStateBytes)
	}
	release, err := acquireStateStoreLock(pinnedPath)
	if err != nil {
		return nil, fmt.Errorf("lock Canopi state: %w", err)
	}
	store.release = release
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = store.Close()
		}
	}()
	if err := recoverStateReplacement(pinnedPath); err != nil {
		return nil, fmt.Errorf("recover Canopi state replacement: %w", err)
	}
	file, err := openPrivateStateFile(pinnedPath)
	if errors.Is(err, os.ErrNotExist) {
		keepOpen = true
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Canopi state: %w", err)
	}
	defer func() { _ = file.Close() }()
	limit := store.config.MaxStateBytes
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect Canopi state: %w", err)
	}
	if info.Size() > limit {
		return nil, errors.New("persisted Canopi state exceeds limit")
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read Canopi state: %w", err)
	}
	if int64(len(payload)) > limit {
		return nil, errors.New("persisted Canopi state exceeds limit")
	}
	var persisted persistedStore
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&persisted); err != nil {
		return nil, fmt.Errorf("decode Canopi state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("persisted Canopi state must contain exactly one JSON object")
	}
	if len(persisted.SeenOrder) > maxRememberedEventIDs {
		return nil, errors.New("persisted Canopi dedupe set exceeds limit")
	}
	if len(persisted.Records) > store.config.MaxLiveRecords {
		return nil, errors.New("persisted Canopi live record set exceeds limit")
	}
	if err := ensurePersistedStateWithinBudget(persisted, store.config.MaxStateBytes); err != nil {
		return nil, err
	}
	for _, event := range persisted.Records {
		if err := event.Validate(); err != nil {
			return nil, fmt.Errorf("invalid persisted event %q: %w", event.EventID, err)
		}
		store.records[event.Key()] = event
	}
	for _, eventID := range persisted.SeenOrder {
		if _, duplicate := store.seen[eventID]; duplicate {
			continue
		}
		store.seen[eventID] = struct{}{}
		store.seenOrder = append(store.seenOrder, eventID)
	}
	store.revision = persisted.Revision
	keepOpen = true
	return store, nil
}

// Close releases this persisted store's lifetime writer lock. It is safe to call repeatedly.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.release != nil {
			s.closeErr = s.release()
		}
	})
	return s.closeErr
}

// Apply validates and idempotently incorporates one lifecycle event.
func (s *Store) Apply(event protocol.Event) (ApplyResult, error) {
	if err := event.Validate(); err != nil {
		return ApplyResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, duplicate := s.seen[event.EventID]; duplicate {
		return ApplyResult{Duplicate: true}, nil
	}
	now := s.now()
	if event.ActivityAt.After(now.Add(s.config.MaxFutureSkew)) {
		return ApplyResult{}, ErrFutureActivity
	}
	if err := s.expireLocked(now); err != nil {
		return ApplyResult{}, err
	}
	existing, exists := s.records[event.Key()]
	if !exists && len(s.records) >= s.config.MaxLiveRecords {
		return ApplyResult{}, ErrLiveRecordLimit
	}
	nextRecords := cloneRecords(s.records)
	nextSeen := cloneSeen(s.seen)
	nextSeenOrder := append([]string(nil), s.seenOrder...)
	rememberEventID(nextSeen, &nextSeenOrder, event.EventID)
	nextRevision := s.revision
	result := ApplyResult{}
	if exists && (event.ActivityAt.Before(existing.ActivityAt) ||
		(event.ActivityAt.Equal(existing.ActivityAt) && event.EventID <= existing.EventID)) {
		result.Stale = true
	} else {
		nextRecords[event.Key()] = event
		nextRevision++
		result.Applied = true
	}
	nextState := persistedState(nextRevision, nextRecords, nextSeenOrder)
	if err := trimSeenOrderToBudget(nextState.Records, nextSeen, &nextSeenOrder, s.config.MaxStateBytes); err != nil {
		return ApplyResult{}, err
	}
	nextState.SeenOrder = append([]string(nil), nextSeenOrder...)
	if err := ensurePersistedStateWithinBudget(nextState, s.config.MaxStateBytes); err != nil {
		return ApplyResult{}, err
	}
	if err := s.persist(nextState); err != nil {
		return ApplyResult{}, err
	}
	s.records = nextRecords
	s.seen = nextSeen
	s.seenOrder = nextSeenOrder
	s.revision = nextRevision
	return result, nil
}

func (s *Store) expireLocked(now time.Time) error {
	nextRecords := cloneRecords(s.records)
	changed := false
	for key, event := range s.records {
		age := now.Sub(event.ActivityAt)
		expired := event.State == protocol.StateDone && age > s.config.DoneRetention
		if event.State != protocol.StateDone && age > s.config.WorkingTTL {
			expired = true
		}
		if expired {
			delete(nextRecords, key)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	nextRevision := s.revision + 1
	if err := s.persist(persistedState(nextRevision, nextRecords, s.seenOrder)); err != nil {
		return err
	}
	s.records = nextRecords
	s.revision = nextRevision
	return nil
}

// Revision returns the monotonic revision of visible current state.
func (s *Store) Revision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revision
}

// Snapshot expires stale agents and returns them in display order.
func (s *Store) Snapshot(now time.Time) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	agents := make([]protocol.Event, 0, len(s.records))
	nextRecords := cloneRecords(s.records)
	for key, event := range s.records {
		age := now.Sub(event.ActivityAt)
		expired := event.State == protocol.StateDone && age > s.config.DoneRetention
		if event.State != protocol.StateDone && age > s.config.WorkingTTL {
			expired = true
		}
		if expired {
			delete(nextRecords, key)
			changed = true
			continue
		}
		agents = append(agents, event)
	}
	if changed {
		nextRevision := s.revision + 1
		if err := s.persist(persistedState(nextRevision, nextRecords, s.seenOrder)); err == nil {
			s.records = nextRecords
			s.revision = nextRevision
		} else {
			// Expiry is committed transactionally. If durable state cannot be
			// updated, keep the acknowledged records visible so the unchanged
			// revision cannot address two different snapshots or render images.
			agents = agents[:0]
			for _, event := range s.records {
				agents = append(agents, event)
			}
		}
	}
	SortEvents(agents)
	snapshot := Snapshot{GeneratedAt: now.UTC(), Revision: s.revision, Agents: agents}
	for _, event := range agents {
		switch event.State {
		case protocol.StateWaitingForUser:
			snapshot.Totals.Waiting++
		case protocol.StateDone:
			snapshot.Totals.Done++
		case protocol.StateWorking:
			snapshot.Totals.Working++
		}
	}
	return snapshot
}

// SortEvents orders events by waiting, done, working, then recent activity.
func SortEvents(events []protocol.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		left, right := stateRank(events[i].State), stateRank(events[j].State)
		if left != right {
			return left < right
		}
		if !events[i].ActivityAt.Equal(events[j].ActivityAt) {
			return events[i].ActivityAt.After(events[j].ActivityAt)
		}
		return events[i].EventID > events[j].EventID
	})
}

func stateRank(state protocol.State) int {
	switch state {
	case protocol.StateWaitingForUser:
		return 0
	case protocol.StateDone:
		return 1
	default:
		return 2
	}
}

func rememberEventID(seen map[string]struct{}, order *[]string, eventID string) {
	if len(*order) == maxRememberedEventIDs {
		oldest := (*order)[0]
		delete(seen, oldest)
		copy(*order, (*order)[1:])
		*order = (*order)[:len(*order)-1]
	}
	seen[eventID] = struct{}{}
	*order = append(*order, eventID)
}

func cloneRecords(records map[string]protocol.Event) map[string]protocol.Event {
	cloned := make(map[string]protocol.Event, len(records))
	for key, event := range records {
		cloned[key] = event
	}
	return cloned
}

func cloneSeen(seen map[string]struct{}) map[string]struct{} {
	cloned := make(map[string]struct{}, len(seen))
	for eventID := range seen {
		cloned[eventID] = struct{}{}
	}
	return cloned
}

func persistedState(revision uint64, records map[string]protocol.Event, seenOrder []string) persistedStore {
	orderedRecords := make([]protocol.Event, 0, len(records))
	for _, event := range records {
		orderedRecords = append(orderedRecords, event)
	}
	SortEvents(orderedRecords)
	return persistedStore{Revision: revision, Records: orderedRecords, SeenOrder: append([]string(nil), seenOrder...)}
}

func persistStore(path string, state persistedStore, maxBytes int64) error {
	directory := filepath.Dir(path)
	if err := prepareStateDirectory(directory); err != nil {
		return fmt.Errorf("protect Canopi state directory: %w", err)
	}
	temporaryPrefix := stateTemporaryPrefix(path)
	if err := removeStateTemporaries(directory, filepath.Base(path), temporaryPrefix); err != nil {
		return fmt.Errorf("reclaim Canopi state temporaries: %w", err)
	}
	if err := ensurePersistedStateWithinBudget(state, maxBytes); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode Canopi state: %w", err)
	}
	if int64(len(payload)) > maxBytes {
		return ErrStateByteLimit
	}
	temporary, err := os.CreateTemp(directory, temporaryPrefix+"*")
	if err != nil {
		return fmt.Errorf("create Canopi state file: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := protectStateFile(temporaryName, temporary); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect Canopi state file: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write Canopi state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync Canopi state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Canopi state: %w", err)
	}
	if err := replaceStateFile(temporaryName, path); err != nil {
		return fmt.Errorf("replace Canopi state: %w", err)
	}
	return nil
}

func ensurePersistedStateWithinBudget(state persistedStore, maxBytes int64) error {
	used, err := serializedRecordStateBytes(state.Records)
	if err != nil {
		return err
	}
	if used > maxBytes {
		return ErrStateByteLimit
	}
	for _, eventID := range state.SeenOrder {
		payload, err := json.Marshal(eventID)
		if err != nil {
			return fmt.Errorf("encode Canopi event ID for state budget: %w", err)
		}
		used += int64(len(payload) + 1)
		if used > maxBytes {
			return ErrStateByteLimit
		}
	}
	return nil
}

func trimSeenOrderToBudget(records []protocol.Event, seen map[string]struct{}, order *[]string, maxBytes int64) error {
	used, err := serializedRecordStateBytes(records)
	if err != nil {
		return err
	}
	if used > maxBytes {
		return ErrStateByteLimit
	}
	if len(*order) == 0 {
		return nil
	}
	latestPayload, err := json.Marshal((*order)[len(*order)-1])
	if err != nil {
		return fmt.Errorf("encode Canopi event ID for state budget: %w", err)
	}
	used += int64(len(latestPayload) + 1)
	if used > maxBytes {
		return ErrStateByteLimit
	}
	firstRetained := len(*order) - 1
	for firstRetained > 0 {
		payload, err := json.Marshal((*order)[firstRetained-1])
		if err != nil {
			return fmt.Errorf("encode Canopi event ID for state budget: %w", err)
		}
		next := used + int64(len(payload)+1)
		if next > maxBytes {
			break
		}
		used = next
		firstRetained--
	}
	for _, eventID := range (*order)[:firstRetained] {
		delete(seen, eventID)
	}
	*order = append([]string(nil), (*order)[firstRetained:]...)
	return nil
}

func serializedRecordStateBytes(records []protocol.Event) (int64, error) {
	used := int64(persistedStateEnvelopeBytes)
	for _, event := range records {
		payload, err := json.Marshal(event)
		if err != nil {
			return 0, fmt.Errorf("encode Canopi event for state budget: %w", err)
		}
		used += int64(len(payload) + 1)
	}
	return used, nil
}

func stateTemporaryPrefix(path string) string {
	digest := sha256.Sum256([]byte(filepath.Base(path)))
	return ".canopi-state-" + hex.EncodeToString(digest[:8]) + "-"
}

func removeStateTemporaries(directory, targetName, temporaryPrefix string) error {
	directoryHandle, err := os.Open(directory) // #nosec G304 -- directory is the selected state file's parent.
	if err != nil {
		return err
	}
	defer func() { _ = directoryHandle.Close() }()
	removed := false
	for {
		names, readErr := directoryHandle.Readdirnames(128)
		for _, name := range names {
			if name == targetName || !strings.HasPrefix(name, temporaryPrefix) {
				continue
			}
			candidate := filepath.Join(directory, name)
			info, statErr := os.Lstat(candidate)
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			if statErr != nil {
				return statErr
			}
			if !info.Mode().IsRegular() {
				continue
			}
			if err := os.Remove(candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
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
		return syncStateDirectory(directory)
	}
	return nil
}
