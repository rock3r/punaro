// Package canopi maintains normalized agent state and renders the panel view.
package canopi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
)

const maxRememberedEventIDs = 50_000

// Config controls lifecycle expiry and completed-agent retention.
type Config struct {
	WorkingTTL    time.Duration
	DoneRetention time.Duration
}

// DefaultConfig returns the production MVP retention settings.
func DefaultConfig() Config {
	return Config{WorkingTTL: 30 * time.Minute, DoneRetention: 2 * time.Hour}
}

func (c Config) validate() error {
	if c.WorkingTTL <= 0 {
		return errors.New("working TTL must be positive")
	}
	if c.DoneRetention <= 0 {
		return errors.New("done retention must be positive")
	}
	return nil
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
	path      string
	records   map[string]protocol.Event
	seen      map[string]struct{}
	seenOrder []string
	revision  uint64
}

type persistedStore struct {
	Revision  uint64           `json:"revision"`
	Records   []protocol.Event `json:"records"`
	SeenOrder []string         `json:"seen_event_ids"`
}

// NewStore constructs an in-memory store with validated configuration.
func NewStore(config Config) *Store {
	if err := config.validate(); err != nil {
		panic(err)
	}
	return &Store{
		config:  config,
		records: make(map[string]protocol.Event),
		seen:    make(map[string]struct{}),
	}
}

// OpenStore opens or creates an atomically persisted state store.
func OpenStore(path string, config Config) (*Store, error) {
	if path == "" {
		return nil, errors.New("state path is required")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	store := NewStore(config)
	store.path = path
	payload, err := os.ReadFile(path) // #nosec G304 -- the operator explicitly selects this private state file.
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Canopi state: %w", err)
	}
	var persisted persistedStore
	if err := json.Unmarshal(payload, &persisted); err != nil {
		return nil, fmt.Errorf("decode Canopi state: %w", err)
	}
	if len(persisted.SeenOrder) > maxRememberedEventIDs {
		return nil, errors.New("persisted Canopi dedupe set exceeds limit")
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
	return store, nil
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
	s.rememberLocked(event.EventID)
	existing, exists := s.records[event.Key()]
	if exists && (event.ActivityAt.Before(existing.ActivityAt) ||
		(event.ActivityAt.Equal(existing.ActivityAt) && event.EventID <= existing.EventID)) {
		if err := s.persistLocked(); err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{Stale: true}, nil
	}
	s.records[event.Key()] = event
	s.revision++
	if err := s.persistLocked(); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Applied: true}, nil
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
	for key, event := range s.records {
		age := now.Sub(event.ActivityAt)
		expired := event.State == protocol.StateDone && age > s.config.DoneRetention
		if event.State != protocol.StateDone && age > s.config.WorkingTTL {
			expired = true
		}
		if expired {
			delete(s.records, key)
			changed = true
			continue
		}
		agents = append(agents, event)
	}
	if changed {
		s.revision++
		_ = s.persistLocked()
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

func (s *Store) rememberLocked(eventID string) {
	if len(s.seenOrder) == maxRememberedEventIDs {
		oldest := s.seenOrder[0]
		delete(s.seen, oldest)
		copy(s.seenOrder, s.seenOrder[1:])
		s.seenOrder = s.seenOrder[:len(s.seenOrder)-1]
	}
	s.seen[eventID] = struct{}{}
	s.seenOrder = append(s.seenOrder, eventID)
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create Canopi state directory: %w", err)
	}
	records := make([]protocol.Event, 0, len(s.records))
	for _, event := range s.records {
		records = append(records, event)
	}
	SortEvents(records)
	payload, err := json.Marshal(persistedStore{Revision: s.revision, Records: records, SeenOrder: s.seenOrder})
	if err != nil {
		return fmt.Errorf("encode Canopi state: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".canopi-state-*")
	if err != nil {
		return fmt.Errorf("create Canopi state file: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
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
	if err := os.Rename(temporaryName, s.path); err != nil {
		return fmt.Errorf("replace Canopi state: %w", err)
	}
	return nil
}
