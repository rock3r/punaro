package relay

import (
	"errors"
	"fmt"
)

const (
	// PendingCountMin is the smallest accepted pending-delivery count ceiling.
	PendingCountMin = 1
	// PendingCountMax is the largest accepted pending-delivery count ceiling.
	PendingCountMax = 10_000_000
	// PendingBytesMin is the smallest accepted pending-body ceiling.
	PendingBytesMin = 1
	// PendingBytesMax is the largest accepted pending-body ceiling.
	PendingBytesMax = 1 << 30
	// CapacityRetryAfterMin is the smallest Retry-After advertised on capacity 429.
	CapacityRetryAfterMin = RateLimitRetryAfterMin
	// CapacityRetryAfterMaxBound is the largest configurable capacity Retry-After.
	CapacityRetryAfterMaxBound = RateLimitRetryAfterMaxBound

	pendingScopeInstallation = "installation"
	pendingScopeRecipient    = "recipient"
	pendingInstallationKey   = ""
)

// ErrAtCapacity is the stable, content-free pending-capacity refusal. HTTP maps
// it to 429 without disclosing conversation, endpoint, or body data.
var ErrAtCapacity = errors.New("relay at capacity")

// CapacityError carries the bounded integer Retry-After for one refusal.
type CapacityError struct {
	RetryAfterSeconds int
}

func (e *CapacityError) Error() string { return ErrAtCapacity.Error() }

func (e *CapacityError) Unwrap() error { return ErrAtCapacity }

// PendingCapacityConfig is the startup-validated pending-delivery ceiling.
type PendingCapacityConfig struct {
	RecipientCount    int
	RecipientBytes    int
	InstallationCount int
	InstallationBytes int
	RetryAfterSeconds int
}

// DefaultPendingCapacityConfig is the conservative installation default.
// Existing contract tests stay inside these ceilings.
func DefaultPendingCapacityConfig() PendingCapacityConfig {
	return PendingCapacityConfig{
		RecipientCount:    10000,
		RecipientBytes:    32 << 20,
		InstallationCount: 100000,
		InstallationBytes: 256 << 20,
		RetryAfterSeconds: 60,
	}
}

// Validate reports whether every bound is an explicit integer in range.
func (c PendingCapacityConfig) Validate() error {
	if err := boundedCapacityInt("pending recipient count", c.RecipientCount, PendingCountMin, PendingCountMax); err != nil {
		return err
	}
	if err := boundedCapacityInt("pending recipient bytes", c.RecipientBytes, PendingBytesMin, PendingBytesMax); err != nil {
		return err
	}
	if err := boundedCapacityInt("pending installation count", c.InstallationCount, PendingCountMin, PendingCountMax); err != nil {
		return err
	}
	if err := boundedCapacityInt("pending installation bytes", c.InstallationBytes, PendingBytesMin, PendingBytesMax); err != nil {
		return err
	}
	if err := boundedCapacityInt("capacity retry-after seconds", c.RetryAfterSeconds, CapacityRetryAfterMin, CapacityRetryAfterMaxBound); err != nil {
		return err
	}
	return nil
}

func boundedCapacityInt(name string, value, minimum, maximum int) error {
	if value < minimum || value > maximum {
		return fmt.Errorf("relay %s must be an integer between %d and %d", name, minimum, maximum)
	}
	return nil
}

// PendingCharge is one recipient's reserved pending count and body bytes.
type PendingCharge struct {
	Recipient string
	Count     int64
	Bytes     int64
}

// CapacityDecision is the atomic allow-or-retry outcome for one reservation.
type CapacityDecision struct {
	Allowed           bool
	RetryAfterSeconds int
}

// DecidePendingCapacity reports whether adding charges stays within every
// recipient and installation ceiling. Rejection does not inspect bodies.
func DecidePendingCapacity(cfg PendingCapacityConfig, installationCount, installationBytes int64, current map[string]struct{ Count, Bytes int64 }, charges []PendingCharge) CapacityDecision {
	retryAfter := cfg.RetryAfterSeconds
	if retryAfter < CapacityRetryAfterMin {
		retryAfter = CapacityRetryAfterMin
	}
	if retryAfter > CapacityRetryAfterMaxBound {
		retryAfter = CapacityRetryAfterMaxBound
	}
	var addCount, addBytes int64
	for _, charge := range charges {
		if charge.Count < 0 || charge.Bytes < 0 {
			return CapacityDecision{RetryAfterSeconds: retryAfter}
		}
		addCount += charge.Count
		addBytes += charge.Bytes
		existing := current[charge.Recipient]
		if existing.Count+charge.Count > int64(cfg.RecipientCount) || existing.Bytes+charge.Bytes > int64(cfg.RecipientBytes) {
			return CapacityDecision{RetryAfterSeconds: retryAfter}
		}
	}
	if installationCount+addCount > int64(cfg.InstallationCount) || installationBytes+addBytes > int64(cfg.InstallationBytes) {
		return CapacityDecision{RetryAfterSeconds: retryAfter}
	}
	return CapacityDecision{Allowed: true, RetryAfterSeconds: retryAfter}
}

// ObserveCapacityRejected increments the capacity-rejection counter.
func (m *Metrics) ObserveCapacityRejected() {
	if m == nil {
		return
	}
	m.capacityRejections.Add(1)
}

// SetPendingGauges records the current installation pending totals.
func (m *Metrics) SetPendingGauges(count, bytes int64) {
	if m == nil {
		return
	}
	m.pendingDeliveries.Store(count)
	m.pendingBytes.Store(bytes)
}

// SetPendingCapacity replaces the in-process pending-delivery ceilings.
// Durable counters remain in the store; this does not reset occupancy.
func (s *Store) SetPendingCapacity(cfg PendingCapacityConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.capacityMu.Lock()
	s.capacity = cfg
	s.capacityMu.Unlock()
	return nil
}

func (s *Store) pendingCapacityConfig() PendingCapacityConfig {
	s.capacityMu.Lock()
	defer s.capacityMu.Unlock()
	if s.capacity == (PendingCapacityConfig{}) {
		return DefaultPendingCapacityConfig()
	}
	return s.capacity
}
