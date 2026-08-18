package relay

import (
	"fmt"
	"time"
)

const (
	// ClosedReasonAcked is a successful recipient acknowledgement.
	ClosedReasonAcked = "acked"
	// ClosedReasonExpired is a policy-aged pending delivery moved to dead-letter.
	ClosedReasonExpired = "expired"
	// ClosedReasonRevoked is membership-revocation retirement of a pending delivery.
	ClosedReasonRevoked = "revoked"

	// RetentionAgeMinimum is the smallest accepted pending-max-age or terminal retention.
	RetentionAgeMinimum = time.Second
	// RetentionPendingMaxAgeMax is 90 days.
	RetentionPendingMaxAgeMax = 90 * 24 * time.Hour
	// RetentionTerminalMax is 365 days.
	RetentionTerminalMax = 365 * 24 * time.Hour
	// RetentionBatchMin is the smallest maintenance page.
	RetentionBatchMin = 1
	// RetentionBatchMax is the largest maintenance page.
	RetentionBatchMax = 1000
)

// RetentionConfig is the startup-validated pending-expiry and terminal-retention policy.
type RetentionConfig struct {
	PendingMaxAge     time.Duration
	TerminalRetention time.Duration
	MaintenanceBatch  int
}

// DefaultRetentionConfig keeps ordinary contract traffic pending at a frozen
// clock. Seven-day bounds are conservative for offline adapters and operator review.
func DefaultRetentionConfig() RetentionConfig {
	return RetentionConfig{
		PendingMaxAge:     7 * 24 * time.Hour,
		TerminalRetention: 7 * 24 * time.Hour,
		MaintenanceBatch:  100,
	}
}

// Validate reports whether every bound is an explicit value in range.
func (c RetentionConfig) Validate() error {
	if err := boundedRetentionDuration("pending max age", c.PendingMaxAge, RetentionAgeMinimum, RetentionPendingMaxAgeMax); err != nil {
		return err
	}
	if err := boundedRetentionDuration("terminal retention", c.TerminalRetention, RetentionAgeMinimum, RetentionTerminalMax); err != nil {
		return err
	}
	if err := boundedRateInt("terminal maintenance batch", c.MaintenanceBatch, RetentionBatchMin, RetentionBatchMax); err != nil {
		return err
	}
	return nil
}

func boundedRetentionDuration(name string, value, minimum, maximum time.Duration) error {
	if value < minimum || value > maximum {
		return fmt.Errorf("relay %s must be between %s and %s", name, minimum, maximum)
	}
	return nil
}

// MaintenanceResult is one content-free bounded maintenance outcome.
type MaintenanceResult struct {
	Expired int `json:"expired"`
	Pruned  int `json:"pruned"`
}

// TerminalRecord is one content-free dead-letter row. It never includes a body
// or credential.
type TerminalRecord struct {
	DeliveryID      string    `json:"delivery_id"`
	MessageID       string    `json:"message_id"`
	ConversationID  string    `json:"conversation_id"`
	RecipientID     string    `json:"recipient_id"`
	Sequence        int64     `json:"sequence"`
	ClosedReason    string    `json:"closed_reason"`
	LeaseGeneration int64     `json:"lease_generation"`
	ClosedAt        time.Time `json:"closed_at"`
}

// TerminalPage is one bounded operator inspection page.
type TerminalPage struct {
	Records    []TerminalRecord `json:"records"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

// ObserveTerminalTransition increments the unlabeled closed-reason counter.
func (m *Metrics) ObserveTerminalTransition(reason string) {
	if m == nil {
		return
	}
	switch reason {
	case ClosedReasonAcked:
		m.terminalTransitionsAcked.Add(1)
	case ClosedReasonExpired:
		m.terminalTransitionsExpired.Add(1)
	case ClosedReasonRevoked:
		m.terminalTransitionsRevoked.Add(1)
	}
}

// ObserveLeaseRedelivery increments the unlabeled lease-expiry/redelivery counter.
func (m *Metrics) ObserveLeaseRedelivery() {
	if m == nil {
		return
	}
	m.leaseRedeliveries.Add(1)
}

// SetOldestPendingAge records the unlabeled age of the oldest pending delivery.
func (m *Metrics) SetOldestPendingAge(age time.Duration) {
	if m == nil {
		return
	}
	if age < 0 {
		age = 0
	}
	m.oldestPendingAgeSeconds.Store(unsignedPending(int64(age / time.Second)))
}

// SetTerminalRetained replaces the unlabeled retained-terminal gauge.
func (m *Metrics) SetTerminalRetained(count int64) {
	if m == nil {
		return
	}
	m.terminalRetained.Store(unsignedPending(count))
}
