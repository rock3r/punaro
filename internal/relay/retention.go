package relay

import (
	"fmt"
	"time"
)

const (
	// RetentionAgeMinSeconds is the smallest accepted pending-delivery max age.
	RetentionAgeMinSeconds = 1
	// RetentionAgeMaxSeconds is the largest accepted pending or terminal age (365 days).
	RetentionAgeMaxSeconds = 365 * 24 * 60 * 60
	// RetentionBatchMin is the smallest accepted maintenance page.
	RetentionBatchMin = 1
	// RetentionBatchMax is the largest accepted maintenance page.
	RetentionBatchMax = 1000
	// TerminalListLimitMin is the smallest operator terminal page.
	TerminalListLimitMin = 1
	// TerminalListLimitMax is the largest operator terminal page.
	TerminalListLimitMax = 100

	// ClosedAcked records a successful local mailbox acknowledgement.
	ClosedAcked = "acked"
	// ClosedExpired records pending-age dead-lettering.
	ClosedExpired = "expired"
	// ClosedRevoked records membership-revocation retirement.
	ClosedRevoked = "revoked"
)

// RetentionConfig is the startup-validated pending-age and terminal-retention policy.
type RetentionConfig struct {
	PendingMaxAgeSeconds     int
	TerminalRetentionSeconds int
	MaintenanceBatch         int
}

// DefaultRetentionConfig expires work after seven days and retains terminal
// metadata for thirty days. Ordinary contract tests stay inside the window.
func DefaultRetentionConfig() RetentionConfig {
	return RetentionConfig{
		PendingMaxAgeSeconds:     7 * 24 * 60 * 60,
		TerminalRetentionSeconds: 30 * 24 * 60 * 60,
		MaintenanceBatch:         100,
	}
}

// Validate reports whether every bound is an explicit integer in range.
func (c RetentionConfig) Validate() error {
	if err := boundedRateInt("pending max age seconds", c.PendingMaxAgeSeconds, RetentionAgeMinSeconds, RetentionAgeMaxSeconds); err != nil {
		return err
	}
	if err := boundedRateInt("terminal retention seconds", c.TerminalRetentionSeconds, RetentionAgeMinSeconds, RetentionAgeMaxSeconds); err != nil {
		return err
	}
	if err := boundedRateInt("delivery maintenance batch", c.MaintenanceBatch, RetentionBatchMin, RetentionBatchMax); err != nil {
		return err
	}
	return nil
}

// MaintenanceResult is one bounded expire-and-prune page.
type MaintenanceResult struct {
	Expired int
	Pruned  int
	Scanned int
}

// TerminalRecord is host-local, content-free closed-delivery metadata.
type TerminalRecord struct {
	DeliveryID      string    `json:"delivery_id"`
	MessageID       string    `json:"message_id"`
	ConversationID  string    `json:"conversation_id"`
	RecipientID     string    `json:"recipient_id"`
	Sequence        int64     `json:"sequence"`
	ClosedReason    string    `json:"closed_reason"`
	LeaseGeneration int64     `json:"lease_generation"`
	CreatedAt       time.Time `json:"created_at"`
	ClosedAt        time.Time `json:"closed_at"`
}

// TerminalPage is one bounded operator inspection page.
type TerminalPage struct {
	Terminals  []TerminalRecord `json:"terminals"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

func validClosedReason(reason string) bool {
	return reason == ClosedAcked || reason == ClosedExpired || reason == ClosedRevoked
}

func boundedListLimit(limit int) (int, error) {
	if limit < TerminalListLimitMin || limit > TerminalListLimitMax {
		return 0, fmt.Errorf("relay terminal page limit must be an integer between %d and %d", TerminalListLimitMin, TerminalListLimitMax)
	}
	return limit, nil
}
