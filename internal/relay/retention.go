package relay

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

const (
	// RetentionAgeMinSeconds is the smallest accepted pending-delivery max age.
	RetentionAgeMinSeconds = 1
	// RetentionAgeMaxSeconds is the largest accepted pending-delivery max age (365 days).
	RetentionAgeMaxSeconds = 365 * 24 * 60 * 60
	// RetentionKeepMinSeconds is the smallest accepted terminal retention window.
	RetentionKeepMinSeconds = 1
	// RetentionKeepMaxSeconds is the largest accepted terminal retention window (365 days).
	RetentionKeepMaxSeconds = 365 * 24 * 60 * 60
	// RetentionBatchMin is the smallest accepted maintenance page size.
	RetentionBatchMin = 1
	// RetentionBatchMax is the largest accepted maintenance page size.
	RetentionBatchMax = 1000
	// DefaultTerminalListLimit is the page size when a list request omits limit.
	DefaultTerminalListLimit = 50
	// MaxTerminalListLimit is the inclusive upper bound for one terminal page.
	MaxTerminalListLimit = 100

	// ClosedReasonAcked records a successful local-mailbox acknowledgement.
	ClosedReasonAcked = "acked"
	// ClosedReasonExpired records a pending-delivery age expiry.
	ClosedReasonExpired = "expired"
	// ClosedReasonRevoked records membership-revocation retirement.
	ClosedReasonRevoked = "revoked"
)

// RetentionConfig is the startup-validated pending-age and terminal-retention policy.
type RetentionConfig struct {
	PendingMaxAgeSeconds     int
	TerminalRetentionSeconds int
	MaintenanceBatch         int
}

// DefaultRetentionConfig is conservative: seven days pending, thirty days of
// content-free terminal metadata, and 100-row maintenance pages.
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
	if err := boundedRateInt("terminal retention seconds", c.TerminalRetentionSeconds, RetentionKeepMinSeconds, RetentionKeepMaxSeconds); err != nil {
		return err
	}
	return boundedRateInt("delivery maintenance batch", c.MaintenanceBatch, RetentionBatchMin, RetentionBatchMax)
}

// PendingMaxAge is the inclusive pending-delivery lifetime.
func (c RetentionConfig) PendingMaxAge() time.Duration {
	return time.Duration(c.PendingMaxAgeSeconds) * time.Second
}

// TerminalRetention is how long closed metadata remains inspectable.
func (c RetentionConfig) TerminalRetention() time.Duration {
	return time.Duration(c.TerminalRetentionSeconds) * time.Second
}

// DeliveryTerminal is one content-free closed-delivery record. It never
// includes message bodies, credentials, or endpoint display names.
type DeliveryTerminal struct {
	DeliveryID      string    `json:"delivery_id"`
	MessageID       string    `json:"message_id"`
	ConversationID  string    `json:"conversation_id"`
	RecipientID     string    `json:"recipient_id"`
	Sequence        int64     `json:"sequence"`
	ClosedReason    string    `json:"closed_reason"`
	LeaseGeneration int64     `json:"lease_generation"`
	ClosedAt        time.Time `json:"closed_at"`
	CreatedAt       time.Time `json:"created_at"`
}

// TerminalListInput is one host-local, bounded inventory page request.
type TerminalListInput struct {
	Cursor string
	Limit  int
}

// TerminalListPage is one cursor-stable page of retained terminal metadata.
type TerminalListPage struct {
	Terminals  []DeliveryTerminal `json:"terminals"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

// MaintenanceResult reports one bounded expire-then-prune page.
type MaintenanceResult struct {
	Expired      int  `json:"expired"`
	Pruned       int  `json:"pruned"`
	Continuation bool `json:"continuation"`
}

// EncodeTerminalListCursor hides the last closed timestamp and delivery ID.
func EncodeTerminalListCursor(closedAt time.Time, deliveryID string) string {
	if deliveryID == "" || closedAt.IsZero() {
		return ""
	}
	raw := fmt.Sprintf("%d\x1e%s", closedAt.UTC().Truncate(time.Microsecond).UnixMicro(), deliveryID)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeTerminalListCursor reports the last closed timestamp and delivery ID.
func DecodeTerminalListCursor(cursor string) (time.Time, string, bool) {
	if cursor == "" {
		return time.Time{}, "", true
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", false
	}
	micros, deliveryID, ok := strings.Cut(string(raw), "\x1e")
	if !ok || deliveryID == "" {
		return time.Time{}, "", false
	}
	var value int64
	if _, err := fmt.Sscan(micros, &value); err != nil || value < 0 {
		return time.Time{}, "", false
	}
	return time.UnixMicro(value).UTC(), deliveryID, true
}

func (m *Metrics) observeTerminalTransition(reason string, count uint64) {
	m.ObserveTerminalTransition(reason, count)
}

// ObserveTerminalTransition increments one closed-reason counter after a durable commit.
func (m *Metrics) ObserveTerminalTransition(reason string, count uint64) {
	if m == nil || count == 0 {
		return
	}
	switch reason {
	case ClosedReasonAcked:
		m.terminalTransitionsAcked.Add(count)
	case ClosedReasonExpired:
		m.terminalTransitionsExpired.Add(count)
	case ClosedReasonRevoked:
		m.terminalTransitionsRevoked.Add(count)
	}
}

// ObserveLeaseRedelivery increments the unlabeled lease-expiry/redelivery counter.
func (m *Metrics) ObserveLeaseRedelivery() {
	if m == nil {
		return
	}
	m.leaseRedeliveries.Add(1)
}

// SetQueueAge replaces the unlabeled oldest-pending-age gauge.
func (m *Metrics) SetQueueAge(seconds uint64) {
	if m == nil {
		return
	}
	m.pendingOldestAgeSeconds.Store(seconds)
}

// SetTerminalsRetained replaces the unlabeled retained-terminal gauge.
func (m *Metrics) SetTerminalsRetained(count uint64) {
	if m == nil {
		return
	}
	m.terminalsRetained.Store(count)
}

func pendingAgeSeconds(oldest time.Time, now time.Time) uint64 {
	if oldest.IsZero() || now.Before(oldest) {
		return 0
	}
	seconds := int64(now.Sub(oldest) / time.Second)
	if seconds < 0 {
		return 0
	}
	return uint64(seconds) // #nosec G115 -- pending age is CHECK-constrained to non-negative durations.
}
