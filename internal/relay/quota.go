package relay

import (
	"errors"
	"fmt"
)

const (
	// QuotaCountMin is the smallest accepted pending-delivery row ceiling.
	QuotaCountMin = 1
	// QuotaCountMax is the largest accepted pending-delivery row ceiling.
	QuotaCountMax = 10_000_000
	// QuotaBytesMin is the smallest accepted pending-body-byte ceiling.
	QuotaBytesMin = 1
	// QuotaBytesMax is the largest accepted pending-body-byte ceiling (64 GiB).
	QuotaBytesMax = 64 << 30
)

// ErrCapacityExceeded is the stable, content-free pending-capacity refusal.
// HTTP maps it to 429 without disclosing recipients, conversations, or bodies.
var ErrCapacityExceeded = errors.New("relay capacity exceeded")

// CapacityError carries the bounded integer Retry-After for one capacity refusal.
type CapacityError struct {
	RetryAfterSeconds int
}

func (e *CapacityError) Error() string { return ErrCapacityExceeded.Error() }

func (e *CapacityError) Unwrap() error { return ErrCapacityExceeded }

// QuotaConfig is the startup-validated pending-delivery ceiling policy.
type QuotaConfig struct {
	RecipientCount    int
	RecipientBytes    int64
	InstallationCount int
	InstallationBytes int64
	RetryAfterSeconds int
}

// DefaultQuotaConfig leaves ordinary contract traffic inside the ceilings at a
// frozen clock. Operators tighten these for a specific installation.
func DefaultQuotaConfig() QuotaConfig {
	return QuotaConfig{
		RecipientCount:    10_000,
		RecipientBytes:    32 << 20,
		InstallationCount: 100_000,
		InstallationBytes: 256 << 20,
		RetryAfterSeconds: 60,
	}
}

// Validate reports whether every bound is an explicit integer in range.
func (c QuotaConfig) Validate() error {
	if err := boundedRateInt("pending recipient count", c.RecipientCount, QuotaCountMin, QuotaCountMax); err != nil {
		return err
	}
	if err := boundedQuotaInt64("pending recipient bytes", c.RecipientBytes, QuotaBytesMin, QuotaBytesMax); err != nil {
		return err
	}
	if err := boundedRateInt("pending installation count", c.InstallationCount, QuotaCountMin, QuotaCountMax); err != nil {
		return err
	}
	if err := boundedQuotaInt64("pending installation bytes", c.InstallationBytes, QuotaBytesMin, QuotaBytesMax); err != nil {
		return err
	}
	if err := boundedRateInt("pending retry-after seconds", c.RetryAfterSeconds, RateLimitRetryAfterMin, RateLimitRetryAfterMaxBound); err != nil {
		return err
	}
	return nil
}

func boundedQuotaInt64(name string, value, minimum, maximum int64) error {
	if value < minimum || value > maximum {
		return fmt.Errorf("relay %s must be an integer between %d and %d", name, minimum, maximum)
	}
	return nil
}

// QuotaCounters is one explicit pending count/byte pair.
type QuotaCounters struct {
	Count int64
	Bytes int64
}

// QuotaCharge is the capacity reserved for one recipient delivery.
type QuotaCharge struct {
	Recipient string
	Bytes     int64
}

// QuotaDecision is the atomic allow-or-retry outcome for one fan-out.
type QuotaDecision struct {
	Allowed           bool
	RetryAfterSeconds int
}

// DecideQuota reports whether the complete fan-out fits every ceiling. It does
// not inspect message bodies beyond the caller-supplied byte length.
func DecideQuota(cfg QuotaConfig, recipients map[string]QuotaCounters, install QuotaCounters, charges []QuotaCharge) QuotaDecision {
	retryAfter := cfg.RetryAfterSeconds
	if retryAfter < RateLimitRetryAfterMin {
		retryAfter = RateLimitRetryAfterMin
	}
	if retryAfter > RateLimitRetryAfterMaxBound {
		retryAfter = RateLimitRetryAfterMaxBound
	}
	if len(charges) == 0 {
		return QuotaDecision{Allowed: true, RetryAfterSeconds: retryAfter}
	}
	addedCount := int64(len(charges))
	var addedBytes int64
	perRecipientCount := make(map[string]int64, len(charges))
	perRecipientBytes := make(map[string]int64, len(charges))
	for _, charge := range charges {
		if charge.Recipient == "" || charge.Bytes < 0 {
			return QuotaDecision{RetryAfterSeconds: retryAfter}
		}
		perRecipientCount[charge.Recipient]++
		perRecipientBytes[charge.Recipient] += charge.Bytes
		addedBytes += charge.Bytes
	}
	if install.Count+addedCount > int64(cfg.InstallationCount) || install.Bytes+addedBytes > cfg.InstallationBytes {
		return QuotaDecision{RetryAfterSeconds: retryAfter}
	}
	for recipient, count := range perRecipientCount {
		current := recipients[recipient]
		if current.Count+count > int64(cfg.RecipientCount) || current.Bytes+perRecipientBytes[recipient] > cfg.RecipientBytes {
			return QuotaDecision{RetryAfterSeconds: retryAfter}
		}
	}
	return QuotaDecision{Allowed: true, RetryAfterSeconds: retryAfter}
}

// ObserveCapacityExceeded increments the unlabeled capacity-rejection counter.
func (m *Metrics) ObserveCapacityExceeded() {
	if m == nil {
		return
	}
	m.capacityRejections.Add(1)
}

// SetPending replaces the unlabeled current pending gauges.
func (m *Metrics) SetPending(count, bytes int64) {
	if m == nil {
		return
	}
	m.pendingDeliveries.Store(unsignedPending(count))
	m.pendingBytes.Store(unsignedPending(bytes))
}

func unsignedPending(value int64) uint64 {
	if value < 0 {
		return 0
	}
	return uint64(value) // #nosec G115 -- pending counters are CHECK-constrained to non-negative values.
}
