package relay

import (
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"time"
)

const (
	// RateLimitBurstMin is the smallest accepted token-bucket capacity.
	RateLimitBurstMin = 1
	// RateLimitBurstMax is the largest accepted token-bucket capacity.
	RateLimitBurstMax = 10000
	// RateLimitRefillMin is the smallest accepted refill in tokens per minute.
	RateLimitRefillMin = 1
	// RateLimitRefillMax is the largest accepted refill in tokens per minute.
	RateLimitRefillMax = 10000
	// RateLimitRetryAfterMin is the smallest Retry-After advertised on 429.
	RateLimitRetryAfterMin = 1
	// RateLimitRetryAfterMaxBound is the largest configurable Retry-After cap.
	RateLimitRetryAfterMaxBound = 3600

	rateBucketSender       = "sender"
	rateBucketConversation = "conversation"
)

// ErrRateLimited is the stable, content-free rate-limit refusal. HTTP maps it
// to 429 without disclosing conversation, endpoint, or body data.
var ErrRateLimited = errors.New("relay rate limited")

// RateLimitedError carries the bounded integer Retry-After for one refusal.
type RateLimitedError struct {
	RetryAfterSeconds int
}

func (e *RateLimitedError) Error() string { return ErrRateLimited.Error() }

func (e *RateLimitedError) Unwrap() error { return ErrRateLimited }

// RateLimitConfig is the startup-validated token-bucket policy. Burst is the
// maximum tokens stored; refill is sustained tokens per minute.
type RateLimitConfig struct {
	SenderBurst                 int
	SenderRefillPerMinute       int
	ConversationBurst           int
	ConversationRefillPerMinute int
	RetryAfterMaxSeconds        int
}

// DefaultRateLimitConfig is the conservative installation default. Existing
// contract tests stay inside these bursts at a frozen clock.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		SenderBurst:                 60,
		SenderRefillPerMinute:       60,
		ConversationBurst:           120,
		ConversationRefillPerMinute: 120,
		RetryAfterMaxSeconds:        60,
	}
}

// Validate reports whether every bound is an explicit integer in range.
func (c RateLimitConfig) Validate() error {
	if err := boundedRateInt("sender burst", c.SenderBurst, RateLimitBurstMin, RateLimitBurstMax); err != nil {
		return err
	}
	if err := boundedRateInt("sender refill per minute", c.SenderRefillPerMinute, RateLimitRefillMin, RateLimitRefillMax); err != nil {
		return err
	}
	if err := boundedRateInt("conversation burst", c.ConversationBurst, RateLimitBurstMin, RateLimitBurstMax); err != nil {
		return err
	}
	if err := boundedRateInt("conversation refill per minute", c.ConversationRefillPerMinute, RateLimitRefillMin, RateLimitRefillMax); err != nil {
		return err
	}
	if err := boundedRateInt("retry-after max seconds", c.RetryAfterMaxSeconds, RateLimitRetryAfterMin, RateLimitRetryAfterMaxBound); err != nil {
		return err
	}
	return nil
}

func boundedRateInt(name string, value, minimum, maximum int) error {
	if value < minimum || value > maximum {
		return fmt.Errorf("relay %s must be an integer between %d and %d", name, minimum, maximum)
	}
	return nil
}

// RateBucket is durable token-bucket state keyed independently of message bodies.
type RateBucket struct {
	Tokens    int64
	UpdatedAt time.Time
}

// RateLimitDecision is the atomic allow-or-retry outcome for one append.
type RateLimitDecision struct {
	Allowed           bool
	RetryAfterSeconds int
	Sender            RateBucket
	Conversation      RateBucket
}

// DecideRateLimit refills both buckets from server/database time and either
// consumes one token from each or reports the wait until the slower bucket
// has a token. Rejection does not mutate the returned buckets for persistence;
// callers persist only on allow.
func DecideRateLimit(cfg RateLimitConfig, sender, conversation RateBucket, now time.Time) RateLimitDecision {
	now = now.UTC().Truncate(time.Millisecond)
	senderRefill := refillPeriod(cfg.SenderRefillPerMinute)
	conversationRefill := refillPeriod(cfg.ConversationRefillPerMinute)
	sender = refillBucket(sender, now, int64(cfg.SenderBurst), senderRefill)
	conversation = refillBucket(conversation, now, int64(cfg.ConversationBurst), conversationRefill)
	if sender.Tokens < 1 || conversation.Tokens < 1 {
		wait := time.Duration(0)
		if sender.Tokens < 1 {
			wait = bucketWait(sender, now, senderRefill)
		}
		if conversation.Tokens < 1 {
			if convWait := bucketWait(conversation, now, conversationRefill); convWait > wait {
				wait = convWait
			}
		}
		return RateLimitDecision{RetryAfterSeconds: boundRetryAfter(wait, cfg.RetryAfterMaxSeconds), Sender: sender, Conversation: conversation}
	}
	sender.Tokens--
	conversation.Tokens--
	return RateLimitDecision{Allowed: true, Sender: sender, Conversation: conversation}
}

func refillPeriod(tokensPerMinute int) time.Duration {
	if tokensPerMinute < 1 {
		tokensPerMinute = 1
	}
	return time.Minute / time.Duration(tokensPerMinute)
}

func refillBucket(bucket RateBucket, now time.Time, burst int64, every time.Duration) RateBucket {
	if bucket.UpdatedAt.IsZero() {
		return RateBucket{Tokens: burst, UpdatedAt: now}
	}
	if now.Before(bucket.UpdatedAt) {
		if bucket.Tokens > burst {
			bucket.Tokens = burst
		}
		return bucket
	}
	elapsed := now.Sub(bucket.UpdatedAt)
	added := elapsed / every
	if added > 0 {
		bucket.Tokens += int64(added)
		bucket.UpdatedAt = bucket.UpdatedAt.Add(added * every)
	}
	if bucket.Tokens > burst {
		bucket.Tokens = burst
	}
	return bucket
}

func bucketWait(bucket RateBucket, now time.Time, every time.Duration) time.Duration {
	next := bucket.UpdatedAt.Add(every)
	wait := next.Sub(now)
	if wait < 0 {
		return 0
	}
	return wait
}

func boundRetryAfter(wait time.Duration, maxSeconds int) int {
	seconds := int(math.Ceil(wait.Seconds()))
	if seconds < RateLimitRetryAfterMin {
		seconds = RateLimitRetryAfterMin
	}
	if maxSeconds < RateLimitRetryAfterMin {
		maxSeconds = RateLimitRetryAfterMin
	}
	if seconds > maxSeconds {
		return maxSeconds
	}
	return seconds
}

// Metrics counts content-free relay pressure signals. Labels are fixed names
// only; bodies, endpoints, roles, and conversation IDs are never recorded.
type Metrics struct {
	rateLimitRejections        atomic.Uint64
	capacityRejections         atomic.Uint64
	pendingDeliveries          atomic.Uint64
	pendingBytes               atomic.Uint64
	oldestPendingAgeSeconds    atomic.Uint64
	terminalTransitionsAcked   atomic.Uint64
	terminalTransitionsExpired atomic.Uint64
	terminalTransitionsRevoked atomic.Uint64
	terminalRetained           atomic.Uint64
	leaseRedeliveries          atomic.Uint64
}

// ObserveRateLimited increments the rate-rejection counter.
func (m *Metrics) ObserveRateLimited() {
	if m == nil {
		return
	}
	m.rateLimitRejections.Add(1)
}

// MetricsSnapshot is the bounded JSON body served on the local health listener.
type MetricsSnapshot struct {
	RelayRateLimitRejections        uint64 `json:"relay_rate_limit_rejections"`
	RelayCapacityRejections         uint64 `json:"relay_capacity_rejections"`
	RelayPendingDeliveries          uint64 `json:"relay_pending_deliveries"`
	RelayPendingBytes               uint64 `json:"relay_pending_bytes"`
	RelayOldestPendingAgeSeconds    uint64 `json:"relay_oldest_pending_age_seconds"`
	RelayTerminalTransitionsAcked   uint64 `json:"relay_terminal_transitions_acked"`
	RelayTerminalTransitionsExpired uint64 `json:"relay_terminal_transitions_expired"`
	RelayTerminalTransitionsRevoked uint64 `json:"relay_terminal_transitions_revoked"`
	RelayTerminalRetained           uint64 `json:"relay_terminal_retained"`
	RelayLeaseRedeliveries          uint64 `json:"relay_lease_redeliveries"`
}

// Snapshot returns the current content-free counters.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	return MetricsSnapshot{
		RelayRateLimitRejections:        m.rateLimitRejections.Load(),
		RelayCapacityRejections:         m.capacityRejections.Load(),
		RelayPendingDeliveries:          m.pendingDeliveries.Load(),
		RelayPendingBytes:               m.pendingBytes.Load(),
		RelayOldestPendingAgeSeconds:    m.oldestPendingAgeSeconds.Load(),
		RelayTerminalTransitionsAcked:   m.terminalTransitionsAcked.Load(),
		RelayTerminalTransitionsExpired: m.terminalTransitionsExpired.Load(),
		RelayTerminalTransitionsRevoked: m.terminalTransitionsRevoked.Load(),
		RelayTerminalRetained:           m.terminalRetained.Load(),
		RelayLeaseRedeliveries:          m.leaseRedeliveries.Load(),
	}
}

// SetRateLimits replaces the in-process bucket policy. Token state remains in
// the durable store; this does not reset depletion.
func (s *Store) SetRateLimits(cfg RateLimitConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.rateMu.Lock()
	s.rateLimits = cfg
	s.rateMu.Unlock()
	return nil
}

// SetMetrics attaches the shared content-free counter sink.
func (s *Store) SetMetrics(metrics *Metrics) {
	s.metrics = metrics
	s.refreshPendingMetrics()
}

func (s *Store) rateLimitConfig() RateLimitConfig {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	if s.rateLimits == (RateLimitConfig{}) {
		return DefaultRateLimitConfig()
	}
	return s.rateLimits
}

// SetQuotaLimits replaces the in-process pending-delivery ceilings. Durable
// counters remain in the store; this does not release reserved capacity.
func (s *Store) SetQuotaLimits(cfg QuotaConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.quotaMu.Lock()
	s.quota = cfg
	s.quotaMu.Unlock()
	return nil
}

func (s *Store) quotaConfig() QuotaConfig {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	if s.quota == (QuotaConfig{}) {
		return DefaultQuotaConfig()
	}
	return s.quota
}
