package relay

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

const (
	rateScopeSenderMachine = "sender_machine"
	rateScopeConversation  = "conversation"
	millitokensPerToken    = int64(1000)

	defaultSenderRateBurst                 = 60
	defaultSenderRateRefillPerMinute       = 60
	defaultConversationRateBurst           = 120
	defaultConversationRateRefillPerMinute = 120
	defaultRateRetryAfterMaxSeconds        = 60

	minRateBurst             = 1
	maxRateBurst             = 10000
	minRateRefillPerMinute   = 1
	maxRateRefillPerMinute   = 10000
	minRateRetryAfterSeconds = 1
	maxRateRetryAfterSeconds = 3600
)

// ErrRateLimited is a retryable, content-free refusal when a durable sender
// or conversation token bucket has no remaining capacity.
var ErrRateLimited = errors.New("relay rate limit exceeded")

// RateLimitedError carries the bounded Retry-After interval for one refusal.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string { return ErrRateLimited.Error() }

func (e *RateLimitedError) Unwrap() error { return ErrRateLimited }

// RetryAfterSeconds is the bounded integer Retry-After value advertised to clients.
func (e *RateLimitedError) RetryAfterSeconds() int {
	if e == nil {
		return minRateRetryAfterSeconds
	}
	seconds := int((e.RetryAfter + time.Second - 1) / time.Second)
	if seconds < minRateRetryAfterSeconds {
		return minRateRetryAfterSeconds
	}
	if seconds > maxRateRetryAfterSeconds {
		return maxRateRetryAfterSeconds
	}
	return seconds
}

// RateLimitPolicy is the startup-validated token-bucket configuration for
// authenticated sender machines and conversations.
type RateLimitPolicy struct {
	SenderBurst                 int
	SenderRefillPerMinute       int
	ConversationBurst           int
	ConversationRefillPerMinute int
	MaxRetryAfterSeconds        int
}

// DefaultRateLimitPolicy returns the conservative production defaults.
func DefaultRateLimitPolicy() RateLimitPolicy {
	return RateLimitPolicy{
		SenderBurst:                 defaultSenderRateBurst,
		SenderRefillPerMinute:       defaultSenderRateRefillPerMinute,
		ConversationBurst:           defaultConversationRateBurst,
		ConversationRefillPerMinute: defaultConversationRateRefillPerMinute,
		MaxRetryAfterSeconds:        defaultRateRetryAfterMaxSeconds,
	}
}

// Validate reports whether every bound is an explicit integer inside the hard
// min/max window. Zero values are not defaults here; callers that want the
// production defaults must use DefaultRateLimitPolicy.
func (p RateLimitPolicy) Validate() error {
	if err := validateRateBound("sender burst", p.SenderBurst, minRateBurst, maxRateBurst); err != nil {
		return err
	}
	if err := validateRateBound("sender refill per minute", p.SenderRefillPerMinute, minRateRefillPerMinute, maxRateRefillPerMinute); err != nil {
		return err
	}
	if err := validateRateBound("conversation burst", p.ConversationBurst, minRateBurst, maxRateBurst); err != nil {
		return err
	}
	if err := validateRateBound("conversation refill per minute", p.ConversationRefillPerMinute, minRateRefillPerMinute, maxRateRefillPerMinute); err != nil {
		return err
	}
	return validateRateBound("rate retry-after max seconds", p.MaxRetryAfterSeconds, minRateRetryAfterSeconds, maxRateRetryAfterSeconds)
}

func validateRateBound(name string, value, min, max int) error {
	if value < min || value > max {
		return fmt.Errorf("relay %s must be between %d and %d", name, min, max)
	}
	return nil
}

// RateLimitConfigurer is the narrow store boundary for durable limiter policy.
// HTTP adapters must not keep an in-memory-only bucket map.
type RateLimitConfigurer interface {
	SetRateLimitPolicy(RateLimitPolicy) error
}

// Metrics holds bounded-cardinality relay counters. Values are never labeled
// with endpoints, roles, conversations, bodies, or credentials.
type Metrics struct {
	rateRejections atomic.Int64
}

// AddRateRejection records one content-free rate-limit refusal.
func (m *Metrics) AddRateRejection() {
	if m == nil {
		return
	}
	m.rateRejections.Add(1)
}

// RateRejections returns the number of rate-limit refusals observed.
func (m *Metrics) RateRejections() int64 {
	if m == nil {
		return 0
	}
	return m.rateRejections.Load()
}

type rateBucketSnapshot struct {
	TokensMilli         int64
	LastRefillUnixMilli int64
}

func refillRateBucket(snapshot rateBucketSnapshot, now time.Time, burst, refillPerMinute int) rateBucketSnapshot {
	nowMilli := now.UTC().UnixMilli()
	maxTokens := int64(burst) * millitokensPerToken
	if snapshot.LastRefillUnixMilli == 0 && snapshot.TokensMilli == 0 {
		return rateBucketSnapshot{TokensMilli: maxTokens, LastRefillUnixMilli: nowMilli}
	}
	last := snapshot.LastRefillUnixMilli
	if last <= 0 || last > nowMilli {
		last = nowMilli
	}
	elapsed := nowMilli - last
	tokens := snapshot.TokensMilli + elapsed*int64(refillPerMinute)/60
	if tokens > maxTokens {
		tokens = maxTokens
	}
	if tokens < 0 {
		tokens = 0
	}
	return rateBucketSnapshot{TokensMilli: tokens, LastRefillUnixMilli: nowMilli}
}

func consumeRefilledBucket(snapshot rateBucketSnapshot, burst, refillPerMinute, maxRetryAfterSeconds int) (rateBucketSnapshot, time.Duration, bool) {
	if snapshot.TokensMilli >= millitokensPerToken {
		snapshot.TokensMilli -= millitokensPerToken
		return snapshot, 0, true
	}
	need := millitokensPerToken - snapshot.TokensMilli
	if need < 1 {
		need = 1
	}
	waitMs := (need*60 + int64(refillPerMinute) - 1) / int64(refillPerMinute)
	seconds := (waitMs + 999) / 1000
	if seconds < int64(minRateRetryAfterSeconds) {
		seconds = minRateRetryAfterSeconds
	}
	if maxRetryAfterSeconds > 0 && seconds > int64(maxRetryAfterSeconds) {
		seconds = int64(maxRetryAfterSeconds)
	}
	return snapshot, time.Duration(seconds) * time.Second, false
}

func newRateLimitedError(retryAfter time.Duration, maxRetryAfterSeconds int) error {
	seconds := int((retryAfter + time.Second - 1) / time.Second)
	if seconds < minRateRetryAfterSeconds {
		seconds = minRateRetryAfterSeconds
	}
	if maxRetryAfterSeconds > 0 && seconds > maxRetryAfterSeconds {
		seconds = maxRetryAfterSeconds
	}
	return &RateLimitedError{RetryAfter: time.Duration(seconds) * time.Second}
}

// ApplyRateBucket refills one durable token bucket from server time and tries
// to consume a single token. Stores must persist the returned snapshot only
// when ok is true and the surrounding append transaction commits.
func ApplyRateBucket(tokensMilli, lastRefillUnixMilli int64, now time.Time, burst, refillPerMinute, maxRetryAfterSeconds int) (int64, int64, time.Duration, bool) {
	snapshot := refillRateBucket(rateBucketSnapshot{TokensMilli: tokensMilli, LastRefillUnixMilli: lastRefillUnixMilli}, now, burst, refillPerMinute)
	consumed, retryAfter, ok := consumeRefilledBucket(snapshot, burst, refillPerMinute, maxRetryAfterSeconds)
	return consumed.TokensMilli, consumed.LastRefillUnixMilli, retryAfter, ok
}

func initialRateBucketTokens(burst int) int64 {
	return int64(burst) * millitokensPerToken
}
