package relay

import (
	"errors"
	"testing"
	"time"
)

func TestRateLimitPolicyRejectsOutOfBoundsValues(t *testing.T) {
	t.Parallel()
	valid := DefaultRateLimitPolicy()
	if err := valid.Validate(); err != nil {
		t.Fatalf("default policy: %v", err)
	}
	invalid := []RateLimitPolicy{
		{SenderBurst: 0, SenderRefillPerMinute: 60, ConversationBurst: 60, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60},
		{SenderBurst: 60, SenderRefillPerMinute: 0, ConversationBurst: 60, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60},
		{SenderBurst: 60, SenderRefillPerMinute: 60, ConversationBurst: 0, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60},
		{SenderBurst: 60, SenderRefillPerMinute: 60, ConversationBurst: 60, ConversationRefillPerMinute: 0, MaxRetryAfterSeconds: 60},
		{SenderBurst: 60, SenderRefillPerMinute: 60, ConversationBurst: 60, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 0},
		{SenderBurst: maxRateBurst + 1, SenderRefillPerMinute: 60, ConversationBurst: 60, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60},
		{SenderBurst: 60, SenderRefillPerMinute: maxRateRefillPerMinute + 1, ConversationBurst: 60, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: 60},
		{SenderBurst: 60, SenderRefillPerMinute: 60, ConversationBurst: 60, ConversationRefillPerMinute: 60, MaxRetryAfterSeconds: maxRateRetryAfterSeconds + 1},
	}
	for _, policy := range invalid {
		if err := policy.Validate(); err == nil {
			t.Fatalf("invalid policy accepted: %#v", policy)
		}
	}
}

func TestTokenBucketRefillAndExactRetryAfter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 18, 12, 0, 0, 0, time.UTC)
	full := refillRateBucket(rateBucketSnapshot{}, now, 1, 30)
	consumed, retry, ok := consumeRefilledBucket(full, 1, 30, 60)
	if !ok || retry != 0 || consumed.TokensMilli != 0 {
		t.Fatalf("first consume snapshot=%#v retry=%s ok=%t", consumed, retry, ok)
	}
	empty := refillRateBucket(consumed, now, 1, 30)
	_, retry, ok = consumeRefilledBucket(empty, 1, 30, 60)
	if ok || retry != 2*time.Second {
		t.Fatalf("empty bucket retry=%s ok=%t, want 2s", retry, ok)
	}
	half := refillRateBucket(consumed, now.Add(time.Second), 1, 30)
	if half.TokensMilli != 500 {
		t.Fatalf("one-second refill millitokens=%d, want 500", half.TokensMilli)
	}
	_, retry, ok = consumeRefilledBucket(half, 1, 30, 60)
	if ok || retry != time.Second {
		t.Fatalf("half bucket retry=%s ok=%t, want 1s", retry, ok)
	}
	ready := refillRateBucket(consumed, now.Add(2*time.Second), 1, 30)
	_, retry, ok = consumeRefilledBucket(ready, 1, 30, 60)
	if !ok || retry != 0 {
		t.Fatalf("refilled consume retry=%s ok=%t", retry, ok)
	}
}

func TestTokenBucketClockRollbackDoesNotRestoreCapacity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 18, 12, 0, 0, 0, time.UTC)
	first := refillRateBucket(rateBucketSnapshot{}, now, 2, 60)
	afterFirst, _, ok := consumeRefilledBucket(first, 2, 60, 60)
	if !ok {
		t.Fatal("first consume was refused")
	}
	rolled := refillRateBucket(afterFirst, now.Add(-time.Second), 2, 60)
	if rolled.LastRefillUnixMilli != afterFirst.LastRefillUnixMilli || rolled.TokensMilli != afterFirst.TokensMilli {
		t.Fatalf("clock rollback mutated watermark rolled=%#v afterFirst=%#v", rolled, afterFirst)
	}
	afterSecond, _, ok := consumeRefilledBucket(rolled, 2, 60, 60)
	if !ok {
		t.Fatal("remaining token was refused during clock rollback")
	}
	restored := refillRateBucket(afterSecond, now, 2, 60)
	_, _, ok = consumeRefilledBucket(restored, 2, 60, 60)
	if ok {
		t.Fatal("clock correction restored a third token")
	}
}

func TestRateLimitedErrorIsRetryableAndContentFree(t *testing.T) {
	t.Parallel()
	err := newRateLimitedError(1500*time.Millisecond, 60)
	var limited *RateLimitedError
	if !errors.As(err, &limited) || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("error=%v", err)
	}
	if limited.RetryAfterSeconds() != 2 || limited.Error() != ErrRateLimited.Error() {
		t.Fatalf("limited=%#v", limited)
	}
}
