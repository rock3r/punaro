package telegram

import (
	"context"
	"fmt"
	"strings"

	"github.com/rock3r/punaro/internal/relay"
)

// BridgeRelay is the signed durable relay surface used by the Telegram
// gateway. It deliberately has no local-mailbox capability.
type BridgeRelay interface {
	Advertise(ctx context.Context, endpoints []string) error
	Lease(ctx context.Context, endpoint string) ([]relay.Delivery, error)
	Ack(ctx context.Context, delivery relay.Delivery) error
	ClaimConversation(ctx context.Context, conversationID, endpoint, idempotencyKey string) (relay.TelegramClaim, error)
	CompleteTelegramClaim(ctx context.Context, conversationID string) (relay.TelegramClaim, error)
	PendingTelegramClaims(ctx context.Context, limit int, after string) ([]relay.TelegramClaim, error)
}

// Bridge joins one enrolled gateway endpoint to the Telegram poller and rich
// sender. It attaches that endpoint before either submitting user text or
// leasing replies, so detached gateway instances cannot retain authority.
type Bridge struct {
	Relay    BridgeRelay
	Endpoint string
	State    *State
	Poller   Poller
	Gateway  Gateway
	Sender   RichSender
	Claims   *ClaimExecutor
	Log      func(string, ...any)
}

// SyncOnce renews gateway attachment, resumes incomplete claims, processes one
// inbound Telegram page, then sends and acknowledges its durable outbound
// deliveries. Claim recovery runs before polling so a routed-but-incomplete
// claim cannot reject inbound and skip ResumeAll. A send failure intentionally
// leaves the delivery unacknowledged for at-least-once retry.
func (b Bridge) SyncOnce(ctx context.Context, offset int64) (int64, error) {
	if b.Relay == nil || b.State == nil || b.Poller == nil || b.Sender == nil || strings.TrimSpace(b.Endpoint) == "" {
		return offset, fmt.Errorf("telegram bridge is not configured")
	}
	if err := b.Relay.Advertise(ctx, []string{b.Endpoint}); err != nil {
		return offset, fmt.Errorf("advertise telegram gateway endpoint: %w", err)
	}
	if b.Claims != nil {
		if err := b.Claims.ResumeAll(ctx); err != nil {
			return offset, err
		}
		if err := b.Claims.StartPending(ctx); err != nil {
			return offset, err
		}
	}
	next, err := (Runner{Poller: b.Poller, Gateway: b.Gateway}).RunOnce(ctx, offset)
	if err != nil {
		return offset, err
	}
	deliveries, err := b.Relay.Lease(ctx, b.Endpoint)
	if err != nil {
		return next, fmt.Errorf("lease Telegram gateway deliveries: %w", err)
	}
	for _, delivery := range deliveries {
		if err := SendDelivery(ctx, b.State, b.Sender, delivery); err != nil {
			b.logEvent("telegram_send_err", "delivery_id="+delivery.ID)
			return next, fmt.Errorf("send Telegram delivery %q: %w", delivery.ID, err)
		}
		b.logEvent("telegram_send_ok", "delivery_id="+delivery.ID)
		if err := b.Relay.Ack(ctx, delivery); err != nil {
			return next, fmt.Errorf("acknowledge Telegram delivery %q: %w", delivery.ID, err)
		}
	}
	return next, nil
}

func (b Bridge) logEvent(class string, fields ...string) {
	logClaim(b.Log, class, fields...)
}
