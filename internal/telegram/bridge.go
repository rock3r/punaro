package telegram

import (
	"context"
	"errors"
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

// GatewayCyclePhase is a closed local failure boundary used only for retry
// classification. It contains no delivery or provider data.
type GatewayCyclePhase string

// Supported gateway cycle phases.
const (
	GatewayPhaseAdvertise GatewayCyclePhase = "advertise"
	GatewayPhaseClaim     GatewayCyclePhase = "claim"
	GatewayPhasePoll      GatewayCyclePhase = "poll"
	GatewayPhaseInbound   GatewayCyclePhase = "inbound"
	GatewayPhaseLease     GatewayCyclePhase = "lease"
	GatewayPhaseSend      GatewayCyclePhase = "send"
	GatewayPhaseAck       GatewayCyclePhase = "ack"
)

// GatewayCycleError preserves only the local phase while retaining the
// wrapped typed error for content-free terminal/transient classification.
type GatewayCycleError struct {
	Phase GatewayCyclePhase
	Err   error
}

func (e *GatewayCycleError) Error() string { return "telegram gateway cycle failed" }
func (e *GatewayCycleError) Unwrap() error { return e.Err }

// ClassifyGatewayCycleFailure maps typed local failures to the durable doctor
// ledger without inspecting arbitrary error strings.
func ClassifyGatewayCycleFailure(err error) GatewayFailureClass {
	if DeletedTopicFailure(err) {
		return GatewayFailureDeletedTopic
	}
	var status BotAPIStatusError
	if errors.As(err, &status) && status.Method == "getUpdates" && PermanentBotAPIFailure(err) {
		return GatewayFailureMessageLessPoll
	}
	if PermanentBotAPIFailure(err) {
		return GatewayFailureOutboundTelegramPermanent
	}
	var permanentRelay interface{ PermanentRelayFailure() bool }
	if errors.As(err, &permanentRelay) && permanentRelay.PermanentRelayFailure() {
		return GatewayFailureInboundRelayPermanent
	}
	return GatewayFailureTransient
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
		return offset, &GatewayCycleError{Phase: GatewayPhaseAdvertise, Err: err}
	}
	if b.Claims != nil {
		if err := b.Claims.ResumeAll(ctx); err != nil {
			return offset, &GatewayCycleError{Phase: GatewayPhaseClaim, Err: err}
		}
		if err := b.Claims.StartPending(ctx); err != nil {
			return offset, &GatewayCycleError{Phase: GatewayPhaseClaim, Err: err}
		}
	}
	next, err := (Runner{Poller: b.Poller, Gateway: b.Gateway}).RunOnce(ctx, offset)
	if err != nil {
		phase := GatewayPhaseInbound
		var status BotAPIStatusError
		if errors.As(err, &status) && status.Method == "getUpdates" {
			phase = GatewayPhasePoll
		}
		return offset, &GatewayCycleError{Phase: phase, Err: err}
	}
	deliveries, err := b.Relay.Lease(ctx, b.Endpoint)
	if err != nil {
		return next, &GatewayCycleError{Phase: GatewayPhaseLease, Err: err}
	}
	for _, delivery := range deliveries {
		if err := SendDelivery(ctx, b.State, b.Sender, delivery, b.Gateway.AllowedUserID); err != nil {
			b.logEvent("telegram_send_err", "delivery_id="+delivery.ID)
			return next, &GatewayCycleError{Phase: GatewayPhaseSend, Err: err}
		}
		b.logEvent("telegram_send_ok", "delivery_id="+delivery.ID)
		if err := b.Relay.Ack(ctx, delivery); err != nil {
			return next, &GatewayCycleError{Phase: GatewayPhaseAck, Err: err}
		}
	}
	return next, nil
}

func (b Bridge) logEvent(class string, fields ...string) {
	logClaim(b.Log, class, fields...)
}
