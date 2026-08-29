package telegram

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/rock3r/punaro/internal/relay"
)

// ClaimRelay is the signed relay surface used to reserve, complete, and poll claims.
type ClaimRelay interface {
	ClaimConversation(ctx context.Context, conversationID, endpoint, idempotencyKey string) (relay.TelegramClaim, error)
	CompleteTelegramClaim(ctx context.Context, conversationID string) (relay.TelegramClaim, error)
	PendingTelegramClaims(ctx context.Context, limit int, after string) ([]relay.TelegramClaim, error)
}

// TopicCreator is the Bot API surface that may create a forum topic. Adopt never uses it.
type TopicCreator interface {
	CreateForumTopic(ctx context.Context, chatID int64, name string) (int64, error)
}

// ClaimExecutor runs local claim_executions through createForumTopic and complete.
type ClaimExecutor struct {
	State         *State
	Relay         ClaimRelay
	Topics        TopicCreator
	AllowedUserID int64
	Log           func(string, ...any)
	// beforeCreatingFence runs after the reserved route lookup and before
	// the creating fence. Tests inject a concurrent SetRoute here.
	beforeCreatingFence func()
}

// GatewayClaimKey is the reserve idempotency key used when the gateway originates the row.
func GatewayClaimKey(conversationID string) string {
	return "gateway-claim-" + conversationID
}

// AdoptClaimKey is the reserve idempotency key used by punaro-telegram adopt.
func AdoptClaimKey(conversationID string) string {
	return "adopt-" + conversationID
}

// Execute advances one local execution. Failures stay retryable on the stored phase.
func (e ClaimExecutor) Execute(ctx context.Context, conversationID string) error {
	if e.State == nil || e.Relay == nil || strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("telegram claim executor is not configured")
	}
	execution, found, err := e.State.ClaimExecution(conversationID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("telegram claim execution is missing")
	}
	if execution.Phase == ClaimPhaseComplete {
		if err := e.rejectMismatchedRoute(conversationID); err != nil {
			e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseComplete, "err="+err.Error())
			return err
		}
		return nil
	}
	if execution.Phase == ClaimPhaseAdopting {
		if err := e.ensureAdoptReserved(ctx, &execution); err != nil {
			e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseAdopting, "err="+err.Error())
			return err
		}
	}
	if execution.Phase == ClaimPhaseReserved {
		if err := e.ensurePending(ctx, &execution); err != nil {
			e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseReserved, "err="+err.Error())
			return err
		}
		if execution.ThreadID <= 0 {
			if chatID, threadID, found, err := e.State.RouteForConversation(conversationID); err != nil {
				e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseReserved, "err=telegram_route_persist_failed")
				return err
			} else if found && threadID > 0 {
				if e.AllowedUserID != 0 && chatID != e.AllowedUserID {
					err := fmt.Errorf("telegram_route_persist_failed")
					e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseReserved, "err="+err.Error())
					return err
				}
				if err := e.State.PersistClaimThread(conversationID, chatID, threadID); err != nil {
					e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseReserved, "err=telegram_persist_thread_failed")
					return err
				}
				execution.ThreadID = threadID
				execution.ChatID = chatID
				execution.Phase = ClaimPhaseTopicCreated
			}
		}
		if execution.ThreadID <= 0 {
			if e.Topics == nil || e.AllowedUserID == 0 {
				err := fmt.Errorf("telegram_create_forum_topic_failed")
				e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseReserved, "err="+err.Error())
				return err
			}
			name, err := relay.SanitizeConversationDisplayName(execution.DisplayName)
			if err != nil || name == "" {
				err := fmt.Errorf("telegram_sanitize_failed")
				e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseReserved, "err="+err.Error())
				return err
			}
			if e.beforeCreatingFence != nil {
				e.beforeCreatingFence()
			}
			chatID, existingThread, creating, err := e.State.BeginClaimCreating(conversationID, e.AllowedUserID)
			if err != nil {
				failed := err
				if err.Error() != "telegram_route_persist_failed" {
					failed = fmt.Errorf("telegram_create_forum_topic_failed")
				}
				e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseReserved, "err="+failed.Error())
				return failed
			}
			if !creating {
				if e.AllowedUserID != 0 && chatID != e.AllowedUserID {
					err := fmt.Errorf("telegram_route_persist_failed")
					e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseReserved, "err="+err.Error())
					return err
				}
				execution.ThreadID = existingThread
				execution.ChatID = chatID
				execution.Phase = ClaimPhaseTopicCreated
			} else {
				execution.Phase = ClaimPhaseCreating
				threadID, err := e.Topics.CreateForumTopic(ctx, e.AllowedUserID, name)
				if err != nil || threadID <= 0 {
					failed := fmt.Errorf("telegram_create_forum_topic_failed")
					if definitivePreCreationRejection(err) {
						if clearErr := e.State.ClearClaimCreating(conversationID); clearErr != nil {
							e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseCreating, "err="+failed.Error())
							return failed
						}
						execution.Phase = ClaimPhaseReserved
					}
					e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+execution.Phase, "err="+failed.Error())
					return failed
				}
				if err := e.State.PersistClaimThread(conversationID, e.AllowedUserID, threadID); err != nil {
					e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseCreating, "err=telegram_persist_thread_failed")
					return err
				}
				execution.ThreadID = threadID
				execution.ChatID = e.AllowedUserID
				execution.Phase = ClaimPhaseTopicCreated
			}
		} else {
			execution.Phase = ClaimPhaseTopicCreated
		}
	}
	if execution.Phase == ClaimPhaseCreating {
		if execution.ThreadID <= 0 {
			if chatID, threadID, found, err := e.State.RouteForConversation(conversationID); err != nil {
				e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseCreating, "err=telegram_route_persist_failed")
				return err
			} else if found && threadID > 0 {
				if e.AllowedUserID != 0 && chatID != e.AllowedUserID {
					err := fmt.Errorf("telegram_route_persist_failed")
					e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseCreating, "err="+err.Error())
					return err
				}
				if err := e.State.PersistClaimThread(conversationID, chatID, threadID); err != nil {
					e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseCreating, "err=telegram_persist_thread_failed")
					return err
				}
				execution.ThreadID = threadID
				execution.ChatID = chatID
				execution.Phase = ClaimPhaseTopicCreated
			} else {
				err := fmt.Errorf("telegram_create_forum_topic_failed")
				e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseCreating, "err="+err.Error())
				return err
			}
		} else {
			execution.Phase = ClaimPhaseTopicCreated
		}
	}
	if execution.Phase == ClaimPhaseTopicCreated {
		if e.AllowedUserID == 0 || execution.ThreadID <= 0 || execution.ChatID == 0 || execution.ChatID != e.AllowedUserID {
			err := fmt.Errorf("telegram_route_persist_failed")
			e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseTopicCreated, "err="+err.Error())
			return err
		}
		if err := e.State.PersistClaimRoute(execution.ChatID, execution.ThreadID, conversationID); err != nil {
			e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseTopicCreated, "err=telegram_route_persist_failed")
			return err
		}
		execution.Phase = ClaimPhaseRoutePersisted
	}
	if execution.Phase == ClaimPhaseRoutePersisted {
		if _, err := e.Relay.CompleteTelegramClaim(ctx, conversationID); err != nil {
			e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseRoutePersisted, "err=telegram_complete_failed")
			return fmt.Errorf("telegram_complete_failed")
		}
		if err := e.State.MarkClaimComplete(conversationID); err != nil {
			e.logEvent("telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseRoutePersisted, "err=telegram_complete_failed")
			return err
		}
		e.logEvent("telegram_claim_completed", "conversation_id="+conversationID)
	}
	return nil
}

func definitivePreCreationRejection(err error) bool {
	var status BotAPIStatusError
	return errors.As(err, &status) && status.Status >= 400 && status.Status < 500
}

func (e ClaimExecutor) ensurePending(ctx context.Context, execution *ClaimExecution) error {
	if execution.SkipReserve {
		return nil
	}
	claim, err := e.Relay.ClaimConversation(ctx, execution.ConversationID, relay.TelegramGatewayEndpoint, GatewayClaimKey(execution.ConversationID))
	if err != nil {
		return fmt.Errorf("telegram_reserve_failed")
	}
	switch claim.Status {
	case "pending":
	case "complete":
		if recoverable, err := e.localClaimRouteRecoverable(execution); err != nil {
			return err
		} else if !recoverable {
			return fmt.Errorf("telegram_claim_already_complete")
		}
	default:
		return fmt.Errorf("telegram_reserve_failed")
	}
	if claim.DisplayName != "" {
		execution.DisplayName = claim.DisplayName
		if err := e.State.PersistClaimDisplayName(execution.ConversationID, claim.DisplayName); err != nil {
			return err
		}
	}
	e.logEvent("telegram_claim_reserved", "actor=gateway", "conversation_id="+execution.ConversationID)
	return nil
}

func (e ClaimExecutor) ensureAdoptReserved(ctx context.Context, execution *ClaimExecution) error {
	claim, err := e.Relay.ClaimConversation(ctx, execution.ConversationID, relay.TelegramGatewayEndpoint, AdoptClaimKey(execution.ConversationID))
	if err != nil {
		return fmt.Errorf("telegram_reserve_failed")
	}
	if strings.TrimSpace(claim.DisplayName) == "" {
		return fmt.Errorf("telegram adopt requires a display name")
	}
	execution.DisplayName = claim.DisplayName
	if err := e.State.PersistClaimDisplayName(execution.ConversationID, claim.DisplayName); err != nil {
		return err
	}
	switch claim.Status {
	case "pending":
		if err := e.State.PersistClaimAdoptReserved(execution.ConversationID); err != nil {
			return err
		}
		execution.Phase = ClaimPhaseRoutePersisted
		e.logEvent("telegram_claim_reserved", "actor=adopt", "conversation_id="+execution.ConversationID)
		return nil
	case "complete":
		if err := e.State.MarkClaimComplete(execution.ConversationID); err != nil {
			return err
		}
		execution.Phase = ClaimPhaseComplete
		e.logEvent("telegram_claim_completed", "conversation_id="+execution.ConversationID)
		return nil
	default:
		return fmt.Errorf("telegram_reserve_failed")
	}
}

func (e ClaimExecutor) localClaimRouteRecoverable(execution *ClaimExecution) (bool, error) {
	if execution.ThreadID > 0 {
		return true, nil
	}
	chatID, threadID, found, err := e.State.RouteForConversation(execution.ConversationID)
	if err != nil {
		return false, err
	}
	if !found || threadID <= 0 {
		return false, nil
	}
	if e.AllowedUserID != 0 && chatID != e.AllowedUserID {
		return false, nil
	}
	return true, nil
}

func (e ClaimExecutor) rejectMismatchedRoute(conversationID string) error {
	chatID, threadID, found, err := e.State.RouteForConversation(conversationID)
	if err != nil {
		return err
	}
	if !found || threadID <= 0 || e.AllowedUserID == 0 || chatID != e.AllowedUserID {
		return fmt.Errorf("telegram_route_persist_failed")
	}
	return nil
}

// ResumeAll continues incomplete local executions, at most pendingClaimPollLimit
// per cycle, advancing a durable conversation cursor so later rows are not starved.
func (e ClaimExecutor) ResumeAll(ctx context.Context) error {
	if err := e.rejectCompletedRouteMismatches(); err != nil {
		return err
	}
	after, err := e.State.resumeClaimCursor()
	if err != nil {
		return err
	}
	executions, err := e.State.IncompleteClaimExecutionsAfter(after, pendingClaimPollLimit)
	if err != nil {
		return err
	}
	last := after
	for _, execution := range executions {
		_ = e.Execute(ctx, execution.ConversationID)
		last = execution.ConversationID
	}
	if len(executions) < pendingClaimPollLimit {
		return e.State.setResumeClaimCursor("")
	}
	return e.State.setResumeClaimCursor(last)
}

func (e ClaimExecutor) rejectCompletedRouteMismatches() error {
	after, err := e.State.completedRouteCursor()
	if err != nil {
		return err
	}
	executions, err := e.State.CompletedClaimExecutionsAfter(after, pendingClaimPollLimit)
	if err != nil {
		return err
	}
	last := after
	for _, execution := range executions {
		if err := e.rejectMismatchedRoute(execution.ConversationID); err != nil {
			e.logEvent("telegram_claim_failed", "conversation_id="+execution.ConversationID, "phase="+ClaimPhaseComplete, "err="+err.Error())
			return err
		}
		last = execution.ConversationID
	}
	if len(executions) < pendingClaimPollLimit {
		return e.State.setCompletedRouteCursor("")
	}
	return e.State.setCompletedRouteCursor(last)
}

const pendingClaimPollLimit = 10

// StartPending inserts reserved rows for relay-pending claims with no local execution.
func (e ClaimExecutor) StartPending(ctx context.Context) error {
	after, err := e.State.pendingClaimCursor()
	if err != nil {
		return err
	}
	scanned := 0
	for {
		claims, err := e.Relay.PendingTelegramClaims(ctx, pendingClaimPollLimit, after)
		if err != nil {
			return fmt.Errorf("poll pending telegram claims: %w", err)
		}
		if len(claims) == 0 {
			return e.State.setPendingClaimCursor("")
		}
		for _, claim := range claims {
			after = claim.ConversationID
			scanned++
			if _, found, err := e.State.ClaimExecution(claim.ConversationID); err != nil {
				return err
			} else if !found {
				inserted, err := e.State.InsertPendingExecution(claim.ConversationID, claim.DisplayName)
				if err != nil {
					return err
				}
				if inserted {
					e.logEvent("telegram_claim_reserved", "actor=session", "conversation_id="+claim.ConversationID)
					_ = e.Execute(ctx, claim.ConversationID)
				}
			}
			if scanned >= pendingClaimPollLimit {
				return e.State.setPendingClaimCursor(after)
			}
		}
		if len(claims) < pendingClaimPollLimit {
			return e.State.setPendingClaimCursor("")
		}
	}
}

// Adopt binds an existing topic_routes row to a completed claim. It never creates a topic.
func Adopt(ctx context.Context, state *State, relayClient ClaimRelay, conversationID string, allowedUserID int64, logfn func(string, ...any)) error {
	if state == nil || relayClient == nil || strings.TrimSpace(conversationID) == "" {
		return fmt.Errorf("telegram adopt is not configured")
	}
	chatID, threadID, found, err := state.RouteForConversation(conversationID)
	if err != nil {
		return err
	}
	if !found || threadID <= 0 {
		return fmt.Errorf("telegram adopt requires an existing topic route")
	}
	if allowedUserID == 0 || chatID != allowedUserID {
		return fmt.Errorf("telegram adopt requires the configured telegram chat")
	}
	if _, err = state.AdoptExistingRoute(conversationID, allowedUserID); err != nil {
		return err
	}
	claim, err := relayClient.ClaimConversation(ctx, conversationID, relay.TelegramGatewayEndpoint, AdoptClaimKey(conversationID))
	if err != nil {
		return fmt.Errorf("telegram_reserve_failed")
	}
	if strings.TrimSpace(claim.DisplayName) == "" {
		return fmt.Errorf("telegram adopt requires a display name")
	}
	if err := state.PersistClaimDisplayName(conversationID, claim.DisplayName); err != nil {
		return err
	}
	if existing, found, err := state.ClaimExecution(conversationID); err != nil {
		return err
	} else if found && existing.Phase == ClaimPhaseComplete && claim.Status == "complete" {
		logClaim(logfn, "telegram_claim_completed", "conversation_id="+conversationID)
		return nil
	}
	if claim.Status == "complete" {
		if err := state.MarkClaimComplete(conversationID); err != nil {
			return err
		}
		logClaim(logfn, "telegram_claim_completed", "conversation_id="+conversationID)
		return nil
	}
	if err := state.PersistClaimAdoptReserved(conversationID); err != nil {
		return err
	}
	if _, err := relayClient.CompleteTelegramClaim(ctx, conversationID); err != nil {
		logClaim(logfn, "telegram_claim_failed", "conversation_id="+conversationID, "phase="+ClaimPhaseRoutePersisted, "err=telegram_complete_failed")
		return fmt.Errorf("telegram_complete_failed")
	}
	if err := state.MarkClaimComplete(conversationID); err != nil {
		return err
	}
	logClaim(logfn, "telegram_claim_completed", "conversation_id="+conversationID)
	return nil
}

func (e ClaimExecutor) logEvent(class string, fields ...string) {
	logClaim(e.Log, class, fields...)
}

func logClaim(logfn func(string, ...any), class string, fields ...string) {
	line := "telegram event class=" + class
	if len(fields) > 0 {
		line += " " + strings.Join(fields, " ")
	}
	if logfn != nil {
		logfn("%s", line)
		return
	}
	log.Printf("%s", line)
}
