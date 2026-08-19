package telegram

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

const (
	startHelpText        = "This bot lets you claim a Punaro topic. Send /list to see unclaimed topics, then tap one to claim it."
	listEmptyText        = "There are no unclaimed Punaro topics right now."
	listPromptText       = "Tap a topic to claim it."
	callbackFailureText  = "Unable to complete this action."
	callbackAcceptedText = "Claim accepted."
	maxButtonTextRunes   = 64
)

// Update is the small, untrusted Telegram input surface used by the gateway.
// Parsing the Bot API response happens outside this policy boundary.
type Update struct {
	ID           int64
	UserID       int64
	ChatID       int64
	ThreadID     int64
	MessageID    int64
	Text         string
	CallbackID   string
	CallbackData string
	ReplyToID    int64
	IsCommand    bool
	Command      string
}

// Submission is opaque user text bound to an explicitly configured relay room.
type Submission struct {
	UpdateID       int64
	ConversationID string
	Text           string
	ChatID         int64
	ThreadID       int64
	ReplyToID      int64
}

// OperatorNotify is the Bot API surface for operator UX. It never carries
// agent mail or conversation identifiers.
type OperatorNotify interface {
	SendMessage(ctx context.Context, chatID int64, text string, keyboard [][]InlineKeyboardButton) error
	AnswerCallbackQuery(ctx context.Context, callbackID, text string) error
}

// Gateway applies authorization, replay, and exact-topic routing policy to
// Telegram updates before submitting opaque text to the relay.
type Gateway struct {
	AllowedUserID int64
	State         *State
	Submit        func(context.Context, Submission) error
	ListUnclaimed func(context.Context) ([]relay.UnclaimedTopic, error)
	Notify        OperatorNotify
	Claims        *ClaimExecutor
	Now           func() time.Time
	Log           func(string, ...any)
}

// Handle never turns Telegram text into control input. Commands are accepted
// only from a parsed bot_command entity. A valid /list tap persists reserved
// then consumes the token before executeClaim; execute failures stay local.
// Main-chat ordinary text stays unbound.
func (g Gateway) Handle(ctx context.Context, update Update) error {
	if g.State == nil || g.Submit == nil || g.AllowedUserID == 0 {
		return fmt.Errorf("telegram gateway is not configured")
	}
	processed, err := g.State.Processed(update.ID)
	if err != nil {
		return fmt.Errorf("read telegram update state: %w", err)
	}
	if processed {
		if update.CallbackID != "" {
			g.logEvent("telegram_update_inert", "reason=replay")
		}
		return nil
	}
	if update.CallbackID != "" {
		return g.handleCallback(ctx, update)
	}
	if update.UserID != g.AllowedUserID {
		g.logEvent("telegram_update_inert", "reason=unauthorized")
		return g.markInert(update.ID)
	}
	if update.IsCommand {
		return g.handleCommand(ctx, update)
	}
	if strings.TrimSpace(update.Text) == "" {
		g.logEvent("telegram_update_inert", "reason=non_text")
		return g.markInert(update.ID)
	}
	conversation, found, err := g.State.Route(update.ChatID, update.ThreadID)
	if err != nil {
		return fmt.Errorf("resolve telegram topic route: %w", err)
	}
	if !found {
		if update.ThreadID == 0 {
			g.logEvent("telegram_update_inert", "reason=main_chat")
		} else {
			g.logEvent("telegram_update_inert", "reason=unbound")
		}
		return g.markInert(update.ID)
	}
	if err := g.Submit(ctx, Submission{UpdateID: update.ID, ConversationID: conversation, Text: update.Text, ChatID: update.ChatID, ThreadID: update.ThreadID, ReplyToID: update.ReplyToID}); err != nil {
		return fmt.Errorf("submit telegram message: %w", err)
	}
	if err := g.State.MarkProcessed(update.ID); err != nil {
		return fmt.Errorf("record telegram update: %w", err)
	}
	g.logEvent("telegram_update_submitted", "conversation_id="+conversation)
	return nil
}

func (g Gateway) handleCallback(ctx context.Context, update Update) error {
	if update.UserID != g.AllowedUserID || update.ChatID != g.AllowedUserID {
		g.logEvent("telegram_update_inert", "reason=unauthorized")
		g.answerCallback(ctx, update.CallbackID, callbackFailureText)
		return g.markInert(update.ID)
	}
	conversation, reserved, err := g.State.ReserveClaimAndConsumeToken(update.CallbackData, g.now())
	if err != nil {
		return fmt.Errorf("reserve telegram claim execution: %w", err)
	}
	if !reserved {
		g.logEvent("telegram_update_inert", "reason=callback")
		g.answerCallback(ctx, update.CallbackID, callbackFailureText)
		return g.markInert(update.ID)
	}
	g.answerCallback(ctx, update.CallbackID, callbackAcceptedText)
	if err := g.State.MarkProcessed(update.ID); err != nil {
		return fmt.Errorf("record telegram update: %w", err)
	}
	g.logEvent("telegram_claim_reserved", "actor=gateway", "conversation_id="+conversation)
	if g.Claims != nil {
		_ = g.Claims.Execute(ctx, conversation)
	}
	return nil
}

func (g Gateway) answerCallback(ctx context.Context, callbackID, text string) {
	if g.Notify == nil || callbackID == "" {
		return
	}
	if err := g.Notify.AnswerCallbackQuery(ctx, callbackID, text); err != nil {
		g.logEvent("telegram_update_inert", "reason=callback_answer")
	}
}

func (g Gateway) handleCommand(ctx context.Context, update Update) error {
	if update.ChatID != g.AllowedUserID {
		g.logEvent("telegram_update_inert", "reason=unauthorized")
		return g.markInert(update.ID)
	}
	switch update.Command {
	case "start":
		if err := g.sendOperator(ctx, startHelpText, nil); err != nil {
			return err
		}
		g.logEvent("telegram_command", "cmd=start")
		return g.markInert(update.ID)
	case "list":
		if err := g.handleList(ctx); err != nil {
			return err
		}
		g.logEvent("telegram_command", "cmd=list")
		return g.markInert(update.ID)
	default:
		g.logEvent("telegram_update_inert", "reason=unknown_command")
		return g.markInert(update.ID)
	}
}

func (g Gateway) handleList(ctx context.Context) error {
	if g.ListUnclaimed == nil || g.Notify == nil {
		return fmt.Errorf("telegram gateway is not configured")
	}
	topics, err := g.ListUnclaimed(ctx)
	if err != nil {
		return fmt.Errorf("list unclaimed telegram topics: %w", err)
	}
	if len(topics) == 0 {
		return g.sendOperator(ctx, listEmptyText, nil)
	}
	labels := make(map[string]string, len(topics))
	for _, topic := range topics {
		label := truncateRunes(topic.DisplayName, maxButtonTextRunes)
		if other, exists := labels[label]; exists && other != topic.ID {
			return fmt.Errorf("telegram unclaimed topic labels are ambiguous")
		}
		labels[label] = topic.ID
	}
	keyboard := make([][]InlineKeyboardButton, 0, len(topics))
	now := g.now()
	for _, topic := range topics {
		token, err := g.State.IssueCallbackToken(topic.ID, now)
		if err != nil {
			return fmt.Errorf("issue telegram callback token: %w", err)
		}
		keyboard = append(keyboard, []InlineKeyboardButton{{
			Text:         truncateRunes(topic.DisplayName, maxButtonTextRunes),
			CallbackData: token,
		}})
	}
	return g.sendOperator(ctx, listPromptText, keyboard)
}

func (g Gateway) sendOperator(ctx context.Context, text string, keyboard [][]InlineKeyboardButton) error {
	if g.Notify == nil {
		return fmt.Errorf("telegram gateway is not configured")
	}
	if err := g.Notify.SendMessage(ctx, g.AllowedUserID, text, keyboard); err != nil {
		return fmt.Errorf("send telegram operator message: %w", err)
	}
	return nil
}

func (g Gateway) markInert(updateID int64) error {
	if err := g.State.MarkProcessed(updateID); err != nil {
		return fmt.Errorf("record inert telegram update: %w", err)
	}
	return nil
}

func (g Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now().UTC()
}

func (g Gateway) logEvent(class string, fields ...string) {
	line := "telegram event class=" + class
	if len(fields) > 0 {
		line += " " + strings.Join(fields, " ")
	}
	if g.Log != nil {
		g.Log("%s", line)
		return
	}
	log.Printf("%s", line)
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if limit < 1 || len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
