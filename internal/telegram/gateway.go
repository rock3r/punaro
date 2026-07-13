package telegram

import (
	"context"
	"fmt"
	"strings"
)

// Update is the small, untrusted Telegram input surface used by the gateway.
// Parsing the Bot API response happens outside this policy boundary.
type Update struct {
	ID       int64
	UserID   int64
	ChatID   int64
	ThreadID int64
	Text     string
}

// Submission is opaque user text bound to an explicitly configured relay room.
type Submission struct {
	ConversationID string
	Text           string
	ChatID         int64
	ThreadID       int64
}

// Gateway applies authorization, replay, and exact-topic routing policy to
// Telegram updates before submitting opaque text to the relay.
type Gateway struct {
	AllowedUserID int64
	State         *State
	Submit        func(context.Context, Submission) error
}

// Handle never turns Telegram text into control input. Replayed and
// unauthorized updates are inert; an unbound topic is rejected rather than
// guessed or redirected to the main chat.
func (g Gateway) Handle(ctx context.Context, update Update) error {
	if g.State == nil || g.Submit == nil || g.AllowedUserID == 0 {
		return fmt.Errorf("telegram gateway is not configured")
	}
	claimed, err := g.State.ClaimUpdate(update.ID)
	if err != nil {
		return fmt.Errorf("claim telegram update: %w", err)
	}
	if !claimed || update.UserID != g.AllowedUserID {
		return nil
	}
	if strings.TrimSpace(update.Text) == "" {
		return nil
	}
	conversation, found, err := g.State.Route(update.ChatID, update.ThreadID)
	if err != nil {
		return fmt.Errorf("resolve telegram topic route: %w", err)
	}
	if !found {
		return fmt.Errorf("telegram topic is not routed")
	}
	if err := g.Submit(ctx, Submission{ConversationID: conversation, Text: update.Text, ChatID: update.ChatID, ThreadID: update.ThreadID}); err != nil {
		return fmt.Errorf("submit telegram message: %w", err)
	}
	return nil
}
