package telegram

import (
	"context"
	"fmt"
	"strings"

	"github.com/rock3r/punaro/internal/relay"
)

// RelaySender is the narrow signed-relay operation required to submit a
// Telegram update as an opaque conversation message.
type RelaySender interface {
	Send(ctx context.Context, conversationID, fromEndpoint, body, idempotencyKey string) (relay.Message, error)
}

// SubmitToRelay binds a gateway endpoint to a signed relay sender. The
// Telegram update ID, rather than message text, defines the retry identity so
// a process restart cannot duplicate a user message.
func SubmitToRelay(sender RelaySender, endpoint string) func(context.Context, Submission) error {
	return func(ctx context.Context, submission Submission) error {
		if sender == nil || strings.TrimSpace(endpoint) == "" || submission.UpdateID < 1 || strings.TrimSpace(submission.ConversationID) == "" || strings.TrimSpace(submission.Text) == "" {
			return fmt.Errorf("invalid Telegram relay submission")
		}
		_, err := sender.Send(ctx, submission.ConversationID, endpoint, submission.Text, fmt.Sprintf("telegram-update:%d", submission.UpdateID))
		return err
	}
}
