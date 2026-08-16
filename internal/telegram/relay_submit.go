package telegram

import (
	"context"
	"fmt"
	"strings"

	"github.com/rock3r/punaro/internal/relay"
)

// InboundRelaySender is the gateway-only telegram-inbound write.
type InboundRelaySender interface {
	SendTelegramInbound(ctx context.Context, conversationID, fromEndpoint, fromParticipant, body, inReplyToMessageID, inReplyToEndpoint string, telegramThreadID int64, idempotencyKey string) (relay.Message, error)
}

// SubmitToRelay binds a gateway endpoint to telegram-inbound. The Telegram
// update ID, rather than message text, defines the retry identity so a process
// restart cannot duplicate a user message.
func SubmitToRelay(sender InboundRelaySender, endpoint string, state *State, logfn func(string, ...any)) func(context.Context, Submission) error {
	return func(ctx context.Context, submission Submission) error {
		if sender == nil || strings.TrimSpace(endpoint) == "" || submission.UpdateID < 1 || strings.TrimSpace(submission.ConversationID) == "" || strings.TrimSpace(submission.Text) == "" {
			return fmt.Errorf("invalid Telegram relay submission")
		}
		var replyMessageID, replyEndpoint string
		if submission.ReplyToID > 0 && state != nil {
			ref, found, err := state.LookupOutbound(submission.ChatID, submission.ReplyToID)
			if err != nil {
				return fmt.Errorf("lookup telegram outbound map: %w", err)
			}
			if !found {
				logClaim(logfn, "telegram_outbound_map_miss", "conversation_id="+submission.ConversationID)
			} else {
				replyMessageID = ref.PunaroMessageID
				replyEndpoint = ref.FromEndpoint
			}
		}
		_, err := sender.SendTelegramInbound(ctx, submission.ConversationID, endpoint, relay.TelegramUserParticipant, submission.Text, replyMessageID, replyEndpoint, submission.ThreadID, fmt.Sprintf("telegram-update:%d", submission.UpdateID))
		return err
	}
}
