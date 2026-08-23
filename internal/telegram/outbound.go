package telegram

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rock3r/punaro/internal/relay"
)

// RichSender posts one already-rendered, topic-bound rich Telegram message.
type RichSender interface {
	SendRichMessage(ctx context.Context, chatID, threadID int64, html string) (int64, error)
}

type permanentTelegramDeliveryError struct {
	reason string
}

func (e permanentTelegramDeliveryError) Error() string                { return e.reason }
func (permanentTelegramDeliveryError) PermanentTelegramFailure() bool { return true }

// SendDelivery renders an opaque agent reply as inert rich HTML and sends it
// only to the exact topic bound to the delivery's conversation. Telegram has
// no idempotency key for sendRichMessage, so callers must acknowledge the
// relay delivery only after this function succeeds; a crash can result in an
// explicit at-least-once duplicate rather than silent loss.
func SendDelivery(ctx context.Context, state *State, sender RichSender, delivery relay.Delivery, allowedUserID int64) error {
	from := delivery.Message.FromEndpoint
	if from == "" {
		from = delivery.Message.FromRole
	}
	if state == nil || sender == nil || strings.TrimSpace(delivery.Message.ConversationID) == "" || strings.TrimSpace(from) == "" || delivery.Message.Body == "" {
		return permanentTelegramDeliveryError{reason: "invalid Telegram delivery"}
	}
	chatID, threadID, found, err := state.RouteForConversation(delivery.Message.ConversationID)
	if err != nil {
		return fmt.Errorf("read Telegram delivery route: %w", err)
	}
	if !found {
		return permanentTelegramDeliveryError{reason: "telegram conversation route is missing"}
	}
	if allowedUserID == 0 || chatID != allowedUserID {
		return permanentTelegramDeliveryError{reason: "telegram conversation route is not the configured chat"}
	}
	for _, rendered := range renderDelivery(from, delivery.Message.Body) {
		messageID, err := sender.SendRichMessage(ctx, chatID, threadID, rendered)
		if err != nil {
			return err
		}
		if err := state.RecordOutbound(chatID, messageID, delivery.Message.ConversationID, delivery.Message.ID, delivery.Message.FromEndpoint, time.Now().UTC()); err != nil {
			return fmt.Errorf("record telegram outbound map: %w", err)
		}
	}
	return nil
}

func renderDelivery(endpoint, body string) []string {
	header := "<p><b>Reply from </b><code>" + html.EscapeString(endpoint) + "</code></p><pre>"
	footer := "</pre>"
	parts := make([]string, 0, 1)
	var current strings.Builder
	for _, runeValue := range body {
		candidate := current.String() + string(runeValue)
		if current.Len() > 0 && len(header)+len(html.EscapeString(candidate))+len(footer) > maxRichMessageBytes {
			parts = append(parts, header+html.EscapeString(current.String())+footer)
			current.Reset()
		}
		current.WriteRune(runeValue)
	}
	if current.Len() > 0 {
		parts = append(parts, header+html.EscapeString(current.String())+footer)
	}
	if len(parts) == 0 && utf8.ValidString(body) {
		return []string{header + footer}
	}
	return parts
}
