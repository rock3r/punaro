package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const maxBotResponseBytes = 1 << 20
const maxRichMessageBytes = 32 << 10

// BotAPIStatusError is a completed Telegram HTTP response. Client errors other
// than rate limiting are terminal because retrying the same request cannot
// change the rejected payload or target.
type BotAPIStatusError struct {
	Method string
	Status int
	Kind   BotAPIErrorKind
}

func (e BotAPIStatusError) Error() string {
	return fmt.Sprintf("telegram %s returned HTTP %d", e.Method, e.Status)
}

// BotAPIErrorKind is a closed classification derived from a bounded response;
// provider text itself is never retained or returned.
type BotAPIErrorKind string

// Stable Bot API error classifications.
const (
	BotAPIErrorUnknown      BotAPIErrorKind = ""
	BotAPIErrorDeletedTopic BotAPIErrorKind = "deleted_topic"
)

// PermanentBotAPIFailure recognizes terminal request outcomes while keeping
// 401 retryable because Access/proxy/token recovery may restore it.
func PermanentBotAPIFailure(err error) bool {
	var status BotAPIStatusError
	if !errors.As(err, &status) {
		return false
	}
	switch status.Status {
	case http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

// DeletedTopicFailure reports the whitelisted Bot API missing-topic class.
func DeletedTopicFailure(err error) bool {
	var status BotAPIStatusError
	return errors.As(err, &status) && status.Kind == BotAPIErrorDeletedTopic
}

// PermanentTelegramFailure reports a completed request that must not poison
// the durable outbound queue. It delegates to the bounded status classifier so
// authorization failures that may recover remain retryable.
func (e BotAPIStatusError) PermanentTelegramFailure() bool {
	return PermanentBotAPIFailure(e)
}

// Client is a narrow Telegram Bot API long-poll client. Its token is retained
// only in memory and is never included in returned errors.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// NewClient validates a Bot API base URL and retains the supplied token only
// in memory for the lifetime of the client.
func NewClient(rawURL, token string, client *http.Client) (*Client, error) {
	base, err := url.Parse(rawURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.Path != "" && base.Path != "/" || base.RawQuery != "" || base.Fragment != "" || strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("invalid Telegram API configuration")
	}
	if client == nil {
		client = &http.Client{Timeout: 40 * time.Second}
	}
	return &Client{base: base, token: token, http: client}, nil
}

// BotCommand is one entry registered with setMyCommands.
type BotCommand struct {
	Command     string
	Description string
}

// InlineKeyboardButton is one operator-UX button. CallbackData must be an
// opaque gateway token, never a conversation id or display-name key.
type InlineKeyboardButton struct {
	Text         string
	CallbackData string
}

// DefaultBotCommands is the menu registered once per gateway process.
func DefaultBotCommands() []BotCommand {
	return []BotCommand{
		{Command: "start", Description: "How this bot works"},
		{Command: "list", Description: "Claim an unclaimed Punaro topic"},
	}
}

// Doctor verifies the configured Bot API identity with Telegram's read-only
// getMe method. Provider response fields are deliberately discarded so they
// cannot cross the diagnostic boundary.
func (c *Client) Doctor(ctx context.Context) error {
	var decoded struct {
		OK     bool `json:"ok"`
		Result struct {
			ID int64 `json:"id"`
		} `json:"result"`
	}
	if err := c.postJSON(ctx, "getMe", []byte(`{}`), &decoded); err != nil {
		return fmt.Errorf("telegram doctor failed")
	}
	if !decoded.OK || decoded.Result.ID == 0 {
		return fmt.Errorf("telegram doctor failed")
	}
	return nil
}

// Updates returns text messages, bot_command metadata, and callback queries.
// Unknown Bot API fields are intentionally ignored; bodies remain opaque text.
func (c *Client) Updates(ctx context.Context, offset int64) ([]Update, error) {
	target := *c.base
	target.Path = strings.TrimRight(target.Path, "/") + "/bot" + c.token + "/getUpdates"
	query := target.Query()
	query.Set("offset", strconv.FormatInt(offset, 10))
	query.Set("timeout", "30")
	query.Set("allowed_updates", `["message","callback_query"]`)
	target.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("telegram poll failed")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("telegram poll failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, readBotAPIStatus(response, "getUpdates")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBotResponseBytes+1))
	if err != nil || len(body) > maxBotResponseBytes {
		return nil, fmt.Errorf("read Telegram poll response")
	}
	var decoded struct {
		OK     bool `json:"ok"`
		Result []struct {
			ID            int64          `json:"update_id"`
			Message       *botAPIMessage `json:"message"`
			CallbackQuery *struct {
				ID      string         `json:"id"`
				Data    string         `json:"data"`
				From    botAPIUser     `json:"from"`
				Message *botAPIMessage `json:"message"`
			} `json:"callback_query"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || !decoded.OK {
		return nil, fmt.Errorf("invalid Telegram poll response")
	}
	updates := make([]Update, 0, len(decoded.Result))
	for _, item := range decoded.Result {
		update := Update{ID: item.ID}
		if item.Message != nil {
			applyBotAPIMessage(&update, item.Message)
		}
		if item.CallbackQuery != nil {
			update.CallbackID = item.CallbackQuery.ID
			update.CallbackData = item.CallbackQuery.Data
			update.UserID = item.CallbackQuery.From.ID
			if item.CallbackQuery.Message != nil {
				update.ChatID = item.CallbackQuery.Message.Chat.ID
				update.MessageID = item.CallbackQuery.Message.MessageID
			}
		}
		updates = append(updates, update)
	}
	return updates, nil
}

type botAPIUser struct {
	ID int64 `json:"id"`
}

type botAPIChat struct {
	ID int64 `json:"id"`
}

type botAPIEntity struct {
	Offset int    `json:"offset"`
	Length int    `json:"length"`
	Type   string `json:"type"`
}

type botAPIMessage struct {
	MessageID int64          `json:"message_id"`
	From      botAPIUser     `json:"from"`
	Chat      botAPIChat     `json:"chat"`
	ThreadID  int64          `json:"message_thread_id"`
	Text      string         `json:"text"`
	Entities  []botAPIEntity `json:"entities"`
	ReplyTo   *struct {
		MessageID int64 `json:"message_id"`
	} `json:"reply_to_message"`
}

func applyBotAPIMessage(update *Update, message *botAPIMessage) {
	update.UserID = message.From.ID
	update.ChatID = message.Chat.ID
	update.ThreadID = message.ThreadID
	update.MessageID = message.MessageID
	update.Text = message.Text
	if message.ReplyTo != nil {
		update.ReplyToID = message.ReplyTo.MessageID
	}
	if command, ok := parseBotCommand(message.Text, message.Entities); ok {
		update.IsCommand = true
		update.Command = command
	}
}

func parseBotCommand(text string, entities []botAPIEntity) (string, bool) {
	for _, entity := range entities {
		if entity.Type != "bot_command" || entity.Offset != 0 {
			continue
		}
		command := normalizeBotCommand(utf16Slice(text, entity.Offset, entity.Length))
		if command != "" {
			return command, true
		}
	}
	return "", false
}

func normalizeBotCommand(raw string) string {
	command := strings.TrimSpace(raw)
	command = strings.TrimPrefix(command, "/")
	if at := strings.IndexByte(command, '@'); at >= 0 {
		command = command[:at]
	}
	return strings.ToLower(command)
}

func utf16Slice(text string, offset, length int) string {
	encoded := utf16.Encode([]rune(text))
	if offset < 0 || length < 0 || offset+length > len(encoded) {
		return ""
	}
	return string(utf16.Decode(encoded[offset : offset+length]))
}

// SendRichMessage sends trusted, already-rendered HTML to one exact Telegram
// topic. It disables entity detection and protects content so opaque agent
// text cannot create accidental mentions, links, or forwarding paths.
func (c *Client) SendRichMessage(ctx context.Context, chatID, threadID int64, html string) (int64, error) {
	if chatID == 0 || threadID <= 0 || strings.TrimSpace(html) == "" || len(html) > maxRichMessageBytes {
		return 0, fmt.Errorf("invalid Telegram rich message")
	}
	body, err := json.Marshal(struct {
		ChatID          int64 `json:"chat_id"`
		MessageThreadID int64 `json:"message_thread_id"`
		RichMessage     struct {
			HTML                string `json:"html"`
			SkipEntityDetection bool   `json:"skip_entity_detection"`
		} `json:"rich_message"`
		ProtectContent bool `json:"protect_content"`
	}{
		ChatID:          chatID,
		MessageThreadID: threadID,
		RichMessage: struct {
			HTML                string `json:"html"`
			SkipEntityDetection bool   `json:"skip_entity_detection"`
		}{HTML: html, SkipEntityDetection: true},
		ProtectContent: true,
	})
	if err != nil {
		return 0, fmt.Errorf("telegram sendRichMessage failed")
	}
	var decoded struct {
		OK     bool `json:"ok"`
		Result struct {
			MessageID int64 `json:"message_id"`
		} `json:"result"`
	}
	if err := c.postJSON(ctx, "sendRichMessage", body, &decoded); err != nil {
		return 0, err
	}
	if !decoded.OK || decoded.Result.MessageID <= 0 {
		return 0, fmt.Errorf("invalid Telegram rich message response")
	}
	return decoded.Result.MessageID, nil
}

// CreateForumTopic creates one private-chat forum topic and returns the Bot API
// message_thread_id. Callers must persist that id before any later work.
func (c *Client) CreateForumTopic(ctx context.Context, chatID int64, name string) (int64, error) {
	if chatID == 0 || strings.TrimSpace(name) == "" {
		return 0, fmt.Errorf("invalid telegram forum topic")
	}
	body, err := json.Marshal(struct {
		ChatID int64  `json:"chat_id"`
		Name   string `json:"name"`
	}{ChatID: chatID, Name: name})
	if err != nil {
		return 0, fmt.Errorf("telegram createForumTopic failed")
	}
	var decoded struct {
		OK     bool `json:"ok"`
		Result struct {
			MessageThreadID int64 `json:"message_thread_id"`
		} `json:"result"`
	}
	if err := c.postJSON(ctx, "createForumTopic", body, &decoded); err != nil {
		return 0, err
	}
	if !decoded.OK || decoded.Result.MessageThreadID <= 0 {
		return 0, fmt.Errorf("invalid telegram createForumTopic response")
	}
	return decoded.Result.MessageThreadID, nil
}

// SetMyCommands registers the operator command menu. Call it once per process.
func (c *Client) SetMyCommands(ctx context.Context, commands []BotCommand) error {
	if len(commands) == 0 {
		return fmt.Errorf("invalid telegram commands")
	}
	encoded := make([]struct {
		Command     string `json:"command"`
		Description string `json:"description"`
	}, 0, len(commands))
	for _, command := range commands {
		if strings.TrimSpace(command.Command) == "" || strings.TrimSpace(command.Description) == "" {
			return fmt.Errorf("invalid telegram commands")
		}
		encoded = append(encoded, struct {
			Command     string `json:"command"`
			Description string `json:"description"`
		}{Command: command.Command, Description: command.Description})
	}
	return c.postMethod(ctx, "setMyCommands", struct {
		Commands any `json:"commands"`
	}{Commands: encoded})
}

// SendMessage posts operator UX to the private chat. Display names are labels
// only; the caller must not put conversation ids in text or callback_data.
func (c *Client) SendMessage(ctx context.Context, chatID int64, text string, keyboard [][]InlineKeyboardButton) error {
	if chatID == 0 || strings.TrimSpace(text) == "" {
		return fmt.Errorf("invalid telegram message")
	}
	type encodedButton struct {
		Text         string `json:"text"`
		CallbackData string `json:"callback_data"`
	}
	request := struct {
		ChatID      int64  `json:"chat_id"`
		Text        string `json:"text"`
		ReplyMarkup *struct {
			InlineKeyboard [][]encodedButton `json:"inline_keyboard"`
		} `json:"reply_markup,omitempty"`
	}{ChatID: chatID, Text: text}
	if len(keyboard) > 0 {
		markup := struct {
			InlineKeyboard [][]encodedButton `json:"inline_keyboard"`
		}{}
		for _, row := range keyboard {
			encoded := make([]encodedButton, 0, len(row))
			for _, button := range row {
				encoded = append(encoded, encodedButton(button))
			}
			markup.InlineKeyboard = append(markup.InlineKeyboard, encoded)
		}
		request.ReplyMarkup = &markup
	}
	return c.postMethod(ctx, "sendMessage", request)
}

// AnswerCallbackQuery dismisses a button tap. The notice must stay generic.
func (c *Client) AnswerCallbackQuery(ctx context.Context, callbackID, text string) error {
	if strings.TrimSpace(callbackID) == "" {
		return fmt.Errorf("invalid telegram callback")
	}
	return c.postMethod(ctx, "answerCallbackQuery", struct {
		CallbackQueryID string `json:"callback_query_id"`
		Text            string `json:"text,omitempty"`
	}{CallbackQueryID: callbackID, Text: text})
}

func (c *Client) postMethod(ctx context.Context, methodName string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram %s failed", methodName)
	}
	var decoded struct {
		OK bool `json:"ok"`
	}
	if err := c.postJSON(ctx, methodName, body, &decoded); err != nil {
		return err
	}
	if !decoded.OK {
		return fmt.Errorf("invalid telegram %s response", methodName)
	}
	return nil
}

func (c *Client) postJSON(ctx context.Context, methodName string, body []byte, decoded any) error {
	target := *c.base
	target.Path = strings.TrimRight(target.Path, "/") + "/bot" + c.token + "/" + methodName
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram %s failed", methodName)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("telegram %s failed", methodName)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return readBotAPIStatus(response, methodName)
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxBotResponseBytes+1))
	if err != nil || len(responseBody) > maxBotResponseBytes || json.Unmarshal(responseBody, decoded) != nil {
		return fmt.Errorf("invalid telegram %s response", methodName)
	}
	return nil
}

func readBotAPIStatus(response *http.Response, methodName string) BotAPIStatusError {
	result := BotAPIStatusError{Method: methodName, Status: response.StatusCode}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBotResponseBytes+1))
	if err != nil || len(body) > maxBotResponseBytes {
		return result
	}
	var decoded struct {
		Description string `json:"description"`
	}
	if json.Unmarshal(body, &decoded) != nil {
		return result
	}
	description := strings.ToLower(strings.TrimSpace(decoded.Description))
	if methodName == "sendRichMessage" && (description == "bad request: message thread not found" || description == "bad request: message thread is not found" || description == "bad request: topic was deleted") {
		result.Kind = BotAPIErrorDeletedTopic
	}
	return result
}
