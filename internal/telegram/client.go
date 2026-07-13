package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxBotResponseBytes = 1 << 20
const maxRichMessageBytes = 32 << 10

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
	if err != nil || base.Scheme != "https" && base.Scheme != "http" || base.Host == "" || strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("invalid Telegram API configuration")
	}
	if client == nil {
		client = &http.Client{Timeout: 40 * time.Second}
	}
	return &Client{base: base, token: token, http: client}, nil
}

// Updates returns only text messages and their routing metadata. Unknown Bot
// API fields are intentionally ignored; bodies remain opaque text.
func (c *Client) Updates(ctx context.Context, offset int64) ([]Update, error) {
	target := *c.base
	target.Path = strings.TrimRight(target.Path, "/") + "/bot" + c.token + "/getUpdates"
	query := target.Query()
	query.Set("offset", strconv.FormatInt(offset, 10))
	query.Set("timeout", "30")
	query.Set("allowed_updates", `["message"]`)
	target.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build Telegram poll: %w", err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("telegram poll failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("telegram poll returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBotResponseBytes+1))
	if err != nil || len(body) > maxBotResponseBytes {
		return nil, fmt.Errorf("read Telegram poll response")
	}
	var decoded struct {
		OK     bool `json:"ok"`
		Result []struct {
			ID      int64 `json:"update_id"`
			Message *struct {
				From struct {
					ID int64 `json:"id"`
				} `json:"from"`
				Chat struct {
					ID int64 `json:"id"`
				} `json:"chat"`
				ThreadID int64  `json:"message_thread_id"`
				Text     string `json:"text"`
			} `json:"message"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || !decoded.OK {
		return nil, fmt.Errorf("invalid Telegram poll response")
	}
	updates := make([]Update, 0, len(decoded.Result))
	for _, item := range decoded.Result {
		if item.Message != nil {
			updates = append(updates, Update{ID: item.ID, UserID: item.Message.From.ID, ChatID: item.Message.Chat.ID, ThreadID: item.Message.ThreadID, Text: item.Message.Text})
		}
	}
	return updates, nil
}

// SendRichMessage sends trusted, already-rendered HTML to one exact Telegram
// topic. It disables entity detection and protects content so opaque agent
// text cannot create accidental mentions, links, or forwarding paths.
func (c *Client) SendRichMessage(ctx context.Context, chatID, threadID int64, html string) error {
	if chatID == 0 || threadID <= 0 || strings.TrimSpace(html) == "" || len(html) > maxRichMessageBytes {
		return fmt.Errorf("invalid Telegram rich message")
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
		return fmt.Errorf("encode Telegram rich message: %w", err)
	}
	target := *c.base
	target.Path = strings.TrimRight(target.Path, "/") + "/bot" + c.token + "/sendRichMessage"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build Telegram rich message: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("telegram rich message failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram rich message returned HTTP %d", response.StatusCode)
	}
	var decoded struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxBotResponseBytes+1)).Decode(&decoded); err != nil || !decoded.OK {
		return fmt.Errorf("invalid Telegram rich message response")
	}
	return nil
}
