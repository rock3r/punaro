package telegram

import (
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

// Client is a narrow Telegram Bot API long-poll client. Its token is retained
// only in memory and is never included in returned errors.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

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
