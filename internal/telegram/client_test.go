package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientFetchesMinimalTopicUpdateWithoutLeakingToken(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/getUpdates" {
			t.Fatal("unexpected request path")
		}
		if r.URL.Query().Get("offset") != "10" {
			t.Fatal("missing offset")
		}
		if r.URL.Query().Get("allowed_updates") != `["message","callback_query"]` {
			t.Fatalf("allowed_updates=%q", r.URL.Query().Get("allowed_updates"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":10,"message":{"message_id":4,"from":{"id":55},"chat":{"id":100},"message_thread_id":7,"text":"question"}}]}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	updates, err := client.Updates(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 1 || updates[0].ID != 10 || updates[0].UserID != 55 || updates[0].ThreadID != 7 || updates[0].MessageID != 4 || updates[0].Text != "question" || updates[0].IsCommand {
		t.Fatalf("updates=%#v", updates)
	}
}

func TestClientPreservesMessageLessUpdateIDsForOffsetProgress(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[` +
			`{"update_id":10,"edited_message":{"message_id":3}},` +
			`{"update_id":11,"message":{"message_id":4,"from":{"id":55},"chat":{"id":100},"message_thread_id":7,"text":"later"}}` +
			`]}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	updates, err := client.Updates(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 2 || updates[0].ID != 10 || updates[0].Text != "" || updates[1].ID != 11 || updates[1].Text != "later" {
		t.Fatalf("updates=%#v", updates)
	}
}

func TestClientDoctorUsesNonMutatingGetMeAndRedactsProviderResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/botsecret/getMe" {
			t.Fatalf("unexpected doctor request %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"id":42,"username":"provider-controlled"}}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Doctor(context.Background()); err != nil {
		t.Fatal(err)
	}

	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"description":"secret provider body"}`))
	})
	err = client.Doctor(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("unsafe doctor error %q", err)
	}
}

func TestClientDoctorRejectsOversizedOrCancelledProviderResponseWithoutLeakingIt(t *testing.T) {
	const providerText = "provider-controlled-secret"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true,"result":{"id":42}}`+strings.Repeat(providerText, maxBotResponseBytes))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Doctor(context.Background()); err == nil || strings.Contains(err.Error(), providerText) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe oversized doctor error %q", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Doctor(ctx); err == nil || strings.Contains(err.Error(), server.URL) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe cancelled doctor error %q", err)
	}
}

func TestBotAPIStatusClassificationKeepsAmbiguousResponsesRetryableAndDetectsDeletedTopic(t *testing.T) {
	if PermanentBotAPIFailure(BotAPIStatusError{Method: "sendRichMessage", Status: http.StatusUnauthorized}) {
		t.Fatal("Telegram 401 was made terminal")
	}
	if PermanentBotAPIFailure(BotAPIStatusError{Method: "sendRichMessage", Status: http.StatusNotFound}) {
		t.Fatal("ambiguous Telegram 404 was made terminal")
	}
	if !PermanentBotAPIFailure(BotAPIStatusError{Method: "sendRichMessage", Status: http.StatusForbidden}) {
		t.Fatal("Telegram 403 was not terminal")
	}
	if !DeletedTopicFailure(BotAPIStatusError{Method: "sendRichMessage", Status: http.StatusBadRequest, Kind: BotAPIErrorDeletedTopic}) {
		t.Fatal("deleted topic was not classified")
	}
}

func TestClientPollsCallbackQueriesAndBotCommands(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botsecret/getUpdates" {
			t.Fatal("unexpected request path")
		}
		if r.URL.Query().Get("allowed_updates") != `["message","callback_query"]` {
			t.Fatalf("allowed_updates=%q", r.URL.Query().Get("allowed_updates"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[` +
			`{"update_id":11,"message":{"message_id":5,"from":{"id":55},"chat":{"id":55},"text":"/start@TopicBot extra","entities":[{"offset":0,"length":16,"type":"bot_command"}]}},` +
			`{"update_id":12,"message":{"message_id":6,"from":{"id":55},"chat":{"id":55},"text":"/list","entities":[{"offset":0,"length":5,"type":"bot_command"}]}},` +
			`{"update_id":13,"message":{"message_id":7,"from":{"id":55},"chat":{"id":100},"message_thread_id":7,"text":"/list"}},` +
			`{"update_id":14,"callback_query":{"id":"cbq-1","from":{"id":55},"data":"opaque-token","message":{"message_id":8,"chat":{"id":55}}}},` +
			`{"update_id":15,"message":{"message_id":9,"from":{"id":55},"chat":{"id":100},"message_thread_id":7,"text":"hi","reply_to_message":{"message_id":3}}},` +
			`{"update_id":16,"message":{"message_id":10,"from":{"id":55},"chat":{"id":55},"text":"please /list the topics","entities":[{"offset":7,"length":5,"type":"bot_command"}]}}` +
			`]}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	updates, err := client.Updates(context.Background(), 11)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 6 {
		t.Fatalf("updates=%#v", updates)
	}
	if !updates[0].IsCommand || updates[0].Command != "start" || updates[0].ChatID != 55 || updates[0].MessageID != 5 {
		t.Fatalf("start=%#v", updates[0])
	}
	if !updates[1].IsCommand || updates[1].Command != "list" {
		t.Fatalf("list=%#v", updates[1])
	}
	if updates[2].IsCommand || updates[2].Command != "" || updates[2].Text != "/list" {
		t.Fatalf("slash text without entity was treated as a command: %#v", updates[2])
	}
	if updates[3].CallbackID != "cbq-1" || updates[3].CallbackData != "opaque-token" || updates[3].UserID != 55 || updates[3].ChatID != 55 || updates[3].MessageID != 8 {
		t.Fatalf("callback=%#v", updates[3])
	}
	if updates[4].ReplyToID != 3 || updates[4].IsCommand {
		t.Fatalf("reply=%#v", updates[4])
	}
	if updates[5].IsCommand || updates[5].Command != "" || updates[5].Text != "please /list the topics" {
		t.Fatalf("mid-text bot_command was treated as a command: %#v", updates[5])
	}
}

func TestClientRegistersCommandsAndSendsOperatorMessages(t *testing.T) {
	t.Parallel()
	seen := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		seen[r.URL.Path]++
		switch r.URL.Path {
		case "/botsecret/setMyCommands":
			var request struct {
				Commands []struct {
					Command     string `json:"command"`
					Description string `json:"description"`
				} `json:"commands"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if len(request.Commands) != 2 || request.Commands[0].Command != "start" || request.Commands[0].Description != "How this bot works" || request.Commands[1].Command != "list" || request.Commands[1].Description != "Claim an unclaimed Punaro topic" {
				t.Fatalf("commands=%#v", request.Commands)
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		case "/botsecret/sendMessage":
			var request struct {
				ChatID      int64  `json:"chat_id"`
				Text        string `json:"text"`
				ParseMode   string `json:"parse_mode"`
				ReplyMarkup *struct {
					InlineKeyboard [][]struct {
						Text         string `json:"text"`
						CallbackData string `json:"callback_data"`
					} `json:"inline_keyboard"`
				} `json:"reply_markup"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.ChatID != 55 || request.Text != "Tap a topic to claim it." || request.ParseMode != "" || request.ReplyMarkup == nil || len(request.ReplyMarkup.InlineKeyboard) != 1 || request.ReplyMarkup.InlineKeyboard[0][0].Text != "How is it going" || request.ReplyMarkup.InlineKeyboard[0][0].CallbackData != "token-1" {
				t.Fatalf("sendMessage=%#v", request)
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":20}}`))
		case "/botsecret/answerCallbackQuery":
			var request struct {
				CallbackQueryID string `json:"callback_query_id"`
				Text            string `json:"text"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.CallbackQueryID != "cbq-1" || request.Text != callbackFailureText {
				t.Fatalf("answerCallbackQuery=%#v", request)
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetMyCommands(context.Background(), DefaultBotCommands()); err != nil {
		t.Fatal(err)
	}
	if err := client.SendMessage(context.Background(), 55, "Tap a topic to claim it.", [][]InlineKeyboardButton{{{Text: "How is it going", CallbackData: "token-1"}}}); err != nil {
		t.Fatal(err)
	}
	if err := client.AnswerCallbackQuery(context.Background(), "cbq-1", callbackFailureText); err != nil {
		t.Fatal(err)
	}
	if seen["/botsecret/setMyCommands"] != 1 || seen["/botsecret/sendMessage"] != 1 || seen["/botsecret/answerCallbackQuery"] != 1 {
		t.Fatalf("seen=%#v", seen)
	}
}

func TestClientSendsThreadBoundRichMessageWithoutAutomaticEntities(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/botsecret/sendRichMessage" {
			t.Fatal("unexpected rich-message request")
		}
		defer func() { _ = r.Body.Close() }()
		var request struct {
			ChatID          int64 `json:"chat_id"`
			MessageThreadID int64 `json:"message_thread_id"`
			RichMessage     struct {
				HTML                string `json:"html"`
				SkipEntityDetection bool   `json:"skip_entity_detection"`
			} `json:"rich_message"`
			ProtectContent bool `json:"protect_content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.ChatID != 100 || request.MessageThreadID != 7 || request.RichMessage.HTML != "<p>safe</p>" || !request.RichMessage.SkipEntityDetection || !request.ProtectContent {
			t.Fatalf("rich request=%#v", request)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":9}}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	messageID, err := client.SendRichMessage(context.Background(), 100, 7, "<p>safe</p>")
	if err != nil || messageID != 9 {
		t.Fatalf("message_id=%d err=%v", messageID, err)
	}
}

func TestClientCreateForumTopicReturnsThreadIDWithoutGetForumTopic(t *testing.T) {
	t.Parallel()
	seen := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path]++
		if r.Method != http.MethodPost || r.URL.Path != "/botsecret/createForumTopic" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		defer func() { _ = r.Body.Close() }()
		var request struct {
			ChatID int64  `json:"chat_id"`
			Name   string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.ChatID != 55 || request.Name != "How is it going" {
			t.Fatalf("createForumTopic=%#v", request)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_thread_id":795446,"name":"How is it going"}}`))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	threadID, err := client.CreateForumTopic(context.Background(), 55, "How is it going")
	if err != nil || threadID != 795446 {
		t.Fatalf("thread_id=%d err=%v", threadID, err)
	}
	if seen["/botsecret/getForumTopic"] != 0 || seen["/botsecret/createForumTopic"] != 1 {
		t.Fatalf("seen=%#v", seen)
	}
}

type urlErrorTransport struct{}

func (urlErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf(`Get %q: connection refused`, req.URL.String())
}

func TestClientOmitsBotTokenFromTransportErrors(t *testing.T) {
	t.Parallel()
	const dummy = "dummy-bot-token-do-not-leak" // #nosec G101 -- non-secret leak-suppression fixture.
	client, err := NewClient("https://api.telegram.org", dummy, &http.Client{Transport: urlErrorTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Updates(context.Background(), 0)
	if err == nil {
		t.Fatal("expected poll transport error")
	}
	if strings.Contains(err.Error(), dummy) {
		t.Fatalf("poll error leaked bot token: %v", err)
	}
	_, err = client.SendRichMessage(context.Background(), 100, 7, "<p>safe</p>")
	if err == nil {
		t.Fatal("expected send transport error")
	}
	if strings.Contains(err.Error(), dummy) {
		t.Fatalf("send error leaked bot token: %v", err)
	}
	_, err = client.CreateForumTopic(context.Background(), 55, "How is it going")
	if err == nil {
		t.Fatal("expected createForumTopic transport error")
	}
	if strings.Contains(err.Error(), dummy) || strings.Contains(err.Error(), "bot") {
		t.Fatalf("createForumTopic error leaked bot token: %v", err)
	}
	for _, name := range []string{"setMyCommands", "sendMessage", "answerCallbackQuery"} {
		var opErr error
		switch name {
		case "setMyCommands":
			opErr = client.SetMyCommands(context.Background(), DefaultBotCommands())
		case "sendMessage":
			opErr = client.SendMessage(context.Background(), 55, "help", nil)
		case "answerCallbackQuery":
			opErr = client.AnswerCallbackQuery(context.Background(), "cbq-1", callbackFailureText)
		}
		if opErr == nil {
			t.Fatalf("expected %s transport error", name)
		}
		if strings.Contains(opErr.Error(), dummy) || strings.Contains(opErr.Error(), "bot") {
			t.Fatalf("%s error leaked bot token: %v", name, opErr)
		}
	}
}

func TestClientRejectsUnsafeAPIRoots(t *testing.T) {
	t.Parallel()
	for _, rawURL := range []string{
		"http://api.telegram.org",
		"https://user:password@api.telegram.org",
		"https://api.telegram.org/prefix",
		"https://api.telegram.org?redirect=elsewhere",
	} {
		if _, err := NewClient(rawURL, "token", nil); err == nil {
			t.Fatalf("unsafe Telegram API URL accepted: %q", rawURL)
		}
	}
}
