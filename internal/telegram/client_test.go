package telegram

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":10,"message":{"from":{"id":55},"chat":{"id":100},"message_thread_id":7,"text":"question"}}]}`))
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
	if len(updates) != 1 || updates[0].ID != 10 || updates[0].UserID != 55 || updates[0].ThreadID != 7 || updates[0].Text != "question" {
		t.Fatalf("updates=%#v", updates)
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
	if err := client.SendRichMessage(context.Background(), 100, 7, "<p>safe</p>"); err != nil {
		t.Fatal(err)
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
