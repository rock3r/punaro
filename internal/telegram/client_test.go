package telegram

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientFetchesMinimalTopicUpdateWithoutLeakingToken(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
