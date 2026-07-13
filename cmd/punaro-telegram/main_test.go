package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestParseRouteRequiresExactTopicAndConversation(t *testing.T) {
	request, err := parseRoute([]string{"--chat-id", "100", "--thread-id", "7", "--conversation", "conversation-1"})
	if err != nil || request.chatID != 100 || request.threadID != 7 || request.conversation != "conversation-1" {
		t.Fatalf("route=%#v err=%v", request, err)
	}
	if _, err := parseRoute([]string{"--chat-id", "100", "--conversation", "conversation-1"}); err == nil {
		t.Fatal("route without thread ID accepted")
	}
}

func TestLoadConfigRequiresExplicitTelegramGatewayIdentity(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "machine.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUNARO_ADAPTER_RELAY_URL", "https://relay.example")
	t.Setenv("PUNARO_MACHINE_ID", "telegram-machine")
	t.Setenv("PUNARO_MACHINE_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("PUNARO_TELEGRAM_BOT_TOKEN", "test-token")
	t.Setenv("PUNARO_TELEGRAM_ALLOWED_USER_ID", "55")
	t.Setenv("PUNARO_TELEGRAM_GATEWAY_ENDPOINT", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("gateway endpoint defaulted instead of requiring explicit enrollment namespace")
	}
}
