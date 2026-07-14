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

func TestLoadPrivateKeyRejectsUnsafeFileModesAndSymlinks(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	keyFile := filepath.Join(directory, "machine.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPrivateKey(keyFile); err == nil {
		t.Fatal("group-readable private key accepted")
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "machine-link")
	if err := os.Symlink(keyFile, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPrivateKey(symlink); err == nil {
		t.Fatal("symlinked private key accepted")
	}
}

func TestLoadConfigReadsBotTokenFromPrivateCredentialFile(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	keyFile := filepath.Join(directory, "machine.key")
	botTokenFile := filepath.Join(directory, "bot-token")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(botTokenFile, []byte("bot-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUNARO_ADAPTER_RELAY_URL", "https://relay.example")
	t.Setenv("PUNARO_MACHINE_ID", "telegram-machine")
	t.Setenv("PUNARO_MACHINE_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("PUNARO_TELEGRAM_BOT_TOKEN", "")
	t.Setenv("PUNARO_TELEGRAM_BOT_TOKEN_FILE", botTokenFile)
	t.Setenv("PUNARO_TELEGRAM_ALLOWED_USER_ID", "55")
	t.Setenv("PUNARO_TELEGRAM_GATEWAY_ENDPOINT", "telegram/primary")
	t.Setenv("PUNARO_TELEGRAM_STATE_DIR", directory)
	config, err := loadConfig()
	if err != nil || config.botToken != "bot-token" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	t.Setenv("PUNARO_TELEGRAM_BOT_TOKEN", "also-set")
	if _, err := loadConfig(); err == nil {
		t.Fatal("multiple bot-token sources accepted")
	}
}

func TestLoadConfigReadsAccessPairFromPrivateCredentialFile(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	keyFile := filepath.Join(directory, "machine.key")
	accessFile := filepath.Join(directory, "access-token")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accessFile, []byte("PUNARO_CF_ACCESS_CLIENT_ID=id\nPUNARO_CF_ACCESS_CLIENT_SECRET=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUNARO_ADAPTER_RELAY_URL", "https://relay.example")
	t.Setenv("PUNARO_MACHINE_ID", "telegram-machine")
	t.Setenv("PUNARO_MACHINE_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("PUNARO_TELEGRAM_BOT_TOKEN", "test-token")
	t.Setenv("PUNARO_TELEGRAM_ALLOWED_USER_ID", "55")
	t.Setenv("PUNARO_TELEGRAM_GATEWAY_ENDPOINT", "telegram/primary")
	t.Setenv("PUNARO_TELEGRAM_STATE_DIR", directory)
	t.Setenv("PUNARO_CF_ACCESS_CLIENT_ID", "")
	t.Setenv("PUNARO_CF_ACCESS_CLIENT_SECRET", "")
	t.Setenv("PUNARO_TELEGRAM_ACCESS_TOKEN_FILE", accessFile)
	config, err := loadConfig()
	if err != nil || config.accessToken.ClientID != "id" || config.accessToken.ClientSecret != "secret" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	t.Setenv("PUNARO_CF_ACCESS_CLIENT_ID", "also-set")
	if _, err := loadConfig(); err == nil {
		t.Fatal("multiple Access credential sources accepted")
	}
}
