package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

func TestParseSendArgsRequiresExplicitIdempotencyKey(t *testing.T) {
	if _, err := parseSendArgs([]string{"--conversation", "conversation-1", "--from", "agent/a", "--body-file", "-"}); err == nil {
		t.Fatal("send without idempotency key was accepted")
	}
	request, err := parseSendArgs([]string{"--conversation", "conversation-1", "--from", "agent/a", "--body-file", "-", "--idempotency-key", "reply-1"})
	if err != nil || request.conversationID != "conversation-1" || request.idempotencyKey != "reply-1" {
		t.Fatalf("send request did not parse")
	}
}

func TestParseAttachmentNotifyArgsRequiresStableOfferHandoff(t *testing.T) {
	if _, err := parseAttachmentNotifyArgs([]string{"--conversation", "conversation-1", "--from", "agent/a", "--offer-file", "offer.cbor"}); err == nil {
		t.Fatal("attachment notify without idempotency key was accepted")
	}
	request, err := parseAttachmentNotifyArgs([]string{"--conversation", "conversation-1", "--from", "agent/a", "--offer-file", "offer.cbor", "--idempotency-key", "offer-transfer-1"})
	if err != nil || request.offerFile != "offer.cbor" || request.idempotencyKey != "offer-transfer-1" {
		t.Fatalf("attachment notify request did not parse: %#v err=%v", request, err)
	}
}

func TestParseCreateArgsRequiresExplicitMembership(t *testing.T) {
	request, err := parseCreateArgs([]string{"--creator", "agent/a", "--member", "agent/a:send,receive,admin", "--member", "agent/b:receive", "--idempotency-key", "create-1"})
	if err != nil || len(request.members) != 2 || request.idempotencyKey != "create-1" {
		t.Fatalf("create request did not parse")
	}
	if _, err := parseCreateArgs([]string{"--creator", "agent/a", "--idempotency-key", "create-1"}); err == nil {
		t.Fatal("create without members accepted")
	}
}

func TestParseInvokeArgsRequiresExplicitContentFreeTargetAndRetryKey(t *testing.T) {
	if _, err := parseInvokeArgs([]string{"--conversation", "conversation-1", "--from", "agent/a", "--target", "agent/b"}); err == nil {
		t.Fatal("invoke without idempotency key was accepted")
	}
	request, err := parseInvokeArgs([]string{"--conversation", "conversation-1", "--from", "agent/a", "--target", "agent/b", "--idempotency-key", "invoke-1"})
	if err != nil || request.conversationID != "conversation-1" || request.fromEndpoint != "agent/a" || request.targetEndpoint != "agent/b" || request.idempotencyKey != "invoke-1" {
		t.Fatalf("invoke request did not parse: %#v err=%v", request, err)
	}
}

func TestLoadConfigRequiresPrivateKeyAndAttachmentGroup(t *testing.T) {
	clearAdapterEnvironment(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PUNARO_ADAPTER_RELAY_URL", "https://relay.example")
	t.Setenv("PUNARO_MACHINE_ID", "machine-a")
	t.Setenv("PUNARO_MACHINE_PRIVATE_KEY_FILE", "")
	t.Setenv("PUNARO_ATTACHED_GROUP", "group/punaro")
	if _, err := loadConfig(); err == nil {
		t.Fatal("missing private key file accepted")
	}
}

func TestLoadConfigLoadsPrivateKeyWithoutLoggingIt(t *testing.T) {
	clearAdapterEnvironment(t)
	t.Setenv("HOME", t.TempDir())
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "machine.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUNARO_ADAPTER_RELAY_URL", "https://relay.example")
	t.Setenv("PUNARO_MACHINE_ID", "machine-a")
	t.Setenv("PUNARO_MACHINE_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("PUNARO_ATTACHED_GROUP", "group/punaro")
	t.Setenv("PUNARO_ADAPTER_DATA_DIR", t.TempDir())
	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.machineID != "machine-a" || len(config.privateKey) != ed25519.PrivateKeySize || config.pollInterval <= 0 {
		t.Fatalf("unexpected non-secret adapter configuration")
	}
}

func TestLoadPrivateKeyRejectsUnsafeFileModesAndSymlinks(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	keyFile := filepath.Join(directory, "machine.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- this test deliberately makes the credential group-readable.
	if err := os.Chmod(keyFile, 0o640); err != nil {
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

func TestDirectCommandsLoadInstallerProfileBeforeTheirTransportBoundary(t *testing.T) {
	clearAdapterEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Punaro-Machine") != "profile-machine" {
			t.Fatal("direct command did not use the profile machine identity")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/conversations":
			_, _ = w.Write([]byte(`{"id":"conversation-1"}`))
		case "/v1/conversations/conversation-1/messages":
			_, _ = w.Write([]byte(`{"id":"message-1","conversation_id":"conversation-1","sequence":1,"from_endpoint":"agent/a","body":"ignored","created_at":"2026-08-03T00:00:00Z"}`))
		default:
			t.Fatalf("unexpected transport boundary %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))
	bodyFile := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(bodyFile, []byte("profile-backed direct send"), 0o600); err != nil {
		t.Fatal(err)
	}
	offerFile := filepath.Join(t.TempDir(), "offer.cde")
	if err := os.WriteFile(offerFile, testOfferPayload(t), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runCreate([]string{"--creator", "agent/a", "--member", "agent/a:send,receive,admin", "--idempotency-key", "create-1"}); err != nil {
		t.Fatalf("create did not reach its transport boundary: %v", err)
	}
	if err := runSend([]string{"--conversation", "conversation-1", "--from", "agent/a", "--body-file", bodyFile, "--idempotency-key", "send-1"}); err != nil {
		t.Fatalf("send did not reach its transport boundary: %v", err)
	}
	if err := runAttachmentNotify([]string{"--conversation", "conversation-1", "--from", "agent/a", "--offer-file", offerFile, "--idempotency-key", "offer-1"}); err != nil {
		t.Fatalf("attachment-notify did not reach its transport boundary: %v", err)
	}
}

func TestLoadConfigFailsClosedForUnsafeOrMalformedProfileWithoutLeakingItsContents(t *testing.T) {
	clearAdapterEnvironment(t)
	secret := "profile-secret-must-not-appear"
	profile := filepath.Join(t.TempDir(), "adapter.env")
	if err := os.WriteFile(profile, []byte("PUNARO_CF_ACCESS_CLIENT_SECRET="+secret+"\nnot-valid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUNARO_ADAPTER_PROFILE_FILE", profile)
	// #nosec G302 -- this fixture deliberately makes the profile group-readable.
	if err := os.Chmod(profile, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("group-readable profile error=%v", err)
	}
	if err := os.Chmod(profile, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("malformed profile error=%v", err)
	}
	symlink := filepath.Join(t.TempDir(), "adapter-link")
	if err := os.Symlink(profile, symlink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUNARO_ADAPTER_PROFILE_FILE", symlink)
	if _, err := loadConfig(); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("symlinked profile error=%v", err)
	}
}

func TestEnvironmentSettingsExplicitlyOverrideInstalledProfile(t *testing.T) {
	clearAdapterEnvironment(t)
	profile := writeInstallerProfile(t, "https://profile.example")
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))
	t.Setenv("PUNARO_MACHINE_ID", "explicit-machine")
	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.machineID != "explicit-machine" {
		t.Fatalf("machine ID=%q, want explicit override", config.machineID)
	}
}

func writeInstallerProfile(t *testing.T, relayURL string) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	configDir := filepath.Join(home, ".config", "punaro")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(configDir, "machine.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(home, ".local", "state", "punaro-adapter")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(configDir, "adapter.env")
	contents := strings.Join([]string{
		"# Created by the installer.",
		"PUNARO_ADAPTER_RELAY_URL=" + relayURL,
		"PUNARO_MACHINE_ID=profile-machine",
		"PUNARO_MACHINE_PRIVATE_KEY_FILE=" + keyFile,
		"PUNARO_ATTACHED_GROUP=group/punaro-attached",
		"PUNARO_ADAPTER_DATA_DIR=" + dataDir,
		"PUNARO_MAILBOX_STATE_DIR=" + filepath.Join(home, ".local", "state", "ai-agent", "mailbox"),
		"PUNARO_ADAPTER_POLL_INTERVAL=30s",
		"PUNARO_AGENT_MAILBOX_BIN=agent-mailbox",
		"",
	}, "\n")
	if err := os.WriteFile(profile, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return profile
}

func clearAdapterEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv(adapterProfileFileEnv, "")
	for key := range adapterProfileKeys {
		t.Setenv(key, "")
	}
}

func testOfferPayload(t *testing.T) []byte {
	t.Helper()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	manifest := attachmentv3.Manifest{Audience: [32]byte{1}, TransferID: [16]byte{2}, ConversationID: [16]byte{3}, SenderDeviceID: [16]byte{4}, SenderGeneration: 1, RecipientDeviceID: [16]byte{5}, RecipientGeneration: 1, DirectoryHead: [32]byte{6}, MembershipCommitment: [32]byte{7}, RevocationEpoch: 1, IssuedAt: 1, ExpiresAt: 2, ContentSalt: [32]byte{8}, PlaintextCommitment: [32]byte{9}, ChunkSize: 1, ChunkCount: 1, PlaintextSize: 1, SignerKeyID: [32]byte{10}}
	if err := attachmentv3.SignManifest(&manifest, private); err != nil {
		t.Fatal(err)
	}
	rawManifest, err := attachmentv3.EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	envelope := attachmentv3.Envelope{Audience: manifest.Audience, TransferID: manifest.TransferID, ConversationID: manifest.ConversationID, SenderDeviceID: manifest.SenderDeviceID, SenderGeneration: manifest.SenderGeneration, RecipientDeviceID: manifest.RecipientDeviceID, RecipientGeneration: manifest.RecipientGeneration, RecipientHPKEKeyID: [32]byte{11}, ManifestCommitment: blake3.Sum256(rawManifest), EncapsulatedKey: [32]byte{12}, Ciphertext: make([]byte, 16), SignerKeyID: manifest.SignerKeyID}
	if err := attachmentv3.SignEnvelope(&envelope, private); err != nil {
		t.Fatal(err)
	}
	offer, err := attachmentv3.EncodeOfferPayload(manifest, envelope, [32]byte{13})
	if err != nil {
		t.Fatal(err)
	}
	return offer
}
