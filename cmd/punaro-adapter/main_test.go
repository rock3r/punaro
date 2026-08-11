package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/relay"
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

func TestParseSendArgsAcceptsOneOptionalTargetRole(t *testing.T) {
	request, err := parseSendArgs([]string{"--conversation", "conversation-1", "--from", "agent/a", "--body-file", "-", "--idempotency-key", "reply-1", "--target-role", "role/reviewer"})
	if err != nil || request.targetRole != "role/reviewer" {
		t.Fatalf("targeted send request=%#v err=%v", request, err)
	}
	if _, err := parseSendArgs([]string{"--conversation", "conversation-1", "--from", "agent/a", "--body-file", "-", "--idempotency-key", "reply-1", "--target-role", " role/reviewer"}); err == nil {
		t.Fatal("non-canonical target role was accepted")
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

func TestParseCreateArgsAcceptsDurableRoleMemberAndBinding(t *testing.T) {
	request, err := parseCreateArgs([]string{"--creator", "agent/a", "--role-member", `{"role":"role/plan-reviewer","machine_id":"machine-b","capabilities":["send","receive"]}`, "--idempotency-key", "create-role-1"})
	if err != nil || len(request.members) != 1 || request.members[0].Role != "role/plan-reviewer" || request.members[0].RoleMachineID != "machine-b" {
		t.Fatalf("role member request=%#v err=%v", request, err)
	}
	request, err = parseCreateArgs([]string{"--creator", "agent/a", "--role-member", `{"role":"ops@west","machine_id":"machine:a","capabilities":["receive"]}`, "--idempotency-key", "create-role-delimiters"})
	if err != nil || len(request.members) != 1 || request.members[0].Role != "ops@west" || request.members[0].RoleMachineID != "machine:a" {
		t.Fatalf("delimited role member request=%#v err=%v", request, err)
	}
	if _, err := parseCreateArgs([]string{"--creator", "agent/a", "--role-member", "role/plan-reviewer@machine-b:receive", "--idempotency-key", "create-role-legacy"}); err == nil {
		t.Fatal("ambiguous legacy role-member was accepted")
	}
	if _, err := parseCreateArgs([]string{"--creator", "agent/a", "--role-member", `{"role":"role/plan-reviewer","machine_id":"machine-b","capabilities":["receive","invoke"]}`, "--idempotency-key", "create-role-invoke"}); err == nil {
		t.Fatal("role member with invoke capability was accepted")
	}
	binding, err := parseBindRoleArgs([]string{"--role", "role/plan-reviewer", "--session", "agent/b/new-session"})
	if err != nil || binding.role != "role/plan-reviewer" || binding.session != "agent/b/new-session" {
		t.Fatalf("role binding=%#v err=%v", binding, err)
	}
	if _, err := parseBindRoleArgs([]string{"--role", "role/plan-reviewer"}); err == nil {
		t.Fatal("incomplete role binding accepted")
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

func TestParseMemberControlArgsRequiresExplicitActorAndRetryKey(t *testing.T) {
	request, err := parseMemberSetArgs([]string{"--conversation", "conversation-1", "--actor", "agent/a", "--member", "agent/b:receive", "--idempotency-key", "control-1"})
	if err != nil || request.actor != "agent/a" || request.member.Endpoint != "agent/b" || request.member.Capabilities != relay.CapReceive {
		t.Fatalf("member set=%#v err=%v", request, err)
	}
	request, err = parseMemberSetArgs([]string{"--conversation", "conversation-1", "--actor", "agent/a", "--member", "role:reviewer:receive", "--idempotency-key", "control-colon"})
	if err != nil || request.member.Endpoint != "role:reviewer" || request.member.Capabilities != relay.CapReceive {
		t.Fatalf("member set with colon endpoint=%#v err=%v", request, err)
	}
	request, err = parseMemberRemoveArgs([]string{"--conversation", "conversation-1", "--actor", "agent/a", "--member", "role:reviewer", "--idempotency-key", "control-remove-colon"})
	if err != nil || request.member.Endpoint != "role:reviewer" {
		t.Fatalf("member remove with colon endpoint=%#v err=%v", request, err)
	}
	if _, err := parseMemberRemoveArgs([]string{"--conversation", "conversation-1", "--actor", "agent/a", "--member", "agent/b"}); err == nil {
		t.Fatal("member remove without stable retry key accepted")
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

func TestMailboxMCPCommandUsesInstalledNonDefaultState(t *testing.T) {
	clearAdapterEnvironment(t)
	profile := filepath.Join(t.TempDir(), "adapter.env")
	mailboxState := filepath.Join(t.TempDir(), "custom-mailbox")
	mailboxBinary := filepath.Join(t.TempDir(), "agent-mailbox")
	contents := strings.Join([]string{
		"PUNARO_MAILBOX_STATE_DIR=" + mailboxState,
		"PUNARO_AGENT_MAILBOX_BIN=" + mailboxBinary,
		"",
	}, "\n")
	if err := os.WriteFile(profile, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(adapterProfileFileEnv, profile)

	command, err := mailboxMCPCommand()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(command, "\x00"), strings.Join([]string{mailboxBinary, "--state-dir", mailboxState, "mcp"}, "\x00"); got != want {
		t.Fatalf("mailbox MCP command = %q, want %q", got, want)
	}
}

func TestMailboxMCPCommandFailsClosedWithoutConfiguredState(t *testing.T) {
	clearAdapterEnvironment(t)
	t.Setenv(adapterProfileFileEnv, filepath.Join(t.TempDir(), "missing.env"))
	if _, err := mailboxMCPCommand(); err == nil {
		t.Fatal("missing adapter profile was accepted")
	}
}

func TestMailboxMCPShutdownIsClean(t *testing.T) {
	if os.Getenv("PUNARO_TEST_MAILBOX_MCP_HELPER") == "1" {
		ready := os.Getenv("PUNARO_TEST_MAILBOX_MCP_READY")
		if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil { // #nosec G703 -- parent test selects this private readiness fixture.
			os.Exit(2)
		}
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt)
		<-signals
		os.Exit(0)
	}

	ready := filepath.Join(t.TempDir(), "ready")
	t.Setenv("PUNARO_TEST_MAILBOX_MCP_HELPER", "1")
	t.Setenv("PUNARO_TEST_MAILBOX_MCP_READY", ready)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runMailboxMCPProcess(ctx, []string{os.Args[0], "-test.run=^TestMailboxMCPShutdownIsClean$"})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("mailbox MCP helper did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("normal mailbox MCP shutdown failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mailbox MCP shutdown did not complete")
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

func TestLoadConfigRequiresCompleteExplicitLANPolicy(t *testing.T) {
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
	t.Setenv("PUNARO_ADAPTER_RELAY_URL", "http://192.168.1.4:8080")
	t.Setenv("PUNARO_MACHINE_ID", "machine-a")
	t.Setenv("PUNARO_MACHINE_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("PUNARO_ATTACHED_GROUP", "group/punaro")
	t.Setenv("PUNARO_ADAPTER_ALLOW_LAN_HTTP", "true")
	if _, err := loadConfig(); err == nil {
		t.Fatal("LAN acknowledgement without a CIDR was accepted")
	}
	t.Setenv("PUNARO_ADAPTER_TRUSTED_LAN_CIDR", "192.168.1.0/24")
	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !config.transportPolicy.AllowLANHTTP || config.transportPolicy.TrustedLANCIDR != "192.168.1.0/24" {
		t.Fatalf("transport policy=%#v", config.transportPolicy)
	}
}

func TestValidateRelayTransportRejectsUnsafeLANBeforeInstallation(t *testing.T) {
	if err := validateRelayTransport([]string{"--relay-url", "http://192.168.1.4:8080", "--allow-lan-http", "--trusted-lan-cidr", "192.168.1.0/24"}); err != nil {
		t.Fatalf("valid LAN transport rejected: %v", err)
	}
	for name, args := range map[string][]string{
		"dns":          {"--relay-url", "http://punaro.lan:8080", "--allow-lan-http", "--trusted-lan-cidr", "192.168.1.0/24"},
		"public":       {"--relay-url", "http://203.0.113.4:8080", "--allow-lan-http", "--trusted-lan-cidr", "203.0.113.0/24"},
		"outside cidr": {"--relay-url", "http://192.168.2.4:8080", "--allow-lan-http", "--trusted-lan-cidr", "192.168.1.0/24"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRelayTransport(args); err == nil {
				t.Fatal("unsafe LAN transport accepted")
			}
		})
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
		case "/v1/conversations/conversation-1/invocations":
			_, _ = w.Write([]byte(`{"id":"invocation-1","status":"pending"}`))
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
	if err := runInvoke([]string{"--conversation", "conversation-1", "--from", "agent/a", "--target", "agent/b", "--idempotency-key", "invoke-1"}); err != nil {
		t.Fatalf("invoke did not reach its transport boundary: %v", err)
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

func TestLoadConfigRequiresMatchingOptInClientIdentityBeforeTransport(t *testing.T) {
	clearAdapterEnvironment(t)
	profile := writeInstallerProfile(t, "https://relay.example")
	identity := filepath.Join(filepath.Dir(profile), "client-identity.json")
	const binding = "11111111-1111-4111-8111-111111111111"
	if err := os.WriteFile(identity, []byte(`{"version":1,"origin":"https://relay.example","client_binding":"`+binding+`","legacy_machine_id":"profile-machine"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	profileContents, err := os.ReadFile(profile) // #nosec G304 -- test fixture path from writeInstallerProfile.
	if err != nil {
		t.Fatal(err)
	}
	profileContents = append(profileContents, []byte("PUNARO_CLIENT_IDENTITY_FILE="+identity+"\nPUNARO_CLIENT_BINDING="+binding+"\n")...)
	if err := os.WriteFile(profile, profileContents, 0o600); err != nil { // #nosec G703 -- test fixture path from writeInstallerProfile.
		t.Fatal(err)
	}
	t.Setenv(adapterProfileFileEnv, profile)
	if _, err := loadConfig(); err != nil {
		t.Fatalf("matching identity state rejected: %v", err)
	}
	if err := os.WriteFile(identity, []byte(`{"version":1,"origin":"https://other.example","client_binding":"`+binding+`","legacy_machine_id":"profile-machine"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(); err == nil || strings.Contains(err.Error(), "other.example") {
		t.Fatalf("cross-origin identity state error=%v", err)
	}
	if err := os.WriteFile(identity, []byte(`{"version":1,"origin":"https://relay.example","client_binding":"`+binding+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(); err == nil {
		t.Fatal("fresh identity state unexpectedly matched legacy adapter")
	}
	if err := os.WriteFile(profile, append(profileContents[:len(profileContents)-len("PUNARO_CLIENT_BINDING="+binding+"\n")], nil...), 0o600); err != nil { // #nosec G703 -- test fixture path from writeInstallerProfile.
		t.Fatal(err)
	}
	if _, err := loadConfig(); err == nil {
		t.Fatal("partial identity configuration was accepted")
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
