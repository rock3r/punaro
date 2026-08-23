package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/adapter"
	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
	"github.com/rock3r/punaro/internal/relay"
	"github.com/rock3r/punaro/internal/telegram"
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

func TestTelegramServiceBindingRejectsStaleDefinitions(t *testing.T) {
	valid := "[Service]\nExecStart=/usr/local/bin/punaro-telegram\n"
	if !telegramServiceFileBound("linux", valid) {
		t.Fatal("valid system service rejected")
	}
	for _, stale := range []string{
		"[Service]\nExecStart=/home/user/punaro-telegram\n",
		valid + "ExecStart=/usr/local/bin/punaro-telegram\n",
		"[Service]\nExecStart=/usr/local/bin/punaro-adapter\n",
		"[Service]\n# ExecStart=/usr/local/bin/punaro-telegram\nExecStart=/usr/local/bin/punaro-adapter\n",
	} {
		if telegramServiceFileBound("linux", stale) {
			t.Fatalf("stale system service accepted: %q", stale)
		}
	}
}

func TestParseAdoptRequiresConversation(t *testing.T) {
	conversation, err := parseAdopt([]string{"--conversation", "conversation-1"})
	if err != nil || conversation != "conversation-1" {
		t.Fatalf("adopt=%q err=%v", conversation, err)
	}
	if _, err := parseAdopt([]string{}); err == nil {
		t.Fatal("adopt without conversation accepted")
	}
}

func TestRunRouteRefusesClaimedConversation(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("PUNARO_TELEGRAM_STATE_DIR", directory)
	state, err := telegram.Open(filepath.Join(directory, "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetRoute(100, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.AdoptExecution("conversation-1", 7); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkClaimComplete("conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runRoute([]string{"--chat-id", "100", "--thread-id", "8", "--conversation", "conversation-1"}); err == nil {
		t.Fatal("claimed conversation remapped")
	}
	if err := runRoute([]string{"--chat-id", "100", "--thread-id", "7", "--conversation", "conversation-2"}); err == nil {
		t.Fatal("claimed thread stolen")
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

func TestLoadConfigRejectsNonPrimaryGatewayEndpoint(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	keyFile := filepath.Join(directory, "machine.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUNARO_ADAPTER_RELAY_URL", "https://relay.example")
	t.Setenv("PUNARO_MACHINE_ID", "telegram-machine")
	t.Setenv("PUNARO_MACHINE_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("PUNARO_TELEGRAM_BOT_TOKEN", "test-token")
	t.Setenv("PUNARO_TELEGRAM_ALLOWED_USER_ID", "55")
	t.Setenv("PUNARO_TELEGRAM_GATEWAY_ENDPOINT", "telegram/other")
	t.Setenv("PUNARO_TELEGRAM_STATE_DIR", directory)
	if _, err := loadConfig(); err == nil {
		t.Fatal("non-primary telegram gateway endpoint accepted")
	}
}

func TestRegisterOperatorCommandsContinuesAfterFailure(t *testing.T) {
	called := false
	registerOperatorCommands(context.Background(), func(context.Context, []telegram.BotCommand) error {
		called = true
		return fmt.Errorf("telegram setMyCommands failed")
	})
	if !called {
		t.Fatal("setMyCommands was not attempted")
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

func TestLoadConfigAcceptsOnlyCompleteExplicitLANPolicy(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	keyFile := filepath.Join(directory, "machine.key")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUNARO_ADAPTER_RELAY_URL", "http://192.168.1.4:8080")
	t.Setenv("PUNARO_MACHINE_ID", "telegram-machine")
	t.Setenv("PUNARO_MACHINE_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("PUNARO_TELEGRAM_BOT_TOKEN", "test-token")
	t.Setenv("PUNARO_TELEGRAM_ALLOWED_USER_ID", "55")
	t.Setenv("PUNARO_TELEGRAM_GATEWAY_ENDPOINT", "telegram/primary")
	t.Setenv("PUNARO_TELEGRAM_STATE_DIR", directory)
	t.Setenv("PUNARO_ADAPTER_ALLOW_LAN_HTTP", "true")
	if _, err := loadConfig(); err == nil {
		t.Fatal("LAN acknowledgement without CIDR was accepted")
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

func TestTelegramDoctorProducesStrictHealthyContentFreeReport(t *testing.T) {
	directory := configureTelegramDoctorTest(t)
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	state, err := telegram.Open(filepath.Join(directory, "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.RecordGatewayCycle(telegram.GatewayCycleRecord{At: now.Add(-time.Minute), Offset: 4, PollOK: true, RelayOK: true, TelegramOK: true}); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	setTelegramDoctorFakes(t, now, adapter.DoctorProbeResult{Transport: true, Origin: true, Access: true, Enrolled: true, Protocol: true, Attached: true}, nil)

	var stdout, stderr bytes.Buffer
	if code := runTelegramDoctor([]string{"--timeout", "2s"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q report=%s", code, stderr.String(), stdout.String())
	}
	report, err := punarodiagnostic.Decode(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if report.Component != punarodiagnostic.ComponentTelegram || report.Identity.MachineID != "telegram-machine" || report.Identity.Release != "v0.1.0-alpha.1" || report.Identity.ReleaseSequence != 1 || report.Identity.CatalogSequence != 1 || report.Identity.Protocol != relay.ProtocolVersion || !report.Healthy {
		t.Fatalf("report=%#v", report)
	}
	for _, secret := range []string{"bot-secret", "access-secret", directory, "relay.example"} {
		if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
			t.Fatalf("doctor leaked %q", secret)
		}
	}
}

func TestTelegramDoctorSeparatesRelayBotAndDurableFailureClasses(t *testing.T) {
	directory := configureTelegramDoctorTest(t)
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	state, err := telegram.Open(filepath.Join(directory, "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := state.RecordGatewayCycle(telegram.GatewayCycleRecord{At: now.Add(-10 * time.Minute), Offset: 4, Failure: telegram.GatewayFailureInboundRelayPermanent}); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	setTelegramDoctorFakes(t, now, adapter.DoctorProbeResult{Transport: true, Origin: true, Access: false}, fmt.Errorf("provider secret body"))

	var stdout, stderr bytes.Buffer
	if code := runTelegramDoctor(nil, &stdout, &stderr); code != 1 {
		t.Fatalf("exit=%d stderr=%q report=%s", code, stderr.String(), stdout.String())
	}
	report, err := punarodiagnostic.Decode(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	for code, want := range map[string]punarodiagnostic.Status{
		"relay_access":               punarodiagnostic.StatusFail,
		"notification_access":        punarodiagnostic.StatusFail,
		"bot_api":                    punarodiagnostic.StatusFail,
		"terminal_inbound_rejection": punarodiagnostic.StatusFail,
		"stuck_head_delivery":        punarodiagnostic.StatusFail,
	} {
		if got := telegramDoctorStatus(report, code); got != want {
			t.Fatalf("%s=%s want %s", code, got, want)
		}
	}
	if strings.Contains(stdout.String(), "provider") || strings.Contains(stderr.String(), "provider") {
		t.Fatal("provider error leaked")
	}
}

func TestTelegramDoctorReportsEveryDurableGatewayFailureClassSeparately(t *testing.T) {
	for name, test := range map[string]struct {
		class telegram.GatewayFailureClass
		code  string
	}{
		"message less poll":  {telegram.GatewayFailureMessageLessPoll, "message_less_update_stall"},
		"transient retry":    {telegram.GatewayFailureTransient, "transient_retry_stall"},
		"outbound permanent": {telegram.GatewayFailureOutboundTelegramPermanent, "terminal_outbound_rejection"},
		"deleted topic":      {telegram.GatewayFailureDeletedTopic, "deleted_topic_target"},
	} {
		t.Run(name, func(t *testing.T) {
			directory := configureTelegramDoctorTest(t)
			now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
			state, err := telegram.Open(filepath.Join(directory, "telegram.db"))
			if err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if err := state.RecordGatewayCycle(telegram.GatewayCycleRecord{At: now.Add(-10 * time.Minute), Offset: 4, Failure: test.class}); err != nil {
					t.Fatal(err)
				}
			}
			if err := state.Close(); err != nil {
				t.Fatal(err)
			}
			setTelegramDoctorFakes(t, now, adapter.DoctorProbeResult{Transport: true, Origin: true, Access: true, Enrolled: true, Protocol: true, Attached: true}, nil)
			var stdout, stderr bytes.Buffer
			if code := runTelegramDoctor(nil, &stdout, &stderr); code != 1 {
				t.Fatalf("exit=%d stderr=%q report=%s", code, stderr.String(), stdout.String())
			}
			report, err := punarodiagnostic.Decode(bytes.NewReader(stdout.Bytes()))
			if err != nil || telegramDoctorStatus(report, test.code) != punarodiagnostic.StatusFail {
				t.Fatalf("code=%s status=%s err=%v", test.code, telegramDoctorStatus(report, test.code), err)
			}
		})
	}
}

func configureTelegramDoctorTest(t *testing.T) string {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	keyFile := filepath.Join(directory, "machine.key")
	botFile := filepath.Join(directory, "bot.credential")
	accessFile := filepath.Join(directory, "access.credential")
	if err := os.WriteFile(keyFile, []byte(base64.RawURLEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(botFile, []byte("bot-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accessFile, []byte("PUNARO_CF_ACCESS_CLIENT_ID=access-id\nPUNARO_CF_ACCESS_CLIENT_SECRET=access-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUNARO_ADAPTER_RELAY_URL", "https://relay.example")
	t.Setenv("PUNARO_MACHINE_ID", "telegram-machine")
	t.Setenv("PUNARO_MACHINE_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("PUNARO_TELEGRAM_BOT_TOKEN", "")
	t.Setenv("PUNARO_TELEGRAM_BOT_TOKEN_FILE", botFile)
	t.Setenv("PUNARO_TELEGRAM_ACCESS_TOKEN_FILE", accessFile)
	t.Setenv("PUNARO_CF_ACCESS_CLIENT_ID", "")
	t.Setenv("PUNARO_CF_ACCESS_CLIENT_SECRET", "")
	t.Setenv("PUNARO_TELEGRAM_ALLOWED_USER_ID", "55")
	t.Setenv("PUNARO_TELEGRAM_GATEWAY_ENDPOINT", relay.TelegramGatewayEndpoint)
	t.Setenv("PUNARO_TELEGRAM_STATE_DIR", directory)
	return directory
}

func setTelegramDoctorFakes(t *testing.T, now time.Time, relayResult adapter.DoctorProbeResult, botErr error) {
	t.Helper()
	oldRelay, oldNotifications := telegramDoctorRelayProbe, telegramDoctorNotificationProbe
	oldBot, oldService := telegramDoctorBotProbe, telegramDoctorServiceProbe
	oldNow, oldRelease := telegramDoctorNow, telegramBuildRelease
	oldSequence, oldCatalogSequence := telegramBuildSequence, telegramBuildCatalogSequence
	telegramDoctorRelayProbe = func(context.Context, config) (adapter.DoctorProbeResult, error) { return relayResult, nil }
	telegramDoctorNotificationProbe = func(context.Context, config) (adapter.DoctorProbeResult, error) { return relayResult, nil }
	telegramDoctorBotProbe = func(context.Context, config) error { return botErr }
	telegramDoctorServiceProbe = func(context.Context) telegramServiceDoctorResult {
		return telegramServiceDoctorResult{Installed: true, Enabled: true, Running: true, Executable: true, Release: true, ExitStatus: true, RestartState: true}
	}
	telegramDoctorNow = func() time.Time { return now }
	telegramBuildRelease = "v0.1.0-alpha.1"
	telegramBuildSequence = "1"
	telegramBuildCatalogSequence = "1"
	t.Cleanup(func() {
		telegramDoctorRelayProbe, telegramDoctorNotificationProbe = oldRelay, oldNotifications
		telegramDoctorBotProbe, telegramDoctorServiceProbe = oldBot, oldService
		telegramDoctorNow, telegramBuildRelease = oldNow, oldRelease
		telegramBuildSequence, telegramBuildCatalogSequence = oldSequence, oldCatalogSequence
	})
}

func telegramDoctorStatus(report punarodiagnostic.Report, code string) punarodiagnostic.Status {
	for _, check := range report.Checks {
		if check.Code == code {
			return check.Status
		}
	}
	return ""
}
