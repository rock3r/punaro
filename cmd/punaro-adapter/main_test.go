package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestParseSendArgsAcceptsDirectRoleSendAndRejectsMixedForms(t *testing.T) {
	request, err := parseSendArgs([]string{"--to", "role/machine-b/implementer", "--from-role", "role/machine-a/reviewer", "--body-file", "-", "--idempotency-key", "dm-1"})
	if err != nil || request.toRole != "role/machine-b/implementer" || request.fromRole != "role/machine-a/reviewer" || request.conversationID != "" {
		t.Fatalf("direct send request=%#v err=%v", request, err)
	}
	if _, err := parseSendArgs([]string{"--to", "implementer", "--from-role", "role/machine-a/reviewer", "--body-file", "-", "--idempotency-key", "dm-1"}); err == nil {
		t.Fatal("unqualified destination was accepted")
	}
	if _, err := parseSendArgs([]string{"--to", "role/machine-b/implementer", "--from-role", "role/machine-a/reviewer", "--conversation", "conversation-1", "--body-file", "-", "--idempotency-key", "dm-1"}); err == nil {
		t.Fatal("mixed send form was accepted")
	}
	if _, err := parseSendArgs([]string{"--to", "role/machine-b/implementer", "--body-file", "-", "--idempotency-key", "dm-1"}); err == nil {
		t.Fatal("direct send without source role was accepted")
	}
}

func TestParseSendArgsAcceptsToUserTelegramWithoutConversation(t *testing.T) {
	request, err := parseSendArgs([]string{"--to", relay.TelegramUserParticipant, "--from", "agent/a", "--body-file", "-", "--idempotency-key", "reply-1"})
	if err != nil || request.to != relay.TelegramUserParticipant || request.targetRole != relay.TelegramUserParticipant || request.conversationID != "" {
		t.Fatalf("user-telegram send request=%#v err=%v", request, err)
	}
	equivalent, err := parseSendArgs([]string{"--target-role", relay.TelegramUserParticipant, "--from", "agent/a", "--body-file", "-", "--idempotency-key", "reply-1"})
	if err != nil || equivalent.targetRole != relay.TelegramUserParticipant || equivalent.conversationID != "" {
		t.Fatalf("equivalent target-role send request=%#v err=%v", equivalent, err)
	}
	matched, err := parseSendArgs([]string{"--to", relay.TelegramUserParticipant, "--conversation", "conversation-1", "--from", "agent/a", "--body-file", "-", "--idempotency-key", "reply-1"})
	if err != nil || matched.conversationID != "conversation-1" || matched.targetRole != relay.TelegramUserParticipant {
		t.Fatalf("user-telegram send with conversation=%#v err=%v", matched, err)
	}
	if _, err := parseSendArgs([]string{"--to", "role/reviewer", "--from", "agent/a", "--body-file", "-", "--idempotency-key", "reply-1"}); err == nil {
		t.Fatal("non-user-telegram --to was accepted")
	}
	if _, err := parseSendArgs([]string{"--to", relay.TelegramUserParticipant, "--target-role", "role/reviewer", "--from", "agent/a", "--body-file", "-", "--idempotency-key", "reply-1"}); err == nil {
		t.Fatal("mismatched --to and --target-role was accepted")
	}
	if _, err := parseSendArgs([]string{"--from", "agent/a", "--body-file", "-", "--idempotency-key", "reply-1"}); err == nil {
		t.Fatal("send without conversation or --to user-telegram was accepted")
	}
	if _, err := parseSendArgs([]string{"--to", relay.TelegramUserParticipant, "--body-file", "-", "--idempotency-key", "reply-1"}); err == nil || !strings.Contains(err.Error(), "--from, --body-file, and --idempotency-key are required") || strings.Contains(err.Error(), "--conversation") {
		t.Fatalf("user-telegram missing-from err=%v", err)
	}
}

func TestParseClaimArgsRequiresConversationFromAndIdempotencyKey(t *testing.T) {
	if _, err := parseClaimArgs([]string{"--from", "agent/a", "--idempotency-key", "claim-room-1"}); err == nil {
		t.Fatal("claim without conversation was accepted")
	}
	if _, err := parseClaimArgs([]string{"--conversation", "conversation-1", "--from", "agent/a"}); err == nil {
		t.Fatal("claim without idempotency key was accepted")
	}
	request, err := parseClaimArgs([]string{"--conversation", "conversation-1", "--from", "agent/a", "--idempotency-key", "claim-room-1"})
	if err != nil || request.conversationID != "conversation-1" || request.fromEndpoint != "agent/a" || request.idempotencyKey != "claim-room-1" {
		t.Fatalf("claim request=%#v err=%v", request, err)
	}
}

func TestParseGetArgsRequiresFrom(t *testing.T) {
	if _, err := parseGetArgs(nil); err == nil {
		t.Fatal("get without --from was accepted")
	}
	request, err := parseGetArgs([]string{"--from", "agent/a"})
	if err != nil || request.fromEndpoint != "agent/a" {
		t.Fatalf("get request=%#v err=%v", request, err)
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
	if err != nil || len(request.members) != 2 || request.idempotencyKey != "create-1" || request.displayName != "" {
		t.Fatalf("create request did not parse")
	}
	named, err := parseCreateArgs([]string{"--creator", "agent/a", "--member", "agent/a:send,receive,admin", "--name", "Review room", "--idempotency-key", "create-named"})
	if err != nil || named.displayName != "Review room" {
		t.Fatalf("named create request=%#v err=%v", named, err)
	}
	if _, err := parseCreateArgs([]string{"--creator", "agent/a", "--idempotency-key", "create-1"}); err == nil {
		t.Fatal("create without members accepted")
	}
}

func TestParseRenameArgsRequiresConversationActorNameAndRetryKey(t *testing.T) {
	request, err := parseRenameArgs([]string{"--conversation", "conversation-1", "--actor", "agent/a", "--name", "Ops room", "--idempotency-key", "rename-1"})
	if err != nil || request.conversationID != "conversation-1" || request.actor != "agent/a" || request.displayName != "Ops room" || request.idempotencyKey != "rename-1" {
		t.Fatalf("rename request=%#v err=%v", request, err)
	}
	if _, err := parseRenameArgs([]string{"--conversation", "conversation-1", "--actor", "agent/a", "--name", "Ops room"}); err == nil {
		t.Fatal("rename without idempotency key was accepted")
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
	registered, err := parseRegisterRoleArgs([]string{"--role", "role/machine-a/reviewer", "--display-name", "  Reviewer  ", "--idempotency-key", "register-1"})
	if err != nil || registered.role != "role/machine-a/reviewer" || registered.displayName != "  Reviewer  " || registered.directAddressable || registered.idempotencyKey != "register-1" {
		t.Fatalf("register role=%#v err=%v", registered, err)
	}
	addressable, err := parseRegisterRoleArgs([]string{"--role", "role/machine-a/reviewer", "--direct-addressable", "--idempotency-key", "register-2"})
	if err != nil || !addressable.directAddressable {
		t.Fatalf("addressable register=%#v err=%v", addressable, err)
	}
	if _, err := parseRegisterRoleArgs([]string{"--role", "role/machine-a/reviewer"}); err == nil {
		t.Fatal("register-role without idempotency key was accepted")
	}
	if _, err := parseRegisterRoleArgs([]string{"--role", "role/plan-reviewer", "--idempotency-key", "register-legacy"}); err == nil {
		t.Fatal("legacy role handle was accepted")
	}
}

func TestParseContactsListArgsDefaultsAndBounds(t *testing.T) {
	request, err := parseContactsListArgs(nil)
	if err != nil || request.cursor != "" || request.limit != relay.DefaultRoleListLimit {
		t.Fatalf("default list=%#v err=%v", request, err)
	}
	request, err = parseContactsListArgs([]string{"--cursor", "page-2", "--limit", "10"})
	if err != nil || request.cursor != "page-2" || request.limit != 10 {
		t.Fatalf("paged list=%#v err=%v", request, err)
	}
	if _, err := parseContactsListArgs([]string{"--limit", "0"}); err == nil {
		t.Fatal("limit 0 was accepted")
	}
	if _, err := parseContactsListArgs([]string{"--limit", "101"}); err == nil {
		t.Fatal("limit 101 was accepted")
	}
	if _, err := parseContactsListArgs([]string{"extra"}); err == nil {
		t.Fatal("positional list argument was accepted")
	}
}

func TestParseContactsResolveArgsRequiresName(t *testing.T) {
	name, err := parseContactsResolveArgs([]string{"reviewer"})
	if err != nil || name != "reviewer" {
		t.Fatalf("short name=%q err=%v", name, err)
	}
	name, err = parseContactsResolveArgs([]string{"role/workstation-review/reviewer"})
	if err != nil || name != "role/workstation-review/reviewer" {
		t.Fatalf("qualified name=%q err=%v", name, err)
	}
	if _, err := parseContactsResolveArgs(nil); err == nil {
		t.Fatal("missing resolve name was accepted")
	}
	if _, err := parseContactsResolveArgs([]string{"reviewer", "extra"}); err == nil {
		t.Fatal("extra resolve argument was accepted")
	}
}

func TestContactsResolveExitCodes(t *testing.T) {
	if code := contactsResolveExit(relay.RoleResolveResult{Status: relay.RoleResolveResolved}); code != 0 {
		t.Fatalf("resolved exit=%d", code)
	}
	if code := contactsResolveExit(relay.RoleResolveResult{Status: relay.RoleResolveNotFound}); code != 1 {
		t.Fatalf("not-found exit=%d", code)
	}
	if code := contactsResolveExit(relay.RoleResolveResult{Status: relay.RoleResolveAmbiguous}); code != 2 {
		t.Fatalf("ambiguous exit=%d", code)
	}
}

func TestContactsStatusErrorDoesNotLogAdapterStop(t *testing.T) {
	if shouldLogAdapterStop(&contactsStatusError{message: relay.RoleResolveNotFound, code: 1}) {
		t.Fatal("expected directory status was logged as a stop")
	}
	if shouldLogAdapterStop(&contactsStatusError{message: relay.RoleResolveAmbiguous, code: 2}) {
		t.Fatal("ambiguous directory status was logged as a stop")
	}
	if !shouldLogAdapterStop(fmt.Errorf("configuration: missing")) {
		t.Fatal("real failure was silenced")
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
		handled := os.Getenv("PUNARO_TEST_MAILBOX_MCP_HANDLED")
		if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil { // #nosec G703 -- parent test selects this private readiness fixture.
			os.Exit(2)
		}
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			os.Exit(3)
		}
		if err := os.WriteFile(handled, []byte("handled"), 0o600); err != nil { // #nosec G703 -- parent test selects this private completion fixture.
			os.Exit(4)
		}
		os.Exit(0)
	}

	directory := t.TempDir()
	ready := filepath.Join(directory, "ready")
	handled := filepath.Join(directory, "handled")
	t.Setenv("PUNARO_TEST_MAILBOX_MCP_HELPER", "1")
	t.Setenv("PUNARO_TEST_MAILBOX_MCP_READY", ready)
	t.Setenv("PUNARO_TEST_MAILBOX_MCP_HANDLED", handled)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input, keepInputOpen := io.Pipe()
	defer func() { _ = keepInputOpen.Close() }()
	done := make(chan error, 1)
	go func() {
		done <- runMailboxMCPProcess(ctx, []string{os.Args[0], "-test.run=^TestMailboxMCPShutdownIsClean$"}, input, io.Discard, io.Discard)
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
	if _, err := os.Stat(handled); err != nil {
		t.Fatalf("mailbox MCP helper did not handle graceful input closure: %v", err)
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
		case "/v1/roles/list":
			_, _ = w.Write([]byte(`{"roles":[]}`))
		case "/v1/roles/resolve":
			_, _ = w.Write([]byte(`{"status":"resolved","role":"role/profile-machine/reviewer","machine_id":"profile-machine"}`))
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
	if err := runContacts([]string{"list"}); err != nil {
		t.Fatalf("contacts list did not reach its transport boundary: %v", err)
	}
	if err := runContacts([]string{"resolve", "role/profile-machine/reviewer"}); err != nil {
		t.Fatalf("contacts resolve did not reach its transport boundary: %v", err)
	}
}

func TestRunClaimTreatsCompleteReserveAsSuccess(t *testing.T) {
	clearAdapterEnvironment(t)
	var gotKey, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations/conversation-1/telegram-claim" {
			t.Fatalf("unexpected claim route %s %s", r.Method, r.URL.Path)
		}
		gotKey = r.Header.Get("Idempotency-Key")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"conversation_id":"conversation-1","status":"complete","display_name":"Ops","created_at":"2026-08-16T12:00:00Z","completed_at":"2026-08-16T12:00:05Z"}`))
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))

	output, err := captureStdout(t, func() error {
		return runClaim([]string{"--conversation", "conversation-1", "--from", "agent/a", "--idempotency-key", "claim-room-1"})
	})
	if err != nil {
		t.Fatalf("complete claim retry failed: %v", err)
	}
	if gotKey != "claim-room-1" || !strings.Contains(gotBody, `"endpoint":"agent/a"`) {
		t.Fatalf("claim request key=%q body=%s", gotKey, gotBody)
	}
	if !strings.Contains(output, `"status":"complete"`) || !strings.Contains(output, `"conversation_id":"conversation-1"`) {
		t.Fatalf("claim output=%q", output)
	}
}

func TestRunClaimAcceptsPendingReserveAndRejectsUnknownStatus(t *testing.T) {
	clearAdapterEnvironment(t)
	status := "pending"
	code := http.StatusCreated
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations/conversation-1/telegram-claim" {
			t.Fatalf("unexpected claim route %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"conversation_id":"conversation-1","status":"` + status + `","display_name":"Ops","created_at":"2026-08-16T12:00:00Z"}`))
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))

	output, err := captureStdout(t, func() error {
		return runClaim([]string{"--conversation", "conversation-1", "--from", "agent/a", "--idempotency-key", "claim-room-1"})
	})
	if err != nil {
		t.Fatalf("pending claim failed: %v", err)
	}
	if !strings.Contains(output, `"status":"pending"`) || !strings.Contains(output, `"conversation_id":"conversation-1"`) {
		t.Fatalf("pending claim output=%q", output)
	}

	status = "reserved"
	code = http.StatusOK
	if err := runClaim([]string{"--conversation", "conversation-1", "--from", "agent/a", "--idempotency-key", "claim-room-1"}); err == nil || err.Error() != "telegram claim was not accepted" {
		t.Fatalf("unknown claim status err=%v", err)
	}
}

func TestRunClaimMapsForbiddenAndConflictWithoutExistenceLeak(t *testing.T) {
	clearAdapterEnvironment(t)
	code := http.StatusForbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/conversations/conversation-1/telegram-claim" {
			t.Fatalf("unexpected claim route %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, `{"error":"authorization denied"}`, code)
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))

	err := runClaim([]string{"--conversation", "conversation-1", "--from", "agent/a", "--idempotency-key", "claim-room-1"})
	if !errors.Is(err, errTelegramClaimForbidden) {
		t.Fatalf("forbidden claim err=%v", err)
	}
	code = http.StatusConflict
	err = runClaim([]string{"--conversation", "conversation-1", "--from", "agent/a", "--idempotency-key", "claim-room-1"})
	if !errors.Is(err, errTelegramClaimConflict) {
		t.Fatalf("conflict claim err=%v", err)
	}
}

func TestRunGetRequiresClaimedSessionTopic(t *testing.T) {
	clearAdapterEnvironment(t)
	var claimed bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sessions/topic" {
			t.Fatalf("unexpected get route %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"endpoint":"agent/a"`) {
			t.Fatalf("session topic body=%s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		if !claimed {
			_, _ = w.Write([]byte(`{"id":"conversation-1","display_name":"Ops","claimed":false}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"conversation-1","display_name":"Ops","claimed":true}`))
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))

	if err := runGet([]string{"--from", "agent/a"}); err == nil || !strings.Contains(err.Error(), "topic is not claimed") {
		t.Fatalf("unclaimed get err=%v", err)
	}
	claimed = true
	output, err := captureStdout(t, func() error { return runGet([]string{"--from", "agent/a"}) })
	if err != nil {
		t.Fatalf("claimed get failed: %v", err)
	}
	if !strings.Contains(output, `"id":"conversation-1"`) || !strings.Contains(output, `"display_name":"Ops"`) || !strings.Contains(output, `"claimed":true`) {
		t.Fatalf("get output=%q", output)
	}
}

func TestRunGetMapsMissingSessionTopicWithoutExistenceLeak(t *testing.T) {
	clearAdapterEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sessions/topic" {
			t.Fatalf("unexpected get route %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, `{"error":"authorization denied"}`, http.StatusForbidden)
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))

	err := runGet([]string{"--from", "agent/a"})
	if err == nil || err.Error() != "session has no topic" {
		t.Fatalf("missing topic err=%v", err)
	}
}

func TestRunSendToUserTelegramResolvesClaimedSessionTopic(t *testing.T) {
	clearAdapterEnvironment(t)
	var sawTopic, sawSend bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sessions/topic":
			sawTopic = true
			_, _ = w.Write([]byte(`{"id":"conversation-1","display_name":"Ops","claimed":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/conversations/conversation-1/messages":
			sawSend = true
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), `"target_role":"user-telegram"`) || !strings.Contains(string(body), `"from_endpoint":"agent/a"`) {
				t.Fatalf("user-telegram send body=%s", body)
			}
			_, _ = w.Write([]byte(`{"id":"message-1","conversation_id":"conversation-1","sequence":1,"from_endpoint":"agent/a","body":"ignored","created_at":"2026-08-16T12:00:00Z"}`))
		default:
			t.Fatalf("unexpected send route %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))
	bodyFile := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(bodyFile, []byte("ping human"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runSend([]string{"--to", relay.TelegramUserParticipant, "--from", "agent/a", "--body-file", bodyFile, "--idempotency-key", "reply-1"}); err != nil {
		t.Fatalf("user-telegram send failed: %v", err)
	}
	if err := runSend([]string{"--to", relay.TelegramUserParticipant, "--conversation", "conversation-1", "--from", "agent/a", "--body-file", bodyFile, "--idempotency-key", "reply-2"}); err != nil {
		t.Fatalf("matching conversation send failed: %v", err)
	}
	if err := runSend([]string{"--to", relay.TelegramUserParticipant, "--conversation", "conversation-other", "--from", "agent/a", "--body-file", bodyFile, "--idempotency-key", "reply-3"}); err == nil || err.Error() != "conversation does not match session topic" {
		t.Fatalf("mismatched conversation err=%v", err)
	}
	if !sawTopic || !sawSend {
		t.Fatal("user-telegram send skipped session topic or message append")
	}
}

func TestRunSendToUserTelegramFailsClosedWhenUnclaimed(t *testing.T) {
	clearAdapterEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sessions/topic" {
			t.Fatalf("unclaimed send reached %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"conversation-1","display_name":"Ops","claimed":false}`))
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))
	bodyFile := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(bodyFile, []byte("too soon"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runSend([]string{"--to", relay.TelegramUserParticipant, "--from", "agent/a", "--body-file", bodyFile, "--idempotency-key", "reply-1"})
	if err == nil || err.Error() != "topic is not claimed" {
		t.Fatalf("unclaimed send err=%v", err)
	}
}

func TestRunSendConversationPathDoesNotResolveSessionTopic(t *testing.T) {
	clearAdapterEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sessions/topic" {
			t.Fatal("existing conversation send resolved a session topic")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations/conversation-9/messages" {
			t.Fatalf("unexpected conversation send route %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "target_role") {
			t.Fatalf("broadcast send included target_role: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"message-9","conversation_id":"conversation-9","sequence":2,"from_endpoint":"agent/a","body":"ignored","created_at":"2026-08-16T12:00:00Z"}`))
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))
	bodyFile := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(bodyFile, []byte("broadcast"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runSend([]string{"--conversation", "conversation-9", "--from", "agent/a", "--body-file", bodyFile, "--idempotency-key", "send-9"}); err != nil {
		t.Fatalf("conversation send failed: %v", err)
	}
}

func TestRunSendTargetRoleDoesNotResolveSessionTopic(t *testing.T) {
	clearAdapterEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sessions/topic" {
			t.Fatal("targeted role send resolved a session topic")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/conversations/conversation-9/messages" {
			t.Fatalf("unexpected targeted send route %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"target_role":"role/reviewer"`) {
			t.Fatalf("targeted send body=%s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"message-9","conversation_id":"conversation-9","sequence":2,"from_endpoint":"agent/a","body":"ignored","created_at":"2026-08-16T12:00:00Z"}`))
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))
	bodyFile := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(bodyFile, []byte("review this"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runSend([]string{"--conversation", "conversation-9", "--from", "agent/a", "--target-role", "role/reviewer", "--body-file", bodyFile, "--idempotency-key", "send-role-9"}); err != nil {
		t.Fatalf("targeted role send failed: %v", err)
	}
}

func TestRunSendToUserTelegramFailsClosedOnMissingOrAmbiguousTopic(t *testing.T) {
	clearAdapterEnvironment(t)
	code := http.StatusForbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sessions/topic" {
			t.Fatalf("pre-append send reached %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, `{"error":"authorization denied"}`, code)
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))
	bodyFile := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(bodyFile, []byte("too soon"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runSend([]string{"--to", relay.TelegramUserParticipant, "--from", "agent/a", "--body-file", bodyFile, "--idempotency-key", "reply-403"})
	if !errors.Is(err, errSessionHasNoTopic) {
		t.Fatalf("missing topic send err=%v", err)
	}
	code = http.StatusConflict
	err = runSend([]string{"--to", relay.TelegramUserParticipant, "--from", "agent/a", "--body-file", bodyFile, "--idempotency-key", "reply-409"})
	if !errors.Is(err, errSessionTopicAmbiguous) {
		t.Fatalf("ambiguous topic send err=%v", err)
	}
}

func TestRunSendToUserTelegramPreservesAppendForbidden(t *testing.T) {
	clearAdapterEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sessions/topic":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"conversation-1","display_name":"Ops","claimed":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/conversations/conversation-1/messages":
			http.Error(w, `{"error":"authorization denied"}`, http.StatusForbidden)
		default:
			t.Fatalf("unexpected send route %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	profile := writeInstallerProfile(t, server.URL)
	t.Setenv("HOME", filepath.Dir(filepath.Dir(filepath.Dir(profile))))
	bodyFile := filepath.Join(t.TempDir(), "body.txt")
	if err := os.WriteFile(bodyFile, []byte("no send cap"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runSend([]string{"--to", relay.TelegramUserParticipant, "--from", "agent/a", "--body-file", bodyFile, "--idempotency-key", "reply-forbidden"})
	if err == nil || errors.Is(err, errTopicNotClaimed) || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("append forbidden err=%v", err)
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

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = writer
	runErr := fn()
	_ = writer.Close()
	os.Stdout = stdout
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(output), runErr
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

func TestWriteBootstrapReadyIsOptional(t *testing.T) {
	t.Setenv(bootstrapReadyEnv, "")
	if err := writeBootstrapReady(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteBootstrapReadyRejectsRelativePath(t *testing.T) {
	t.Setenv(bootstrapReadyEnv, "relative-health.json")
	if err := writeBootstrapReady(); err == nil {
		t.Fatal("relative ready path accepted")
	}
}

func TestWriteBootstrapReadyPublishesHealthyRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "health.json")
	t.Setenv(bootstrapReadyEnv, path)
	if err := writeBootstrapReady(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != bootstrapReadyBody {
		t.Fatalf("ready=%q", body)
	}
}

func TestWriteBootstrapReadyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	path := filepath.Join(dir, "health.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	t.Setenv(bootstrapReadyEnv, path)
	if err := writeBootstrapReady(); err == nil {
		t.Fatal("symlink ready path accepted")
	}
}
