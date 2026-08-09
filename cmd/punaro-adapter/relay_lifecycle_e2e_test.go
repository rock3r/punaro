//go:build e2e && darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/adapter"
	"github.com/rock3r/punaro/internal/clientidentity"
)

func TestE2EClientIdentitySidecarGatesInstalledAdapter(t *testing.T) {
	if os.Getenv("PUNARO_REAL_RELAY_E2E") != "1" {
		t.Skip("set PUNARO_REAL_RELAY_E2E=1 to run the installed client identity smoke test")
	}
	mailbox, err := exec.LookPath("agent-mailbox")
	if err != nil {
		t.Fatal("agent-mailbox is required for the installed client identity smoke test")
	}

	root := e2eRepositoryRoot(t)
	fixture := t.TempDir()
	home := filepath.Join(fixture, "client")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal("create disposable client home")
	}
	machineID := "e2e-identity-" + uuid.NewString()
	const origin = "https://127.0.0.1:1"
	e2eInstallClient(t, root, home, origin, machineID, mailbox, filepath.Join(home, "mailbox"), false)

	profile := filepath.Join(home, ".config", "punaro", "adapter.env")
	identity := filepath.Join(home, ".config", "punaro", "client-identity.json")
	binding := uuid.NewString()
	state := clientidentity.State{Version: clientidentity.Version, Origin: origin, ClientBinding: binding, LegacyMachineID: machineID}
	raw, err := state.Encode()
	if err != nil {
		t.Fatal("encode identity sidecar")
	}
	if err := os.WriteFile(identity, raw, 0o600); err != nil {
		t.Fatal("write identity sidecar")
	}
	profileRaw, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal("read installed profile")
	}
	profileRaw = append(profileRaw, []byte("PUNARO_CLIENT_IDENTITY_FILE="+identity+"\nPUNARO_CLIENT_BINDING="+binding+"\n")...)
	if err := os.WriteFile(profile, profileRaw, 0o600); err != nil {
		t.Fatal("write installed profile identity settings")
	}

	adapterBinary := filepath.Join(home, ".local", "bin", "punaro-adapter")
	environment := e2eEnvironment(e2eGoEnvironment(), map[string]string{adapterProfileFileEnv: profile})
	if err := os.WriteFile(identity, []byte(`{"version":1,"origin":"https://127.0.0.1:2","client_binding":"`+binding+`","legacy_machine_id":"`+machineID+`"}`), 0o600); err != nil {
		t.Fatal("write cross-origin identity sidecar")
	}
	rejected := exec.Command(adapterBinary)
	rejected.Env = environment
	output, err := rejected.CombinedOutput()
	if err == nil || strings.Contains(string(output), binding) || strings.Contains(string(output), machineID) {
		t.Fatalf("cross-origin installed adapter error=%v output=%q", err, output)
	}
	if err := os.WriteFile(identity, raw, 0o600); err != nil {
		t.Fatal("restore matching identity sidecar")
	}

	started := exec.Command(adapterBinary)
	started.Env = environment
	started.Stdout = io.Discard
	started.Stderr = io.Discard
	if err := started.Start(); err != nil {
		t.Fatal("start installed adapter with matching identity")
	}
	time.Sleep(250 * time.Millisecond)
	if err := started.Process.Signal(os.Interrupt); err != nil {
		t.Fatal("stop installed adapter")
	}
	if err := started.Wait(); err != nil {
		t.Fatalf("matching identity adapter did not stop cleanly: %v", err)
	}
}

func TestE2ERealTwoClientRelayLifecycle(t *testing.T) {
	if os.Getenv("PUNARO_REAL_RELAY_E2E") != "1" {
		t.Skip("set PUNARO_REAL_RELAY_E2E=1 to run the disposable two-client lifecycle smoke test")
	}
	mailbox, err := exec.LookPath("agent-mailbox")
	if err != nil {
		t.Fatal("agent-mailbox is required for the real two-client lifecycle smoke test")
	}

	root := e2eRepositoryRoot(t)
	fixture := t.TempDir()
	senderHome := filepath.Join(fixture, "sender")
	receiverHome := filepath.Join(fixture, "receiver")
	for _, home := range []string{senderHome, receiverHome} {
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal("create disposable client home")
		}
	}

	installedServicePath := filepath.Join(receiverHome, "Library", "LaunchAgents", "org.punaro.adapter.plist")
	launchDomain := "gui/" + strconvItoa(os.Getuid())

	proxyListener := e2eListenLoopback(t)
	relayAddress, healthAddress := e2eDistinctLoopbackAddresses(t, proxyListener.Addr().String())
	proxy := e2eStartRelayProxy(t, relayAddress, proxyListener)
	relayURL := "https://" + proxy.listener.Addr().String()

	senderProfile := filepath.Join(senderHome, ".config", "punaro", "adapter.env")
	receiverProfile := filepath.Join(receiverHome, ".config", "punaro", "adapter.env")

	senderMailboxState := filepath.Join(senderHome, "mailbox")
	receiverMailboxState := filepath.Join(receiverHome, "mailbox")
	senderMachineID := "e2e-sender-" + uuid.NewString()
	receiverMachineID := "e2e-receiver-" + uuid.NewString()
	e2eInstallClient(t, root, senderHome, relayURL, senderMachineID, mailbox, senderMailboxState, false)
	e2eInstallClient(t, root, receiverHome, relayURL, receiverMachineID, mailbox, receiverMailboxState, false)
	e2eRewriteRelayURL(t, senderProfile, "http://"+proxy.listener.Addr().String())
	e2eRewriteRelayURL(t, receiverProfile, "http://"+proxy.listener.Addr().String())
	receiverAdapter := filepath.Join(receiverHome, ".local", "bin", "punaro-adapter")
	servicePath := e2eIsolatedLaunchAgent(t, installedServicePath, receiverHome, receiverProfile, receiverAdapter, fixture)
	t.Cleanup(func() { _ = e2eLaunchctl("bootout", launchDomain, servicePath) })

	senderEndpoint := "agent/" + senderMachineID + "/session"
	receiverEndpoint := "agent/" + receiverMachineID + "/session"
	e2eMailbox(t, senderMailboxState, "group", "add-member", "--group", "group/punaro-attached", "--person", senderEndpoint, "--json")
	e2eMailbox(t, receiverMailboxState, "group", "add-member", "--group", "group/punaro-attached", "--person", receiverEndpoint, "--json")

	relayBinary := filepath.Join(fixture, "punarod")
	e2eRun(t, root, e2eGoEnvironment(), "go", "build", "-trimpath", "-o", relayBinary, "./cmd/punarod")
	machines := e2eEnrollmentSet(t, senderHome, receiverHome)
	relayEnvironment := e2eEnvironment(e2eGoEnvironment(), map[string]string{
		"PUNARO_DATA_DIR":            filepath.Join(fixture, "relay-state"),
		"PUNARO_RELAY_ENABLED":       "true",
		"PUNARO_RELAY_MACHINES_JSON": machines,
		"PUNARO_LISTEN_ADDR":         relayAddress,
		"PUNARO_HEALTH_LISTEN_ADDR":  healthAddress,
		"PUNARO_LOG_LEVEL":           "error",
		"PUNARO_ACCESS_ISSUER":       "",
		"PUNARO_ACCESS_AUDIENCE":     "",
		"PUNARO_ACCESS_JWKS_URL":     "",
		"PUNARO_ACCESS_JWKS_FILE":    "",
		"PUNARO_ENV_FILE":            "",
	})
	relay := e2eStartRelay(t, relayBinary, relayEnvironment)
	t.Cleanup(func() { e2eStopProcess(relay) })
	e2eEventually(t, 20*time.Second, func() bool { return e2eReady(healthAddress) }, "disposable central relay did not become ready")
	proxyURL := "http://" + proxy.listener.Addr().String()
	e2eAdvertiseEndpoint(t, proxyURL, senderHome, senderEndpoint)
	e2eAdvertiseEndpoint(t, proxyURL, receiverHome, receiverEndpoint)
	e2eStopProcess(relay)
	relay = e2eStartRelay(t, relayBinary, relayEnvironment)
	e2eEventually(t, 20*time.Second, func() bool { return e2eReady(healthAddress) }, "restarted central relay did not become ready")

	senderAdapter := filepath.Join(senderHome, ".local", "bin", "punaro-adapter")
	sender := exec.Command(senderAdapter)
	sender.Env = e2eEnvironment(e2eGoEnvironment(), map[string]string{
		adapterProfileFileEnv: senderProfile,
	})
	sender.Stdout = io.Discard
	sender.Stderr = io.Discard
	if err := sender.Start(); err != nil {
		t.Fatal("start installed sender adapter")
	}
	t.Cleanup(func() { e2eStopProcess(sender) })
	if err := e2eLaunchctl("bootstrap", launchDomain, servicePath); err != nil {
		t.Fatal("start installed receiver service")
	}

	conversationID := e2eCreateConversation(t, senderAdapter, senderProfile, senderEndpoint, receiverEndpoint)
	e2eRejectUnauthorizedLease(t, proxyURL, senderHome, receiverEndpoint)
	e2eSend(t, senderAdapter, senderProfile, conversationID, senderEndpoint)

	e2eMailbox(t, receiverMailboxState, "wait", "--for", receiverEndpoint, "--timeout", "60s", "--json")
	claim := e2eClaim(t, mailbox, receiverMailboxState, receiverEndpoint)
	e2eMailbox(t, receiverMailboxState, "ack", "--delivery", claim.DeliveryID, "--lease-token", claim.LeaseToken)
	e2eEventually(t, 10*time.Second, func() bool { return proxy.firstAckRejected.Load() }, "receiver did not reach the forced acknowledgement retry boundary")

	if err := e2eLaunchctl("bootout", launchDomain, servicePath); err != nil {
		t.Fatal("stop installed receiver service before retry restart")
	}
	proxy.retryAcknowledged.Store(false)
	proxy.allowRetryAcknowledgement.Store(true)
	if err := e2eLaunchctl("bootstrap", launchDomain, servicePath); err != nil {
		t.Fatal("restart installed receiver service for retry")
	}
	// A restarted adapter uses a fresh consumer identity. The relay must retain
	// the prior process's live lease until its bounded recovery window expires,
	// then let the durable forwarded journal state retry only the acknowledgement.
	e2eEventually(t, 75*time.Second, func() bool { return proxy.retryAcknowledged.Load() }, "restarted receiver did not retry its relay acknowledgement")

	e2eExpectMailboxTimeout(t, receiverMailboxState, receiverEndpoint)
}

type e2eClaimResult struct {
	DeliveryID string `json:"delivery_id"`
	LeaseToken string `json:"lease_token"`
}

type e2eRelayProxy struct {
	listener                  net.Listener
	server                    *http.Server
	firstAckRejected          atomic.Bool
	retryAcknowledged         atomic.Bool
	allowRetryAcknowledgement atomic.Bool
}

func e2eRepositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("resolve repository root")
	}
	return root
}

func e2eFreeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("allocate disposable loopback address")
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal("release disposable loopback address")
	}
	return address
}

func e2eListenLoopback(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("reserve disposable loopback address")
	}
	return listener
}

func e2eDistinctLoopbackAddresses(t *testing.T, occupied ...string) (string, string) {
	t.Helper()
	reserved := make(map[string]struct{}, len(occupied)+2)
	for _, address := range occupied {
		reserved[address] = struct{}{}
	}
	for attempts := 0; attempts < 20; attempts++ {
		relayAddress := e2eFreeLoopbackAddress(t)
		if _, exists := reserved[relayAddress]; exists {
			continue
		}
		reserved[relayAddress] = struct{}{}
		healthAddress := e2eFreeLoopbackAddress(t)
		if _, exists := reserved[healthAddress]; !exists {
			return relayAddress, healthAddress
		}
		delete(reserved, relayAddress)
	}
	t.Fatal("allocate distinct disposable relay and health addresses")
	return "", ""
}

func e2eStartRelayProxy(t *testing.T, relayAddress string, listener net.Listener) *e2eRelayProxy {
	t.Helper()
	target, err := url.Parse("http://" + relayAddress)
	if err != nil {
		t.Fatal("configure disposable relay proxy")
	}
	state := &e2eRelayProxy{}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	proxy.ModifyResponse = func(upstream *http.Response) error {
		if upstream.Request.Method == http.MethodPost && strings.HasPrefix(upstream.Request.URL.Path, "/v1/deliveries/") && strings.HasSuffix(upstream.Request.URL.Path, "/ack") && upstream.StatusCode >= http.StatusOK && upstream.StatusCode < http.StatusMultipleChoices {
			state.retryAcknowledged.Store(true)
		}
		return nil
	}
	state.server = &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/v1/deliveries/") && strings.HasSuffix(request.URL.Path, "/ack") {
			if state.firstAckRejected.CompareAndSwap(false, true) {
				response.Header().Set("Cache-Control", "no-store")
				response.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if !state.allowRetryAcknowledgement.Load() {
				response.Header().Set("Cache-Control", "no-store")
				response.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		proxy.ServeHTTP(response, request)
	})}
	state.listener = listener
	go func() { _ = state.server.Serve(listener) }()
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = state.server.Shutdown(shutdown)
	})
	return state
}

func e2eStartRelay(t *testing.T, binary string, environment []string) *exec.Cmd {
	t.Helper()
	relay := exec.Command(binary)
	relay.Env = environment
	relay.Stdout = io.Discard
	relay.Stderr = io.Discard
	if err := relay.Start(); err != nil {
		t.Fatal("start disposable central relay")
	}
	return relay
}

func e2eInstallClient(t *testing.T, root, home, relayURL, machineID, mailbox, mailboxState string, enable bool) {
	t.Helper()
	arguments := []string{filepath.Join(root, "scripts", "install-client.sh"), "--relay-url", relayURL, "--machine-id", machineID, "--agent-mailbox-bin", mailbox, "--mailbox-state-dir", mailboxState}
	if enable {
		arguments = append(arguments, "--enable")
	}
	environment := e2eEnvironment(e2eGoEnvironment(), map[string]string{"HOME": home})
	e2eRun(t, root, environment, "sh", arguments...)
}

func e2eEnrollmentSet(t *testing.T, homes ...string) string {
	t.Helper()
	records := make([]json.RawMessage, 0, len(homes))
	for _, home := range homes {
		raw, err := os.ReadFile(filepath.Join(home, ".config", "punaro", "enrollment.json"))
		if err != nil || !json.Valid(raw) {
			t.Fatal("read public disposable client enrollment")
		}
		records = append(records, append(json.RawMessage(nil), raw...))
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatal("encode disposable relay enrollment")
	}
	return string(encoded)
}

func e2eRewriteRelayURL(t *testing.T, profile, relayURL string) {
	t.Helper()
	raw, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal("read disposable client profile")
	}
	lines := strings.Split(string(raw), "\n")
	changed := false
	for index, line := range lines {
		if strings.HasPrefix(line, "PUNARO_ADAPTER_RELAY_URL=") {
			lines[index] = "PUNARO_ADAPTER_RELAY_URL=" + relayURL
			changed = true
		}
	}
	if !changed || os.WriteFile(profile, []byte(strings.Join(lines, "\n")), 0o600) != nil {
		t.Fatal("configure disposable client relay route")
	}
}

func e2eIsolatedLaunchAgent(t *testing.T, installedServicePath, home, profile, binary, fixture string) string {
	t.Helper()
	raw, err := os.ReadFile(installedServicePath)
	if err != nil {
		t.Fatal("read installed receiver service definition")
	}
	label := "org.punaro.adapter.e2e-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	labelPattern := regexp.MustCompile(`<key>Label</key>\s*<string>org\.punaro\.adapter</string>`)
	rewritten := labelPattern.ReplaceAll(raw, []byte("<key>Label</key>\n  <string>"+label+"</string>"))
	rewritten = []byte(strings.Replace(string(rewritten), `set -a; . "$HOME/.config/punaro/adapter.env"; set +a; `, "", 1))
	isolationCommand := `exec /usr/bin/env -i HOME="` + home + `" PATH="/usr/bin:/bin:/usr/sbin:/sbin" ` + adapterProfileFileEnv + `="` + profile + `" "` + binary + `"`
	rewritten = []byte(strings.Replace(string(rewritten), `exec "$HOME/.local/bin/punaro-adapter"`, isolationCommand, 1))
	if string(rewritten) == string(raw) || strings.Contains(string(rewritten), `"$HOME/.config/punaro/adapter.env"`) || strings.Contains(string(rewritten), `"$HOME/.local/bin/punaro-adapter"`) || !strings.Contains(string(rewritten), `exec /usr/bin/env -i`) || !strings.Contains(string(rewritten), adapterProfileFileEnv) {
		t.Fatal("isolate installed receiver service definition")
	}
	path := filepath.Join(fixture, "receiver-launch-agent.plist")
	if err := os.WriteFile(path, rewritten, 0o600); err != nil {
		t.Fatal("write isolated receiver service definition")
	}
	return path
}

func e2eCreateConversation(t *testing.T, binary, profile, sender, receiver string) string {
	t.Helper()
	arguments := []string{"create", "--creator", sender, "--member", sender + ":send,receive,admin", "--member", receiver + ":receive", "--idempotency-key", "e2e-create-" + uuid.NewString()}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		output, err := e2eTryAdapterCommand(binary, profile, arguments...)
		if err == nil {
			var result struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(output, &result) == nil && result.ID != "" {
				return result.ID
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("create conversation through installed sender adapter")
	return ""
}

func e2eRejectUnauthorizedLease(t *testing.T, relayURL, senderHome, receiverEndpoint string) {
	t.Helper()
	privateKey, err := loadPrivateKey(filepath.Join(senderHome, ".config", "punaro", "machine.key"))
	if err != nil {
		t.Fatal("load installed sender identity for unauthorized lease check")
	}
	client, err := adapter.NewHTTPRelayClient(relayURL, e2eMachineID(t, senderHome), privateKey, &http.Client{Timeout: 10 * time.Second}, adapter.AccessServiceToken{})
	if err != nil {
		t.Fatal("create installed sender relay client for unauthorized lease check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.Lease(ctx, receiverEndpoint); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatal("enrolled sender lease was not rejected as forbidden")
	}
}

func e2eAdvertiseEndpoint(t *testing.T, relayURL, home, endpoint string) {
	t.Helper()
	privateKey, err := loadPrivateKey(filepath.Join(home, ".config", "punaro", "machine.key"))
	if err != nil {
		t.Fatal("load installed client identity for initial relay advertisement")
	}
	client, err := adapter.NewHTTPRelayClient(relayURL, e2eMachineID(t, home), privateKey, &http.Client{Timeout: 10 * time.Second}, adapter.AccessServiceToken{})
	if err != nil {
		t.Fatal("create installed client relay adapter for initial advertisement")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Advertise(ctx, []string{endpoint}); err != nil {
		t.Fatal("advertise installed client endpoint to disposable relay")
	}
}

func e2eMachineID(t *testing.T, home string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, ".config", "punaro", "enrollment.json"))
	if err != nil {
		t.Fatal("read installed sender public enrollment")
	}
	var enrollment struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &enrollment); err != nil || enrollment.ID == "" {
		t.Fatal("decode installed sender public enrollment")
	}
	return enrollment.ID
}

func e2eSend(t *testing.T, binary, profile, conversationID, sender string) {
	t.Helper()
	body := filepath.Join(t.TempDir(), "message.json")
	if err := os.WriteFile(body, []byte(`{"kind":"smoke"}`), 0o600); err != nil {
		t.Fatal("write disposable message input")
	}
	_ = e2eAdapterCommand(t, binary, profile, "send", "--conversation", conversationID, "--from", sender, "--body-file", body, "--idempotency-key", "e2e-send-"+uuid.NewString())
}

func e2eClaim(t *testing.T, mailbox, state, endpoint string) e2eClaimResult {
	t.Helper()
	output := e2eMailboxOutput(t, mailbox, state, "recv", "--for", endpoint, "--json")
	var claim e2eClaimResult
	if err := json.Unmarshal(output, &claim); err != nil || claim.DeliveryID == "" || claim.LeaseToken == "" {
		t.Fatal("claim local Punaro mailbox delivery")
	}
	return claim
}

func e2eAdapterCommand(t *testing.T, binary, profile string, arguments ...string) []byte {
	t.Helper()
	return e2eRun(t, "", e2eEnvironment(e2eGoEnvironment(), map[string]string{adapterProfileFileEnv: profile}), binary, arguments...)
}

func e2eTryAdapterCommand(binary, profile string, arguments ...string) ([]byte, error) {
	command := exec.Command(binary, arguments...)
	command.Env = e2eEnvironment(e2eGoEnvironment(), map[string]string{adapterProfileFileEnv: profile})
	return command.Output()
}

func e2eMailbox(t *testing.T, state string, arguments ...string) {
	t.Helper()
	_ = e2eMailboxOutput(t, "agent-mailbox", state, arguments...)
}

func e2eMailboxOutput(t *testing.T, mailbox, state string, arguments ...string) []byte {
	t.Helper()
	return e2eRun(t, "", e2eGoEnvironment(), mailbox, append([]string{"--state-dir", state}, arguments...)...)
}

func e2eMailboxError(state string, arguments ...string) error {
	command := exec.Command("agent-mailbox", append([]string{"--state-dir", state}, arguments...)...)
	command.Env = e2eGoEnvironment()
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func e2eExpectMailboxTimeout(t *testing.T, state, endpoint string) {
	t.Helper()
	err := e2eMailboxError(state, "wait", "--for", endpoint, "--timeout", "8s", "--json")
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 2 {
		t.Fatal("receiver mailbox did not report the expected empty-delivery timeout")
	}
}

func e2eRun(t *testing.T, directory string, environment []string, binary string, arguments ...string) []byte {
	t.Helper()
	command := exec.Command(binary, arguments...)
	command.Dir = directory
	command.Env = environment
	output, err := command.Output()
	if err != nil {
		t.Fatal("disposable lifecycle command failed")
	}
	return output
}

func e2eGoEnvironment() []string {
	settings := map[string]string{"GOTOOLCHAIN": "local"}
	for _, name := range []string{"GOMODCACHE", "GOCACHE"} {
		output, err := exec.Command("go", "env", name).Output()
		if err == nil && strings.TrimSpace(string(output)) != "" {
			settings[name] = strings.TrimSpace(string(output))
		}
	}
	base := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if found && strings.HasPrefix(name, "PUNARO_") {
			continue
		}
		base = append(base, entry)
	}
	return e2eEnvironment(base, settings)
}

func e2eEnvironment(base []string, additions map[string]string) []string {
	values := make(map[string]string, len(base)+len(additions))
	for _, entry := range base {
		name, value, found := strings.Cut(entry, "=")
		if found {
			values[name] = value
		}
	}
	for name, value := range additions {
		values[name] = value
	}
	result := make([]string, 0, len(values))
	for name, value := range values {
		result = append(result, name+"="+value)
	}
	return result
}

func e2eLaunchctl(arguments ...string) error {
	command := exec.Command("launchctl", arguments...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func e2eReady(address string) bool {
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + address + "/readyz")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func e2eEventually(t *testing.T, timeout time.Duration, condition func() bool, failure string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(failure)
}

func e2eStopProcess(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	_ = command.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-done
	}
}

func strconvItoa(value int) string {
	return fmt.Sprintf("%d", value)
}
