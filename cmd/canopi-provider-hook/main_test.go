package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/canopi/protocol"
	"github.com/rock3r/punaro/internal/canopi"
	"github.com/rock3r/punaro/internal/canopiadapter"
)

func TestProviderHookQueuesCodexAndGrokWithoutForwardingProviderContent(t *testing.T) {
	for _, fixture := range []struct {
		name     string
		provider provider
		raw      string
		want     protocol.Source
	}{
		{name: "Codex", provider: providerCodex, raw: `{"session_id":"thread-1","cwd":"/src/punaro","hook_event_name":"PermissionRequest","tool_input":{"command":"private command"}}`, want: protocol.SourceCodex},
		{name: "Grok", provider: providerGrok, raw: `{"sessionId":"thread-1","cwd":"/src/punaro","hookEventName":"Notification","notificationType":"idle_prompt","lastAssistantMessage":"private answer"}`, want: protocol.SourceGrokBuild},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			environment := testProviderEnvironment(t)
			if err := runPrepare(fixture.provider, func(key string) string { return environment[key] }); err != nil {
				t.Fatal(err)
			}
			if err := runHookAt(fixture.provider, bytes.NewBufferString(fixture.raw), func(key string) string { return environment[key] }, func() error { return nil }, time.Now()); err != nil {
				t.Fatal(err)
			}
			spool := canopiadapter.Spool{Directory: environment["CANOPI_SPOOL_DIR"]}
			var events []protocol.Event
			if err := spool.Drain(t.Context(), func(_ context.Context, event protocol.Event) error {
				events = append(events, event)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(events) != 1 || events[0].Source != fixture.want {
				t.Fatalf("events = %+v", events)
			}
		})
	}
}

func TestProviderHookQueuesNormalizedPiExtensionEvent(t *testing.T) {
	environment := testProviderEnvironment(t)
	if err := runPrepare(providerPi, func(key string) string { return environment[key] }); err != nil {
		t.Fatal(err)
	}
	event, err := canopiadapter.MapPiLifecycle("pi-session-1", "agent_start", protocol.StateWorking, "", canopiadapter.AdapterConfig{MachineID: "studio-m2", TaskTitle: "Punaro / tests"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := runEmit(providerPi, bytes.NewReader(payload), func(key string) string { return environment[key] }, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	spool := canopiadapter.Spool{Directory: environment["CANOPI_SPOOL_DIR"]}
	if got, err := spool.Pending(); err != nil || got != 1 {
		t.Fatalf("pending events = %d, %v", got, err)
	}
}

func TestProviderHookExamplesArePrivacySafeAndMapToSupportedLifecycles(t *testing.T) {
	for _, fixture := range []struct {
		name     string
		path     string
		provider provider
		events   []string
	}{
		{name: "Codex", path: filepath.Join("..", "..", "canopi", "providers", "codex-hooks.example.json"), provider: providerCodex, events: []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PermissionRequest", "SubagentStart", "SubagentStop", "Stop"}},
		{name: "Grok Build", path: filepath.Join("..", "..", "canopi", "providers", "grok-build-hooks.example.json"), provider: providerGrok, events: []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Notification", "SubagentStart", "SubagentStop", "Stop"}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			payload, err := os.ReadFile(fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(payload), "tool_input") || strings.Contains(string(payload), "transcript") {
				t.Fatal("example config interpolates private provider content")
			}
			var parsed struct {
				Hooks map[string]json.RawMessage `json:"hooks"`
			}
			if err := json.Unmarshal(payload, &parsed); err != nil {
				t.Fatal(err)
			}
			for _, event := range fixture.events {
				if _, ok := parsed.Hooks[event]; !ok {
					t.Fatalf("missing lifecycle hook %q", event)
				}
			}
		})
	}
}

func TestCodexHookExampleLoadsInInstalledCodex(t *testing.T) {
	codexPath, err := exec.LookPath("codex")
	if err != nil {
		t.Skip("Codex CLI is not installed on this test host")
	}
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(project, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join("..", "..", "canopi", "providers", "codex-hooks.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".codex", "hooks.json"), payload, 0o600); err != nil { // #nosec G703 -- project is created by this test with t.TempDir.
		t.Fatal(err)
	}
	codexHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(codexHome, "hooks.json"), payload, 0o600); err != nil { // #nosec G703 -- codexHome is created by this test with t.TempDir.
		t.Fatal(err)
	}
	context, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(context, codexPath, "app-server", "--enable", "hooks", "--stdio") // #nosec G204 -- the resolved installed Codex path is a host contract test input.
	command.Dir = project
	command.Env = append(os.Environ(), "CODEX_HOME="+codexHome)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	encoder := json.NewEncoder(stdin)
	if err := encoder.Encode(map[string]any{"id": 1, "method": "initialize", "params": map[string]any{"clientInfo": map[string]string{"name": "canopi-contract-test", "version": "1"}, "capabilities": map[string]any{"experimentalApi": true}}}); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if _, err := waitForJSONRPCResponse(scanner, 1); err != nil {
		t.Fatalf("initialize Codex app server: %v; stderr=%s", err, stderr.String())
	}
	if err := encoder.Encode(map[string]any{"id": 2, "method": "hooks/list", "params": map[string]any{"cwds": []string{project}}}); err != nil {
		t.Fatal(err)
	}
	response, err := waitForJSONRPCResponse(scanner, 2)
	if err != nil {
		t.Fatalf("list Codex hooks: %v; stderr=%s", err, stderr.String())
	}
	result, _ := response["result"].(map[string]any)
	data, _ := result["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("Codex hook data = %#v", result["data"])
	}
	entry, _ := data[0].(map[string]any)
	if errors, _ := entry["errors"].([]any); len(errors) != 0 {
		t.Fatalf("Codex rejected example hooks: %#v", errors)
	}
	hooks, _ := entry["hooks"].([]any)
	if len(hooks) != 8 {
		t.Fatalf("Codex loaded %d hooks, want 8: %#v; result=%#v", len(hooks), hooks, result)
	}
}

func TestGrokBuildHookExampleLoadsInInstalledInspector(t *testing.T) {
	grokPath, err := exec.LookPath("grok")
	if err != nil {
		t.Skip("Grok Build CLI is not installed on this test host")
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed on this test host")
	}
	project := t.TempDir()
	if output, err := exec.CommandContext(t.Context(), gitPath, "init", "--quiet", project).CombinedOutput(); err != nil { // #nosec G204 -- fixed local git initialization in a temporary contract-test project.
		t.Fatalf("initialize temporary Grok Build project: %v: %s", err, output)
	}
	payload, err := os.ReadFile(filepath.Join("..", "..", "canopi", "providers", "grok-build-hooks.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	hooksDirectory := filepath.Join(home, ".grok", "hooks")
	if err := os.MkdirAll(hooksDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooksDirectory, "canopi.json"), payload, 0o600); err != nil { // #nosec G703 -- hooksDirectory is created by this test with t.TempDir.
		t.Fatal(err)
	}
	context, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(context, grokPath, "inspect", "--json") // #nosec G204 -- the resolved installed Grok Build path is a host contract test input.
	command.Dir = project
	command.Env = append(os.Environ(), "HOME="+home, "GROK_HOME="+filepath.Join(home, ".grok"))
	output, err := command.Output()
	if err != nil {
		t.Fatalf("Grok Build inspect: %v", err)
	}
	var inspected struct {
		Hooks []any `json:"hooks"`
	}
	if err := json.Unmarshal(output, &inspected); err != nil {
		t.Fatalf("decode Grok Build inspect output: %v", err)
	}
	if len(inspected.Hooks) != 8 {
		t.Fatalf("Grok Build loaded %d hooks, want 8: %s", len(inspected.Hooks), output)
	}
}

func TestPiExtensionEmitsSessionStartToCollector(t *testing.T) {
	piPath, err := exec.LookPath("pi")
	if err != nil {
		t.Skip("Pi is not installed on this test host")
	}
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Skip("Go is not installed on this test host")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	collector, _, observed := testCollectorWithEvents(t)
	outputPath := filepath.Join(t.TempDir(), "canopi-provider-hook")
	buildContext, cancelBuild := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancelBuild()
	build := exec.CommandContext(buildContext, goPath, "build", "-trimpath", "-o", outputPath, "./cmd/canopi-provider-hook") // #nosec G204 -- fixed local build inputs for the Pi host contract test.
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Pi provider runner: %v: %s", err, output)
	}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token-123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spoolPath := filepath.Join(t.TempDir(), "spool")
	runnerEnvironment := append(os.Environ(),
		"CANOPI_ENDPOINT="+collector.URL,
		"CANOPI_TOKEN_FILE="+tokenPath,
		"CANOPI_MACHINE_ID=pi-contract-test",
		"CANOPI_SPOOL_DIR="+spoolPath,
		"CANOPI_PROVIDER_HOOK="+outputPath,
		"PI_CODING_AGENT_DIR="+t.TempDir(),
	)
	configPath := filepath.Join(t.TempDir(), "canopi.env")
	config := strings.Join([]string{
		"CANOPI_ENDPOINT=" + collector.URL,
		"CANOPI_TOKEN_FILE=" + tokenPath,
		"CANOPI_MACHINE_ID=pi-contract-test",
		"CANOPI_SPOOL_DIR=" + spoolPath,
		"CANOPI_PROVIDER_HOOK=" + outputPath,
	}, "\n") + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	prepare := exec.CommandContext(t.Context(), outputPath, "pi", "prepare") // #nosec G204 -- fixed provider runner built above.
	prepare.Env = runnerEnvironment
	if output, err := prepare.CombinedOutput(); err != nil {
		t.Fatalf("prepare Pi spool: %v: %s", err, output)
	}
	extensionPath := filepath.Join(root, "canopi", "providers", "pi", "canopi.ts")
	piContext, cancelPi := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancelPi()
	pi := exec.CommandContext(piContext, piPath, "--offline", "--no-session", "--mode", "rpc", "--extension", extensionPath) // #nosec G204 -- fixed installed Pi path and repository extension path in a host contract test.
	pi.Dir = root
	pi.Env = append(os.Environ(), "CANOPI_CONFIG_FILE="+configPath, "PI_CODING_AGENT_DIR="+t.TempDir())
	var stdout, stderr bytes.Buffer
	pi.Stdout = &stdout
	pi.Stderr = &stderr
	if err := pi.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pi.Process.Kill()
		_ = pi.Wait()
	})
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case event := <-observed:
			if event.Source == protocol.SourcePi && event.Metadata["hook"] == "session_start" && event.State == protocol.StateWorking {
				return
			}
		case <-deadline.C:
			t.Fatalf("Pi extension did not reach collector; stdout=%s stderr=%s", stdout.String(), stderr.String())
		case <-tick.C:
		}
	}
}

func waitForJSONRPCResponse(scanner *bufio.Scanner, id int) (map[string]any, error) {
	for scanner.Scan() {
		var message map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			continue
		}
		if messageID, ok := message["id"].(float64); ok && int(messageID) == id {
			return message, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("Codex app server closed before its response")
}

func TestProvidersDeliverARealLifecycleToCollectorAndRender(t *testing.T) {
	collector, store := testCollector(t)
	for _, fixture := range []struct {
		name     string
		provider provider
		raw      string
		emit     bool
	}{
		{name: "Codex", provider: providerCodex, raw: `{"session_id":"codex-session","cwd":"/src/punaro","hook_event_name":"PermissionRequest","tool_input":{"command":"private"}}`},
		{name: "Grok", provider: providerGrok, raw: `{"sessionId":"grok-session","cwd":"/src/punaro","hookEventName":"Notification","notificationType":"idle_prompt","lastAssistantMessage":"private"}`},
		{name: "Pi", provider: providerPi, emit: true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			environment := testProviderEnvironment(t)
			environment["CANOPI_ENDPOINT"] = collector.URL
			if err := os.WriteFile(environment["CANOPI_TOKEN_FILE"], []byte("test-token-123456\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := runPrepare(fixture.provider, func(key string) string { return environment[key] }); err != nil {
				t.Fatal(err)
			}
			if fixture.emit {
				event, err := canopiadapter.MapPiLifecycle("pi-session", "agent_settled", protocol.StateWaitingForUser, protocol.WaitingReasonOther, canopiadapter.AdapterConfig{MachineID: "studio-m2"}, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				payload, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				if err := runEmit(fixture.provider, bytes.NewReader(payload), func(key string) string { return environment[key] }, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			} else if err := runHookAt(fixture.provider, bytes.NewBufferString(fixture.raw), func(key string) string { return environment[key] }, func() error { return nil }, time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := runDelivery(fixture.provider, func(key string) string { return environment[key] }); err != nil {
				t.Fatal(err)
			}
		})
	}
	if len(store.Snapshot(time.Now()).Agents) != 3 {
		t.Fatalf("collector agents = %d, want 3", len(store.Snapshot(time.Now()).Agents))
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, collector.URL+"/v1/render/800x480.png", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-token-123456")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("render response = %d %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	config, err := png.DecodeConfig(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if config.Width != 800 || config.Height != 480 {
		t.Fatalf("render dimensions = %dx%d, want 800x480", config.Width, config.Height)
	}
}

func testCollector(t *testing.T) (*httptest.Server, *canopi.Store) {
	t.Helper()
	server, store, _ := testCollectorWithEvents(t)
	return server, store
}

func testCollectorWithEvents(t *testing.T) (*httptest.Server, *canopi.Store, <-chan protocol.Event) {
	t.Helper()
	store := canopi.NewStore(canopi.DefaultConfig())
	handler, err := canopi.NewHandler(canopi.HandlerConfig{
		Store:  store,
		Token:  "test-token-123456",
		Render: canopi.RenderConfig{Width: 800, Height: 480, Grid: canopi.GridConfig{Columns: 2, Rows: 6}, RelativeTimeBucket: time.Minute, Title: "CANOPI"},
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan protocol.Event, 16)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost && request.URL.Path == "/v1/events" {
			payload, readErr := io.ReadAll(request.Body)
			if readErr == nil {
				var event protocol.Event
				if json.Unmarshal(payload, &event) == nil {
					select {
					case observed <- event:
					default:
					}
				}
				request.Body = io.NopCloser(bytes.NewReader(payload))
			}
		}
		handler.ServeHTTP(writer, request)
	}))
	t.Cleanup(server.Close)
	return server, store, observed
}

func testProviderEnvironment(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"CANOPI_ENDPOINT":   "http://canopi.test",
		"CANOPI_TOKEN_FILE": filepath.Join(t.TempDir(), "token"),
		"CANOPI_MACHINE_ID": "studio-m2",
		"CANOPI_SPOOL_DIR":  filepath.Join(t.TempDir(), "spool"),
	}
}
