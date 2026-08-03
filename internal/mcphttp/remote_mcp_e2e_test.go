//go:build e2e

package mcphttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	remoteMCPE2EConfigEnv   = "PUNARO_REMOTE_MCP_E2E_CONFIG"
	maxRemoteMCPE2EConfig   = 64 << 10
	maxRemoteMCPE2EResponse = 1 << 20
)

type remoteMCPE2EConfig struct {
	CandidateCommit     string `json:"candidate_commit"`
	Endpoint            string `json:"endpoint"`
	Resource            string `json:"resource"`
	AuthorizationServer string `json:"authorization_server"`
	Tokens              struct {
		Valid             string `json:"valid"`
		Invalid           string `json:"invalid"`
		WrongIssuer       string `json:"wrong_issuer"`
		WrongAudience     string `json:"wrong_audience"`
		Expired           string `json:"expired"`
		Revoked           string `json:"revoked"`
		NoScope           string `json:"no_scope"`
		InsufficientScope string `json:"insufficient_scope"`
	} `json:"tokens"`
	AuthorizedTool struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"authorized_tool"`
	ForbiddenTool struct {
		Name           string          `json:"name"`
		Arguments      json.RawMessage `json:"arguments"`
		ExpectedStatus int             `json:"expected_status"`
	} `json:"forbidden_tool"`
	RedactionProbe string `json:"redaction_probe"`
}

type remoteMCPE2EResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

func TestRemoteMCPE2EReleaseCandidate(t *testing.T) {
	config := loadRemoteMCPE2EConfig(t)
	runRemoteMCPE2EReleaseCandidate(t, config)
}

func TestRemoteMCPE2EConfigRejectsIncompleteOrUnsafeInputs(t *testing.T) {
	valid := []byte(`{
		"candidate_commit":"0123456789abcdef0123456789abcdef01234567",
		"endpoint":"https://mcp.example.test/mcp",
		"resource":"https://mcp.example.test/mcp",
		"authorization_server":"https://auth.example.test",
		"tokens":{"valid":"aaaaaaaaaaaaaaaa","invalid":"bbbbbbbbbbbbbbbb","wrong_issuer":"cccccccccccccccc","wrong_audience":"dddddddddddddddd","expired":"eeeeeeeeeeeeeeee","revoked":"ffffffffffffffff","no_scope":"gggggggggggggggg","insufficient_scope":"hhhhhhhhhhhhhhhh"},
		"authorized_tool":{"name":"punaro_memory_search","arguments":{"query":"e2e"}},
		"forbidden_tool":{"name":"punaro_memory_propose","arguments":{},"expected_status":403},
		"redaction_probe":"not-a-secret-redaction-probe"
	}`)
	if _, err := parseRemoteMCPE2EConfig(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, replacement := range [][]byte{
		bytes.Replace(valid, []byte(`"https://mcp.example.test/mcp"`), []byte(`"http://mcp.example.test/mcp"`), 1),
		bytes.Replace(valid, []byte(`"expected_status":403`), []byte(`"expected_status":200`), 1),
		bytes.Replace(valid, []byte(`"valid":"aaaaaaaaaaaaaaaa"`), []byte(`"valid":""`), 1),
		bytes.Replace(valid, []byte(`"valid":"aaaaaaaaaaaaaaaa"`), []byte(`"valid":"bad\nvalue"`), 1),
		bytes.Replace(valid, []byte(`"redaction_probe":"not-a-secret-redaction-probe"`), []byte(`"redaction_probe":"bad\"value"`), 1),
		bytes.Replace(valid, []byte(`{"query":"e2e"}`), []byte(`{"query":"e2e","query":"other"}`), 1),
		append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"candidate_commit":"0123456789abcdef0123456789abcdef01234567"}`)...),
	} {
		if _, err := parseRemoteMCPE2EConfig(replacement); err == nil {
			t.Fatal("unsafe E2E config accepted")
		}
	}
}

func TestRemoteMCPE2EReleaseCandidateHarness(t *testing.T) {
	var config remoteMCPE2EConfig
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(response).Encode(map[string]any{"resource": config.Resource, "authorization_servers": []string{config.AuthorizationServer}})
			return
		}
		if request.URL.Path != "/mcp" {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			response.Header().Set("WWW-Authenticate", `Bearer realm="punaro-mcp", resource_metadata="https://metadata.example.test", scope="memory.search memory.read memory.propose"`)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		if token == config.Tokens.NoScope {
			response.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			response.WriteHeader(http.StatusForbidden)
			return
		}
		if token == config.Tokens.InsufficientScope {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		if token != config.Tokens.Valid {
			response.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(request.Body)
		if bytes.HasPrefix(body, []byte("[")) || bytes.Contains(body, []byte(`"method":"tools/list","method"`)) || bytes.Contains(body, []byte(`"id":{}`)) || bytes.Contains(body, []byte(`"extra":true`)) {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"jsonrpc":"2.0","id":"remote-mcp-e2e","result":{}}`))
	}))
	defer server.Close()
	config = remoteMCPE2EFixtureConfig(t, server.URL+"/mcp")
	runRemoteMCPE2EReleaseCandidateWithClient(t, config, server.Client())
}

func remoteMCPE2EFixtureConfig(t *testing.T, endpoint string) remoteMCPE2EConfig {
	t.Helper()
	config, err := parseRemoteMCPE2EConfig([]byte(`{
		"candidate_commit":"0123456789abcdef0123456789abcdef01234567",
		"endpoint":"` + endpoint + `",
		"resource":"` + endpoint + `",
		"authorization_server":"https://auth.example.test",
		"tokens":{"valid":"aaaaaaaaaaaaaaaa","invalid":"bbbbbbbbbbbbbbbb","wrong_issuer":"cccccccccccccccc","wrong_audience":"dddddddddddddddd","expired":"eeeeeeeeeeeeeeee","revoked":"ffffffffffffffff","no_scope":"gggggggggggggggg","insufficient_scope":"hhhhhhhhhhhhhhhh"},
		"authorized_tool":{"name":"punaro_memory_search","arguments":{"query":"e2e"}},
		"forbidden_tool":{"name":"punaro_memory_propose","arguments":{},"expected_status":403},
		"redaction_probe":"not-a-secret-redaction-probe"
	}`))
	if err != nil {
		t.Fatal("remote MCP E2E fixture configuration is invalid")
	}
	return config
}

func loadRemoteMCPE2EConfig(t *testing.T) remoteMCPE2EConfig {
	t.Helper()
	configPath := os.Getenv(remoteMCPE2EConfigEnv)
	if configPath == "" {
		t.Skip("set PUNARO_REMOTE_MCP_E2E_CONFIG to run the remote MCP release-candidate E2E test")
	}
	contents, err := os.ReadFile(configPath) // #nosec G304 -- operator-selected private E2E configuration.
	if err != nil {
		t.Fatal("remote MCP E2E configuration is unavailable")
	}
	if len(contents) > maxRemoteMCPE2EConfig {
		t.Fatal("remote MCP E2E configuration is too large")
	}
	config, err := parseRemoteMCPE2EConfig(contents)
	if err != nil {
		t.Fatal("remote MCP E2E configuration is invalid")
	}
	return config
}

func parseRemoteMCPE2EConfig(raw []byte) (remoteMCPE2EConfig, error) {
	if !validJSONRPCValue(raw, maxJSONRPCDepth) {
		return remoteMCPE2EConfig{}, errors.New("invalid remote MCP E2E configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config remoteMCPE2EConfig
	if err := decoder.Decode(&config); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return remoteMCPE2EConfig{}, errors.New("invalid remote MCP E2E configuration")
	}
	if !validCommit(config.CandidateCommit) || !validRemoteMCPE2EURL(config.Endpoint, true) || config.Endpoint != config.Resource || !validRemoteMCPE2EURL(config.Resource, true) || !validRemoteMCPE2EURL(config.AuthorizationServer, false) || !validRemoteMCPE2EBearer(config.RedactionProbe) {
		return remoteMCPE2EConfig{}, errors.New("invalid remote MCP E2E configuration")
	}
	seen := map[string]struct{}{config.RedactionProbe: {}}
	for _, token := range config.tokens() {
		if !validRemoteMCPE2EBearer(token) {
			return remoteMCPE2EConfig{}, errors.New("invalid remote MCP E2E configuration")
		}
		if _, duplicate := seen[token]; duplicate {
			return remoteMCPE2EConfig{}, errors.New("invalid remote MCP E2E configuration")
		}
		seen[token] = struct{}{}
	}
	if !validRemoteMCPE2ETool(config.AuthorizedTool.Name, config.AuthorizedTool.Arguments) || !validRemoteMCPE2ETool(config.ForbiddenTool.Name, config.ForbiddenTool.Arguments) || config.ForbiddenTool.ExpectedStatus < 400 || config.ForbiddenTool.ExpectedStatus > 499 {
		return remoteMCPE2EConfig{}, errors.New("invalid remote MCP E2E configuration")
	}
	return config, nil
}

func validCommit(raw string) bool {
	if len(raw) != 40 {
		return false
	}
	for _, character := range raw {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validRemoteMCPE2EURL(raw string, requirePath bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != raw || strings.Contains(parsed.Host, "@") {
		return false
	}
	if requirePath {
		return parsed.Path != "" && parsed.Path != "/" && path.Clean(parsed.EscapedPath()) == parsed.EscapedPath()
	}
	return parsed.Path == "" || parsed.Path == "/"
}

func validRemoteMCPE2ETool(name string, arguments json.RawMessage) bool {
	if name == "" || len(name) > 128 || strings.TrimSpace(name) != name || !validJSONObject(arguments, maxJSONRPCDepth) {
		return false
	}
	return true
}

func validRemoteMCPE2EBearer(value string) bool {
	if len(value) < 16 || len(value) > 16<<10 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("-._~+/=", rune(character))) {
			return false
		}
	}
	return true
}

func (config remoteMCPE2EConfig) tokens() []string {
	return []string{config.Tokens.Valid, config.Tokens.Invalid, config.Tokens.WrongIssuer, config.Tokens.WrongAudience, config.Tokens.Expired, config.Tokens.Revoked, config.Tokens.NoScope, config.Tokens.InsufficientScope}
}

func (config remoteMCPE2EConfig) sensitiveValues() []string {
	return append(config.tokens(), config.RedactionProbe)
}

func runRemoteMCPE2EReleaseCandidate(t *testing.T, config remoteMCPE2EConfig) {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	runRemoteMCPE2EReleaseCandidateWithClient(t, config, client)
}

func runRemoteMCPE2EReleaseCandidateWithClient(t *testing.T, config remoteMCPE2EConfig, client *http.Client) {
	t.Helper()
	if client == nil {
		t.Fatal("remote MCP E2E HTTP client is unavailable")
	}
	metadata := remoteMCPE2EDo(t, client, http.MethodGet, remoteMCPE2EMetadataURL(t, config.Resource), "", nil)
	if metadata.Status != http.StatusOK || !strings.Contains(metadata.Header.Get("Content-Type"), "application/json") || metadata.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("protected-resource discovery did not return the required metadata response")
	}
	var document struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if json.Unmarshal(metadata.Body, &document) != nil || document.Resource != config.Resource || !slices.Contains(document.AuthorizationServers, config.AuthorizationServer) {
		t.Fatal("protected-resource discovery metadata is invalid")
	}

	unauthorized := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, "", remoteMCPE2ERequest(t, "tools/list", map[string]any{}))
	remoteMCPE2ERequireStatus(t, unauthorized, http.StatusUnauthorized)
	remoteMCPE2ERedacted(t, unauthorized, config.sensitiveValues())
	challenge := unauthorized.Header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, "Bearer") || !strings.Contains(challenge, "resource_metadata=") || !strings.Contains(challenge, `scope="memory.search memory.read memory.propose"`) {
		t.Fatal("unauthorized request did not return the OAuth discovery challenge")
	}

	for _, token := range []string{config.Tokens.Invalid, config.Tokens.WrongIssuer, config.Tokens.WrongAudience, config.Tokens.Expired, config.Tokens.Revoked} {
		response := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, token, remoteMCPE2ERequest(t, "tools/list", map[string]any{}))
		remoteMCPE2ERequireStatus(t, response, http.StatusUnauthorized)
		remoteMCPE2ERedacted(t, response, config.sensitiveValues())
		if !strings.Contains(response.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Fatal("invalid bearer token did not return the OAuth invalid-token challenge")
		}
	}

	noScope := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, config.Tokens.NoScope, remoteMCPE2ERequest(t, "tools/list", map[string]any{}))
	remoteMCPE2ERequireStatus(t, noScope, http.StatusForbidden)
	remoteMCPE2ERedacted(t, noScope, config.sensitiveValues())
	if !strings.Contains(noScope.Header.Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Fatal("missing required scope did not return an insufficient-scope challenge")
	}

	for _, malformedRequest := range [][]byte{
		[]byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}`),
		[]byte(`{"jsonrpc":"2.0","id":{},"method":"tools/list"}`),
		[]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","extra":true}`),
	} {
		malformed := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, config.Tokens.Valid, malformedRequest)
		remoteMCPE2ERedacted(t, malformed, config.sensitiveValues())
		remoteMCPE2ERequireJSONRPCFailure(t, malformed)
	}

	authorized := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, config.Tokens.Valid, remoteMCPE2ERequest(t, "tools/call", map[string]any{"name": config.AuthorizedTool.Name, "arguments": config.AuthorizedTool.Arguments}))
	remoteMCPE2ERequireJSONRPCSuccess(t, authorized)

	forbidden := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, config.Tokens.InsufficientScope, remoteMCPE2ERequest(t, "tools/call", map[string]any{"name": config.ForbiddenTool.Name, "arguments": config.ForbiddenTool.Arguments}))
	remoteMCPE2ERequireStatus(t, forbidden, config.ForbiddenTool.ExpectedStatus)
	remoteMCPE2ERedacted(t, forbidden, config.sensitiveValues())
	remoteMCPE2ERequireJSONRPCFailure(t, forbidden)

	redacted := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, config.RedactionProbe, remoteMCPE2ERequest(t, "tools/list", map[string]any{"probe": config.RedactionProbe}))
	remoteMCPE2ERequireStatus(t, redacted, http.StatusUnauthorized)
	remoteMCPE2ERedacted(t, redacted, config.sensitiveValues())
	t.Logf("remote MCP release-candidate E2E evidence passed for candidate_commit=%s", config.CandidateCommit)
}

func remoteMCPE2EMetadataURL(t *testing.T, resource string) string {
	t.Helper()
	parsed, err := url.Parse(resource)
	if err != nil {
		t.Fatal("remote MCP resource is invalid")
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: "/.well-known/oauth-protected-resource" + parsed.EscapedPath()}).String()
}

func remoteMCPE2ERequest(t *testing.T, method string, params any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "remote-mcp-e2e", "method": method, "params": params})
	if err != nil {
		t.Fatal("remote MCP E2E request could not be encoded")
	}
	return raw
}

func remoteMCPE2EDo(t *testing.T, client *http.Client, method, endpoint, token string, body []byte) remoteMCPE2EResponse {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal("remote MCP E2E request could not be created")
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("remote MCP E2E request failed")
	}
	defer response.Body.Close()
	body, err = io.ReadAll(io.LimitReader(response.Body, maxRemoteMCPE2EResponse+1))
	if err != nil || len(body) > maxRemoteMCPE2EResponse {
		t.Fatal("remote MCP E2E response is invalid")
	}
	return remoteMCPE2EResponse{Status: response.StatusCode, Header: response.Header.Clone(), Body: body}
}

func remoteMCPE2ERequireStatus(t *testing.T, response remoteMCPE2EResponse, expected int) {
	t.Helper()
	if response.Status != expected {
		t.Fatalf("remote MCP E2E response status=%d, want %d", response.Status, expected)
	}
}

func remoteMCPE2ERequireJSONRPCSuccess(t *testing.T, response remoteMCPE2EResponse) {
	t.Helper()
	if response.Status < 200 || response.Status > 299 {
		t.Fatalf("authorized MCP request status=%d", response.Status)
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(response.Body, &envelope) != nil || envelope.JSONRPC != "2.0" || len(envelope.Result) == 0 || len(envelope.Error) != 0 {
		t.Fatal("authorized MCP request did not return a JSON-RPC result")
	}
}

func remoteMCPE2ERequireJSONRPCFailure(t *testing.T, response remoteMCPE2EResponse) {
	t.Helper()
	if response.Status >= 400 {
		return
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(response.Body, &envelope) != nil || envelope.JSONRPC != "2.0" || len(envelope.Result) != 0 || len(envelope.Error) == 0 {
		t.Fatal("MCP request did not fail closed")
	}
}

func remoteMCPE2ERedacted(t *testing.T, response remoteMCPE2EResponse, sensitive []string) {
	t.Helper()
	values := string(response.Body)
	for _, headerValues := range response.Header {
		values += "\n" + strings.Join(headerValues, "\n")
	}
	for _, value := range sensitive {
		if strings.Contains(values, value) {
			t.Fatal("remote MCP failure exposed a protected request value")
		}
	}
}
