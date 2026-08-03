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
	"os/exec"
	"path"
	"reflect"
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
	ProtocolVersion     string `json:"protocol_version"`
	Tokens              struct {
		Valid         string `json:"valid"`
		Invalid       string `json:"invalid"`
		WrongIssuer   string `json:"wrong_issuer"`
		WrongAudience string `json:"wrong_audience"`
		Expired       string `json:"expired"`
		Revoked       struct {
			Token          string `json:"token"`
			ExpectedStatus int    `json:"expected_status"`
		} `json:"revoked"`
		NoScope           string `json:"no_scope"`
		InsufficientScope string `json:"insufficient_scope"`
	} `json:"tokens"`
	AuthorizedTool struct {
		Name           string          `json:"name"`
		Arguments      json.RawMessage `json:"arguments"`
		ExpectedResult json.RawMessage `json:"expected_result"`
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
		"protocol_version":"2024-11-05",
		"tokens":{"valid":"aaaaaaaaaaaaaaaa","invalid":"bbbbbbbbbbbbbbbb","wrong_issuer":"cccccccccccccccc","wrong_audience":"dddddddddddddddd","expired":"eeeeeeeeeeeeeeee","revoked":{"token":"ffffffffffffffff","expected_status":403},"no_scope":"gggggggggggggggg","insufficient_scope":"hhhhhhhhhhhhhhhh"},
		"authorized_tool":{"name":"punaro_memory_search","arguments":{"query":"e2e"},"expected_result":{"content":[{"type":"text","text":"release-candidate-e2e"}]}},
		"forbidden_tool":{"name":"punaro_memory_propose","arguments":{},"expected_status":403},
		"redaction_probe":"not-a-secret-redaction-probe"
	}`)
	if _, err := parseRemoteMCPE2EConfig(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, replacement := range [][]byte{
		bytes.Replace(valid, []byte(`"https://mcp.example.test/mcp"`), []byte(`"http://mcp.example.test/mcp"`), 1),
		bytes.Replace(valid, []byte(`"forbidden_tool":{"name":"punaro_memory_propose","arguments":{},"expected_status":403}`), []byte(`"forbidden_tool":{"name":"punaro_memory_propose","arguments":{},"expected_status":200}`), 1),
		bytes.Replace(valid, []byte(`"token":"ffffffffffffffff","expected_status":403`), []byte(`"token":"ffffffffffffffff","expected_status":418`), 1),
		bytes.Replace(valid, []byte(`"valid":"aaaaaaaaaaaaaaaa"`), []byte(`"valid":""`), 1),
		bytes.Replace(valid, []byte(`"valid":"aaaaaaaaaaaaaaaa"`), []byte(`"valid":"bad\nvalue"`), 1),
		bytes.Replace(valid, []byte(`"redaction_probe":"not-a-secret-redaction-probe"`), []byte(`"redaction_probe":"bad\"value"`), 1),
		bytes.Replace(valid, []byte(`{"query":"e2e"}`), []byte(`{"query":"e2e","query":"other"}`), 1),
		bytes.Replace(valid, []byte(`"expected_result":{"content":[{"type":"text","text":"release-candidate-e2e"}]}`), []byte(`"expected_result":{}`), 1),
		append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"candidate_commit":"0123456789abcdef0123456789abcdef01234567"}`)...),
	} {
		if _, err := parseRemoteMCPE2EConfig(replacement); err == nil {
			t.Fatal("unsafe E2E config accepted")
		}
	}
}

func TestRemoteMCPE2EChallengeRequiresExactResourceMetadata(t *testing.T) {
	const want = "https://mcp.example.test/.well-known/oauth-protected-resource/mcp"
	challenge := `Bearer realm="punaro-mcp", resource_metadata="` + want + `", scope="memory.search memory.read memory.propose"`
	if got, ok := remoteMCPE2EChallengeParameter(challenge, "resource_metadata"); !ok || got != want {
		t.Fatalf("resource_metadata=%q ok=%t", got, ok)
	}
	if _, ok := remoteMCPE2EChallengeParameter(`Bearer resource_metadata="https://other.example.test"`, "scope"); ok {
		t.Fatal("missing challenge parameter accepted")
	}
}

func TestRemoteMCPE2EJSONRPCSuccessRequiresExactCorrelatedToolResult(t *testing.T) {
	want := json.RawMessage(`{"content":[{"type":"text","text":"release-candidate-e2e"}]}`)
	valid := remoteMCPE2EResponse{Status: http.StatusOK, Body: []byte(`{"jsonrpc":"2.0","id":"remote-mcp-e2e","result":{"content":[{"type":"text","text":"release-candidate-e2e"}]}}`)}
	if !validRemoteMCPE2EJSONRPCSuccess(valid, want) {
		t.Fatal("valid correlated MCP tool result rejected")
	}
	for _, response := range []remoteMCPE2EResponse{
		{Status: http.StatusOK, Body: []byte(`{"jsonrpc":"2.0","id":"wrong","result":{"content":[{"type":"text","text":"release-candidate-e2e"}]}}`)},
		{Status: http.StatusOK, Body: []byte(`{"jsonrpc":"2.0","id":"remote-mcp-e2e","result":{}}`)},
		{Status: http.StatusOK, Body: []byte(`{"jsonrpc":"2.0","id":"remote-mcp-e2e","result":{"content":[{"type":"text","text":"other"}]}}`)},
	} {
		if validRemoteMCPE2EJSONRPCSuccess(response, want) {
			t.Fatal("uncorrelated or invalid MCP tool result accepted")
		}
	}
}

func TestRemoteMCPE2ERevocationRequiresConfiguredClosedRejection(t *testing.T) {
	invalidToken := remoteMCPE2EResponse{Status: http.StatusUnauthorized, Header: http.Header{"Www-Authenticate": []string{`Bearer error="invalid_token"`}}}
	inactiveSubject := remoteMCPE2EResponse{Status: http.StatusForbidden}
	if !validRemoteMCPE2ERevocationResponse(invalidToken, http.StatusUnauthorized) {
		t.Fatal("token revocation rejection rejected")
	}
	if !validRemoteMCPE2ERevocationResponse(inactiveSubject, http.StatusForbidden) {
		t.Fatal("inactive subject revocation rejection rejected")
	}
	if validRemoteMCPE2ERevocationResponse(invalidToken, http.StatusForbidden) || validRemoteMCPE2ERevocationResponse(inactiveSubject, http.StatusUnauthorized) {
		t.Fatal("revocation accepted the wrong rejection boundary")
	}
}

func TestRemoteMCPE2EConfigReadIsBounded(t *testing.T) {
	if _, err := readRemoteMCPE2EConfig(strings.NewReader(strings.Repeat("x", maxRemoteMCPE2EConfig+1))); err == nil {
		t.Fatal("oversized E2E config accepted")
	}
}

func TestRemoteMCPE2EOAuthErrorChallengeIsStructured(t *testing.T) {
	valid := remoteMCPE2EResponse{Status: http.StatusUnauthorized, Header: http.Header{"Www-Authenticate": []string{`Bearer error="invalid_token"`}}}
	if !validRemoteMCPE2EOAuthErrorChallenge(valid, "invalid_token") {
		t.Fatal("valid Bearer error challenge rejected")
	}
	invalid := remoteMCPE2EResponse{Status: http.StatusUnauthorized, Header: http.Header{"Www-Authenticate": []string{`Basic error="invalid_token"`}}}
	if validRemoteMCPE2EOAuthErrorChallenge(invalid, "invalid_token") {
		t.Fatal("non-Bearer error challenge accepted")
	}
}

func TestRemoteMCPE2EJSONRPCFailureRejectsServerErrors(t *testing.T) {
	if validRemoteMCPE2EJSONRPCFailure(remoteMCPE2EResponse{Status: http.StatusInternalServerError}) {
		t.Fatal("server error accepted as malformed-request rejection")
	}
	if !validRemoteMCPE2EJSONRPCFailure(remoteMCPE2EResponse{Status: http.StatusBadRequest}) {
		t.Fatal("client error rejected as malformed-request rejection")
	}
}

func TestRemoteMCPE2EInitializeRequiresNegotiatedProtocol(t *testing.T) {
	valid := remoteMCPE2EResponse{Status: http.StatusOK, Body: []byte(`{"jsonrpc":"2.0","id":"remote-mcp-e2e-initialize","result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"candidate","version":"1"}}}`)}
	if !validRemoteMCPE2EInitializeSuccess(valid, "2024-11-05") {
		t.Fatal("valid initialize response rejected")
	}
	wrongVersion := remoteMCPE2EResponse{Status: http.StatusOK, Body: []byte(`{"jsonrpc":"2.0","id":"remote-mcp-e2e-initialize","result":{"protocolVersion":"other","capabilities":{},"serverInfo":{"name":"candidate","version":"1"}}}`)}
	if validRemoteMCPE2EInitializeSuccess(wrongVersion, "2024-11-05") {
		t.Fatal("wrong initialize protocol accepted")
	}
}

func TestRemoteMCPE2ECandidateCommitMustMatchCheckout(t *testing.T) {
	if err := validateRemoteMCPE2ECandidateCommit("0123456789abcdef0123456789abcdef01234567", "0123456789abcdef0123456789abcdef01234567"); err != nil {
		t.Fatalf("matching candidate commit rejected: %v", err)
	}
	if err := validateRemoteMCPE2ECandidateCommit("0123456789abcdef0123456789abcdef01234567", "fedcba9876543210fedcba9876543210fedcba98"); err == nil {
		t.Fatal("mismatched candidate commit accepted")
	}
}

func TestRemoteMCPE2EReleaseCandidateHarness(t *testing.T) {
	var config remoteMCPE2EConfig
	var insufficientScopeAuthorized, validForbidden bool
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
			response.Header().Set("WWW-Authenticate", `Bearer realm="punaro-mcp", resource_metadata="https://`+request.Host+`/.well-known/oauth-protected-resource/mcp", scope="memory.search memory.read memory.propose"`)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		if token == config.Tokens.NoScope {
			response.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			response.WriteHeader(http.StatusForbidden)
			return
		}
		if token != config.Tokens.Valid && token != config.Tokens.InsufficientScope {
			response.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(request.Body)
		if token == config.Tokens.InsufficientScope && bytes.Contains(body, []byte(`"name":"punaro_memory_search"`)) {
			insufficientScopeAuthorized = true
		}
		if token == config.Tokens.Valid && bytes.Contains(body, []byte(`"name":"punaro_memory_propose"`)) {
			validForbidden = true
		}
		if bytes.HasPrefix(body, []byte("[")) || bytes.Contains(body, []byte(`"method":"tools/list","method"`)) || bytes.Contains(body, []byte(`"id":{}`)) || bytes.Contains(body, []byte(`"extra":true`)) {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		if bytes.Contains(body, []byte(`"method":"initialize"`)) {
			_, _ = response.Write([]byte(`{"jsonrpc":"2.0","id":"remote-mcp-e2e-initialize","result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"candidate","version":"1"}}}`))
			return
		}
		if bytes.Contains(body, []byte(`"method":"notifications/initialized"`)) {
			response.WriteHeader(http.StatusAccepted)
			return
		}
		if bytes.Contains(body, []byte(`"name":"punaro_memory_propose"`)) {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = response.Write([]byte(`{"jsonrpc":"2.0","id":"remote-mcp-e2e","result":{"content":[{"type":"text","text":"release-candidate-e2e"}]}}`))
	}))
	defer server.Close()
	config = remoteMCPE2EFixtureConfig(t, server.URL+"/mcp")
	runRemoteMCPE2EReleaseCandidateWithClient(t, config, server.Client())
	if !insufficientScopeAuthorized || !validForbidden {
		t.Fatal("scope-boundary probes were not exercised")
	}
}

func remoteMCPE2EFixtureConfig(t *testing.T, endpoint string) remoteMCPE2EConfig {
	t.Helper()
	config, err := parseRemoteMCPE2EConfig([]byte(`{
		"candidate_commit":"0123456789abcdef0123456789abcdef01234567",
		"endpoint":"` + endpoint + `",
		"resource":"` + endpoint + `",
		"authorization_server":"https://auth.example.test",
		"protocol_version":"2024-11-05",
		"tokens":{"valid":"aaaaaaaaaaaaaaaa","invalid":"bbbbbbbbbbbbbbbb","wrong_issuer":"cccccccccccccccc","wrong_audience":"dddddddddddddddd","expired":"eeeeeeeeeeeeeeee","revoked":{"token":"ffffffffffffffff","expected_status":401},"no_scope":"gggggggggggggggg","insufficient_scope":"hhhhhhhhhhhhhhhh"},
		"authorized_tool":{"name":"punaro_memory_search","arguments":{"query":"e2e"},"expected_result":{"content":[{"type":"text","text":"release-candidate-e2e"}]}},
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
	file, err := os.Open(configPath) // #nosec G304 -- operator-selected private E2E configuration.
	if err != nil {
		t.Fatal("remote MCP E2E configuration is unavailable")
	}
	defer file.Close()
	contents, err := readRemoteMCPE2EConfig(file)
	if err != nil {
		t.Fatal("remote MCP E2E configuration is invalid")
	}
	config, err := parseRemoteMCPE2EConfig(contents)
	if err != nil {
		t.Fatal("remote MCP E2E configuration is invalid")
	}
	checkedOutCommit, err := checkedOutRemoteMCPE2ECommit()
	if err != nil || validateRemoteMCPE2ECandidateCommit(config.CandidateCommit, checkedOutCommit) != nil {
		t.Fatal("remote MCP E2E candidate commit does not match the checkout")
	}
	return config
}

func checkedOutRemoteMCPE2ECommit() (string, error) {
	output, err := exec.Command("git", "rev-parse", "HEAD").Output() // #nosec G204 -- fixed local Git command binds evidence to the checkout.
	if err != nil {
		return "", errors.New("candidate commit unavailable")
	}
	commit := strings.TrimSpace(string(output))
	if !validCommit(commit) {
		return "", errors.New("candidate commit unavailable")
	}
	return commit, nil
}

func validateRemoteMCPE2ECandidateCommit(configured, checkedOut string) error {
	if configured != checkedOut {
		return errors.New("candidate commit mismatch")
	}
	return nil
}

func readRemoteMCPE2EConfig(reader io.Reader) ([]byte, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maxRemoteMCPE2EConfig+1))
	if err != nil || len(contents) > maxRemoteMCPE2EConfig {
		return nil, errors.New("invalid remote MCP E2E configuration")
	}
	return contents, nil
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
	if !validCommit(config.CandidateCommit) || !validRemoteMCPE2EURL(config.Endpoint, true) || config.Endpoint != config.Resource || !validRemoteMCPE2EURL(config.Resource, true) || !validRemoteMCPE2EURL(config.AuthorizationServer, false) || !validRemoteMCPE2EProtocolVersion(config.ProtocolVersion) || !validRemoteMCPE2EBearer(config.RedactionProbe) {
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
	if !validRemoteMCPE2ETool(config.AuthorizedTool.Name, config.AuthorizedTool.Arguments) || !validRemoteMCPE2EToolResult(config.AuthorizedTool.ExpectedResult) || !validRemoteMCPE2ETool(config.ForbiddenTool.Name, config.ForbiddenTool.Arguments) || config.ForbiddenTool.ExpectedStatus != http.StatusForbidden || config.Tokens.Revoked.ExpectedStatus != http.StatusUnauthorized && config.Tokens.Revoked.ExpectedStatus != http.StatusForbidden {
		return remoteMCPE2EConfig{}, errors.New("invalid remote MCP E2E configuration")
	}
	return config, nil
}

func validRemoteMCPE2EProtocolVersion(value string) bool {
	if len(value) == 0 || len(value) > 32 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return true
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

func validRemoteMCPE2EToolResult(raw json.RawMessage) bool {
	if !validJSONObject(raw, maxJSONRPCDepth) {
		return false
	}
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if json.Unmarshal(raw, &result) != nil || result.IsError || len(result.Content) == 0 {
		return false
	}
	for _, content := range result.Content {
		if content.Type == "text" && content.Text != "" {
			return true
		}
	}
	return false
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
	return []string{config.Tokens.Valid, config.Tokens.Invalid, config.Tokens.WrongIssuer, config.Tokens.WrongAudience, config.Tokens.Expired, config.Tokens.Revoked.Token, config.Tokens.NoScope, config.Tokens.InsufficientScope}
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
	metadataURL, metadataOK := remoteMCPE2EChallengeParameter(challenge, "resource_metadata")
	scope, scopeOK := remoteMCPE2EChallengeParameter(challenge, "scope")
	if !metadataOK || metadataURL != remoteMCPE2EMetadataURL(t, config.Resource) || !scopeOK || scope != defaultScopeChallenge {
		t.Fatal("unauthorized request did not return the OAuth discovery challenge")
	}

	for _, token := range []string{config.Tokens.Invalid, config.Tokens.WrongIssuer, config.Tokens.WrongAudience, config.Tokens.Expired} {
		response := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, token, remoteMCPE2ERequest(t, "tools/list", map[string]any{}))
		remoteMCPE2ERequireStatus(t, response, http.StatusUnauthorized)
		remoteMCPE2ERedacted(t, response, config.sensitiveValues())
		if !validRemoteMCPE2EOAuthErrorChallenge(response, "invalid_token") {
			t.Fatal("invalid bearer token did not return the OAuth invalid-token challenge")
		}
	}
	revoked := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, config.Tokens.Revoked.Token, remoteMCPE2ERequest(t, "tools/list", map[string]any{}))
	remoteMCPE2ERedacted(t, revoked, config.sensitiveValues())
	if !validRemoteMCPE2ERevocationResponse(revoked, config.Tokens.Revoked.ExpectedStatus) {
		t.Fatal("revoked bearer did not return the configured closed rejection")
	}

	noScope := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, config.Tokens.NoScope, remoteMCPE2ERequest(t, "tools/list", map[string]any{}))
	remoteMCPE2ERequireStatus(t, noScope, http.StatusForbidden)
	remoteMCPE2ERedacted(t, noScope, config.sensitiveValues())
	if !validRemoteMCPE2EOAuthErrorChallenge(noScope, "insufficient_scope") {
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

	validSessionID := remoteMCPE2EInitializeSession(t, client, config, config.Tokens.Valid)
	authorized := remoteMCPE2EDoWithSession(t, client, http.MethodPost, config.Endpoint, config.Tokens.Valid, validSessionID, remoteMCPE2ERequest(t, "tools/call", map[string]any{"name": config.AuthorizedTool.Name, "arguments": config.AuthorizedTool.Arguments}))
	remoteMCPE2ERequireJSONRPCSuccess(t, authorized, config.AuthorizedTool.ExpectedResult)

	insufficientScopeSessionID := remoteMCPE2EInitializeSession(t, client, config, config.Tokens.InsufficientScope)
	insufficientScopeAuthorized := remoteMCPE2EDoWithSession(t, client, http.MethodPost, config.Endpoint, config.Tokens.InsufficientScope, insufficientScopeSessionID, remoteMCPE2ERequest(t, "tools/call", map[string]any{"name": config.AuthorizedTool.Name, "arguments": config.AuthorizedTool.Arguments}))
	remoteMCPE2ERequireJSONRPCSuccess(t, insufficientScopeAuthorized, config.AuthorizedTool.ExpectedResult)
	for _, probe := range []struct {
		token     string
		sessionID string
	}{
		{token: config.Tokens.InsufficientScope, sessionID: insufficientScopeSessionID},
		{token: config.Tokens.Valid, sessionID: validSessionID},
	} {
		forbidden := remoteMCPE2EDoWithSession(t, client, http.MethodPost, config.Endpoint, probe.token, probe.sessionID, remoteMCPE2ERequest(t, "tools/call", map[string]any{"name": config.ForbiddenTool.Name, "arguments": config.ForbiddenTool.Arguments}))
		remoteMCPE2ERequireStatus(t, forbidden, config.ForbiddenTool.ExpectedStatus)
		remoteMCPE2ERedacted(t, forbidden, config.sensitiveValues())
		remoteMCPE2ERequireJSONRPCFailure(t, forbidden)
	}

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
	return remoteMCPE2ERequestWithID(t, "remote-mcp-e2e", method, params)
}

func remoteMCPE2ERequestWithID(t *testing.T, id, method string, params any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		t.Fatal("remote MCP E2E request could not be encoded")
	}
	return raw
}

func remoteMCPE2ENotification(t *testing.T, method string, params any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	if err != nil {
		t.Fatal("remote MCP E2E notification could not be encoded")
	}
	return raw
}

func remoteMCPE2EDo(t *testing.T, client *http.Client, method, endpoint, token string, body []byte) remoteMCPE2EResponse {
	return remoteMCPE2EDoWithSession(t, client, method, endpoint, token, "", body)
}

func remoteMCPE2EDoWithSession(t *testing.T, client *http.Client, method, endpoint, token, sessionID string, body []byte) remoteMCPE2EResponse {
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
	if sessionID != "" {
		request.Header.Set("Mcp-Session-Id", sessionID)
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

func remoteMCPE2ERequireJSONRPCSuccess(t *testing.T, response remoteMCPE2EResponse, expectedResult json.RawMessage) {
	t.Helper()
	if !validRemoteMCPE2EJSONRPCSuccess(response, expectedResult) {
		t.Fatal("authorized MCP request did not return a JSON-RPC result")
	}
}

func validRemoteMCPE2ERevocationResponse(response remoteMCPE2EResponse, expectedStatus int) bool {
	if response.Status != expectedStatus {
		return false
	}
	switch expectedStatus {
	case http.StatusUnauthorized:
		return validRemoteMCPE2EOAuthErrorChallenge(response, "invalid_token")
	case http.StatusForbidden:
		return response.Header.Get("WWW-Authenticate") == ""
	default:
		return false
	}
}

func validRemoteMCPE2EOAuthErrorChallenge(response remoteMCPE2EResponse, expectedError string) bool {
	errorCode, found := remoteMCPE2EChallengeParameter(response.Header.Get("WWW-Authenticate"), "error")
	return found && errorCode == expectedError
}

func remoteMCPE2ERequireInitializeSuccess(t *testing.T, response remoteMCPE2EResponse, expectedProtocolVersion string) {
	t.Helper()
	if !validRemoteMCPE2EInitializeSuccess(response, expectedProtocolVersion) {
		t.Fatal("MCP initialize did not negotiate the configured protocol")
	}
}

func remoteMCPE2EInitializeSession(t *testing.T, client *http.Client, config remoteMCPE2EConfig, token string) string {
	t.Helper()
	initialized := remoteMCPE2EDo(t, client, http.MethodPost, config.Endpoint, token, remoteMCPE2ERequestWithID(t, "remote-mcp-e2e-initialize", "initialize", map[string]any{"protocolVersion": config.ProtocolVersion, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "punaro-remote-mcp-e2e", "version": "1"}}))
	remoteMCPE2ERequireInitializeSuccess(t, initialized, config.ProtocolVersion)
	sessionID := initialized.Header.Get("Mcp-Session-Id")
	notification := remoteMCPE2EDoWithSession(t, client, http.MethodPost, config.Endpoint, token, sessionID, remoteMCPE2ENotification(t, "notifications/initialized", map[string]any{}))
	remoteMCPE2ERequireInitializedNotification(t, notification)
	return sessionID
}

func validRemoteMCPE2EInitializeSuccess(response remoteMCPE2EResponse, expectedProtocolVersion string) bool {
	if response.Status < 200 || response.Status > 299 || !validJSONRPCValue(response.Body, maxJSONRPCDepth) {
		return false
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			ProtocolVersion string          `json:"protocolVersion"`
			Capabilities    json.RawMessage `json:"capabilities"`
			ServerInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	return json.Unmarshal(response.Body, &envelope) == nil && envelope.JSONRPC == "2.0" && len(envelope.Error) == 0 && jsonRawMessageEquals(envelope.ID, json.RawMessage(`"remote-mcp-e2e-initialize"`)) && envelope.Result.ProtocolVersion == expectedProtocolVersion && validJSONObject(envelope.Result.Capabilities, maxJSONRPCDepth) && envelope.Result.ServerInfo.Name != "" && envelope.Result.ServerInfo.Version != ""
}

func remoteMCPE2ERequireInitializedNotification(t *testing.T, response remoteMCPE2EResponse) {
	t.Helper()
	if response.Status < 200 || response.Status > 299 || len(response.Body) != 0 {
		t.Fatal("MCP initialized notification did not complete")
	}
}

func validRemoteMCPE2EJSONRPCSuccess(response remoteMCPE2EResponse, expectedResult json.RawMessage) bool {
	if response.Status < 200 || response.Status > 299 || !validJSONRPCValue(response.Body, maxJSONRPCDepth) || !validRemoteMCPE2EToolResult(expectedResult) {
		return false
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if json.Unmarshal(response.Body, &envelope) != nil || envelope.JSONRPC != "2.0" || len(envelope.Error) != 0 || !jsonRawMessageEquals(envelope.ID, json.RawMessage(`"remote-mcp-e2e"`)) || !jsonRawMessageEquals(envelope.Result, expectedResult) {
		return false
	}
	return validRemoteMCPE2EToolResult(envelope.Result)
}

func jsonRawMessageEquals(left, right json.RawMessage) bool {
	var leftValue, rightValue any
	leftDecoder := json.NewDecoder(bytes.NewReader(left))
	leftDecoder.UseNumber()
	rightDecoder := json.NewDecoder(bytes.NewReader(right))
	rightDecoder.UseNumber()
	return leftDecoder.Decode(&leftValue) == nil && leftDecoder.Decode(&struct{}{}) == io.EOF && rightDecoder.Decode(&rightValue) == nil && rightDecoder.Decode(&struct{}{}) == io.EOF && reflect.DeepEqual(leftValue, rightValue)
}

func remoteMCPE2EChallengeParameter(challenge, wanted string) (string, bool) {
	scheme, remaining, found := strings.Cut(strings.TrimSpace(challenge), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	parameters := make(map[string]string)
	for {
		remaining = strings.TrimLeft(remaining, " ")
		if remaining == "" {
			break
		}
		nameEnd := strings.IndexByte(remaining, '=')
		if nameEnd <= 0 {
			return "", false
		}
		name := remaining[:nameEnd]
		remaining = remaining[nameEnd+1:]
		if !validRemoteMCPE2EChallengeName(name) || !strings.HasPrefix(remaining, `"`) {
			return "", false
		}
		remaining = remaining[1:]
		var value strings.Builder
		closed := false
		for len(remaining) > 0 {
			character := remaining[0]
			remaining = remaining[1:]
			if character == '"' {
				closed = true
				break
			}
			if character == '\\' {
				if len(remaining) == 0 || remaining[0] != '"' && remaining[0] != '\\' {
					return "", false
				}
				character = remaining[0]
				remaining = remaining[1:]
			}
			value.WriteByte(character)
		}
		if !closed {
			return "", false
		}
		if _, duplicate := parameters[name]; duplicate {
			return "", false
		}
		parameters[name] = value.String()
		remaining = strings.TrimLeft(remaining, " ")
		if remaining == "" {
			break
		}
		if !strings.HasPrefix(remaining, ",") {
			return "", false
		}
		remaining = remaining[1:]
	}
	value, found := parameters[wanted]
	return value, found
}

func validRemoteMCPE2EChallengeName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func remoteMCPE2ERequireJSONRPCFailure(t *testing.T, response remoteMCPE2EResponse) {
	t.Helper()
	if !validRemoteMCPE2EJSONRPCFailure(response) {
		t.Fatal("MCP request did not fail closed")
	}
}

func validRemoteMCPE2EJSONRPCFailure(response remoteMCPE2EResponse) bool {
	if response.Status >= 400 && response.Status < 500 {
		return true
	}
	if response.Status < 200 || response.Status > 299 || !validJSONRPCValue(response.Body, maxJSONRPCDepth) {
		return false
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	return json.Unmarshal(response.Body, &envelope) == nil && envelope.JSONRPC == "2.0" && len(envelope.Result) == 0 && len(envelope.Error) != 0
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
