// Package mcphttp exposes the independently optional remote MCP gateway
// boundary. This initial resource-metadata surface deliberately mounts no MCP
// transport and accepts no credentials; a later slice supplies the audited
// OAuth resource-server and strict JSON-RPC transport implementation.
package mcphttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// New creates only the OAuth protected-resource metadata endpoint for one
// canonical HTTPS MCP resource. It intentionally does not mount /mcp.
func New(resource string, authorizationServers []string) (http.Handler, error) {
	if !validCanonicalHTTPSURL(resource, true) || len(authorizationServers) == 0 {
		return nil, errors.New("remote MCP metadata configuration is invalid")
	}
	servers := make([]string, len(authorizationServers))
	seen := make(map[string]struct{}, len(authorizationServers))
	for index, server := range authorizationServers {
		if !validCanonicalHTTPSURL(server, false) {
			return nil, errors.New("remote MCP metadata configuration is invalid")
		}
		if _, duplicate := seen[server]; duplicate {
			return nil, errors.New("remote MCP metadata configuration is invalid")
		}
		seen[server] = struct{}{}
		servers[index] = server
	}
	metadata, err := json.Marshal(protectedResourceMetadata{Resource: resource, AuthorizationServers: servers})
	if err != nil {
		return nil, errors.New("remote MCP metadata configuration is invalid")
	}
	mux := http.NewServeMux()
	metadataPath := "/.well-known/oauth-protected-resource" + resourcePath(resource)
	mux.HandleFunc("GET "+metadataPath, func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_, _ = response.Write(metadata)
	})
	return mux, nil
}

func validCanonicalHTTPSURL(raw string, permitPath bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(parsed.Host, "@") {
		return false
	}
	if !permitPath && parsed.Path != "" && parsed.Path != "/" {
		return false
	}
	return parsed.String() == raw
}

func resourcePath(resource string) string {
	parsed, _ := url.Parse(resource)
	if parsed.Path == "" || parsed.Path == "/" {
		return ""
	}
	return parsed.EscapedPath()
}
