// Package mcphttp exposes the independently optional remote MCP gateway
// boundary. It advertises the protected resource and challenges requests at
// that resource without accepting credentials or mounting an MCP transport.
// A later slice supplies the audited OAuth resource server and strict JSON-RPC
// transport implementation.
package mcphttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
)

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

const defaultScopeChallenge = "memory.search memory.read memory.propose"

// New creates the OAuth protected-resource metadata endpoint and a discovery
// challenge for one canonical HTTPS MCP resource. It accepts no credentials and
// does not mount an MCP transport.
func New(resource string, authorizationServers []string) (http.Handler, error) {
	resourcePath := resourcePath(resource)
	if !validCanonicalHTTPSURL(resource, true) || resourcePath == "" || len(authorizationServers) == 0 {
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
	metadataPath := "/.well-known/oauth-protected-resource" + resourcePath
	mux.HandleFunc("GET "+metadataPath, func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Cache-Control", "no-store")
		_, _ = response.Write(metadata)
	})
	metadataURL, err := protectedResourceMetadataURL(resource, metadataPath)
	if err != nil {
		return nil, errors.New("remote MCP metadata configuration is invalid")
	}
	mux.HandleFunc(resourcePath, func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("WWW-Authenticate", `Bearer realm="punaro-mcp", resource_metadata="`+metadataURL+`", scope="`+defaultScopeChallenge+`"`)
		response.WriteHeader(http.StatusUnauthorized)
	})
	return mux, nil
}

func protectedResourceMetadataURL(resource, metadataPath string) (string, error) {
	parsed, err := url.Parse(resource)
	if err != nil {
		return "", err
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: metadataPath}).String(), nil
}

func validCanonicalHTTPSURL(raw string, permitPath bool) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(parsed.Host, "@") || (parsed.EscapedPath() != "" && path.Clean(parsed.EscapedPath()) != parsed.EscapedPath()) {
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
