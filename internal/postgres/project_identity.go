package postgres

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxProjectLocatorBytes = 2048

// ProjectIdentityKind is a closed class of verified project locators.
type ProjectIdentityKind string

// Supported project locator kinds.
const (
	ProjectIdentityLocalGit      ProjectIdentityKind = "local_git"
	ProjectIdentityGitRemote     ProjectIdentityKind = "git_remote"
	ProjectIdentityOperatorAlias ProjectIdentityKind = "operator_alias"
	ProjectIdentityWorkspace     ProjectIdentityKind = "workspace"
)

// NormalizeProjectIdentityLocator returns a credential-free stable locator.
// Git normalization is deliberately conservative: it unifies transport syntax,
// host case, default ports, and a lowercase .git suffix while retaining path
// case and rejecting URL features with ambiguous repository semantics.
func NormalizeProjectIdentityLocator(kind ProjectIdentityKind, raw string) (string, error) {
	if !utf8.ValidString(raw) || len(raw) == 0 || len(raw) > maxProjectLocatorBytes || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", errors.New("invalid project identity locator")
	}
	switch kind {
	case ProjectIdentityGitRemote:
		return normalizeGitRemote(raw)
	case ProjectIdentityLocalGit, ProjectIdentityWorkspace:
		value := strings.ToLower(strings.TrimSpace(raw))
		if !validOpaqueID(value) {
			return "", errors.New("invalid project identity locator")
		}
		return value, nil
	case ProjectIdentityOperatorAlias:
		value := strings.ToLower(strings.TrimSpace(raw))
		if !validDisplayName(value) {
			return "", errors.New("invalid project identity locator")
		}
		return value, nil
	default:
		return "", errors.New("invalid project identity locator")
	}
}

func normalizeGitRemote(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.Contains(value, "%") {
		return "", errors.New("invalid Git remote locator")
	}
	var host, port, repository, scheme string
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
			return "", errors.New("invalid Git remote locator")
		}
		scheme = strings.ToLower(parsed.Scheme)
		switch scheme {
		case "https", "http", "ssh", "git":
		default:
			return "", errors.New("invalid Git remote locator")
		}
		host = parsed.Hostname()
		port = parsed.Port()
		if strings.HasSuffix(parsed.Host, ":") && port == "" {
			return "", errors.New("invalid Git remote locator")
		}
		repository = parsed.Path
	} else {
		colon := strings.IndexByte(value, ':')
		if colon < 1 || colon == len(value)-1 || strings.Contains(value[:colon], "/") {
			return "", errors.New("invalid Git remote locator")
		}
		hostPart := value[:colon]
		if at := strings.LastIndexByte(hostPart, '@'); at >= 0 {
			hostPart = hostPart[at+1:]
		}
		host = hostPart
		repository = value[colon+1:]
		scheme = "ssh"
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if !validGitHost(host) {
		return "", errors.New("invalid Git remote locator")
	}
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", errors.New("invalid Git remote locator")
		}
		switch scheme + ":" + port {
		case "ssh:22", "https:443", "http:80", "git:9418":
		default:
			host = net.JoinHostPort(host, port)
		}
	}
	repository = strings.TrimPrefix(repository, "/")
	repository = strings.TrimSuffix(repository, "/")
	repository = strings.TrimSuffix(repository, ".git")
	parts := strings.Split(repository, "/")
	if len(parts) < 2 {
		return "", errors.New("invalid Git remote locator")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part {
			return "", errors.New("invalid Git remote locator")
		}
	}
	normalized := host + "/" + strings.Join(parts, "/")
	if len(normalized) > maxProjectLocatorBytes {
		return "", errors.New("invalid Git remote locator")
	}
	return normalized, nil
}

func validGitHost(host string) bool {
	if host == "" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return false
	}
	for _, r := range host {
		if r > unicode.MaxASCII {
			return false
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}
