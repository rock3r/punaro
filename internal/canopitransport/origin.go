// Package canopitransport validates transport endpoints used by Canopi clients.
package canopitransport

import (
	"errors"
	"net"
	"net/http"
	"net/url"
)

// ValidateOrigin permits HTTPS origins and plaintext only to a literal
// loopback address. Bearer-authenticated LAN traffic must never use HTTP.
func ValidateOrigin(raw string) error {
	origin, err := url.Parse(raw)
	if err != nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return errors.New("canopi endpoint must be an origin without credentials, path, query, or fragment")
	}
	if origin.Scheme == "https" {
		return nil
	}
	address := net.ParseIP(origin.Hostname())
	if origin.Scheme == "http" && address != nil && address.IsLoopback() {
		return nil
	}
	return errors.New("canopi endpoint must use HTTPS except for a literal loopback address")
}

// DoWithoutRedirects sends one request without allowing credentials to cross
// into a redirect target that did not pass origin validation.
func DoWithoutRedirects(client *http.Client, request *http.Request) (*http.Response, error) {
	if client == nil {
		return nil, errors.New("http client is required")
	}
	if request == nil || request.URL == nil {
		return nil, errors.New("http request URL is required")
	}
	origin := (&url.URL{Scheme: request.URL.Scheme, Host: request.URL.Host}).String()
	if err := ValidateOrigin(origin); err != nil {
		return nil, err
	}
	redirectSafe := *client
	redirectSafe.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return redirectSafe.Do(request) // #nosec G704 -- the request origin is validated immediately above and redirects are disabled.
}
