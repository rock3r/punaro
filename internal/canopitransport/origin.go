// Package canopitransport validates transport endpoints used by Canopi clients.
package canopitransport

import (
	"errors"
	"net"
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
