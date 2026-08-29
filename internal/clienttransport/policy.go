// Package clienttransport validates the transport boundary selected by native
// Punaro clients. Plaintext credentials are permitted only for an explicit,
// literal private or link-local LAN address contained by an operator-pinned
// CIDR. HTTPS and loopback development listeners remain the defaults.
package clienttransport

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Policy is the complete client-side acknowledgement for trusted-LAN HTTP.
// Both fields must be present together and are rejected for HTTPS and loopback
// origins so stale configuration cannot silently change transport meaning.
type Policy struct {
	AllowLANHTTP   bool
	TrustedLANCIDR string
}

// ValidateOrigin rejects credentials, paths, mutable URL components, ambient
// DNS for plaintext, and every implicit or publicly routable HTTP origin.
func ValidateOrigin(raw string, policy Policy) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("client origin is invalid")
	}
	if err := validatePort(parsed); err != nil {
		return nil, errors.New("client origin is invalid")
	}
	parsed.Path = ""
	parsed.ForceQuery = false
	switch parsed.Scheme {
	case "https":
		if policy.AllowLANHTTP || policy.TrustedLANCIDR != "" {
			return nil, errors.New("trusted-LAN policy is valid only for plaintext LAN HTTP")
		}
		return parsed, nil
	case "http":
	default:
		return nil, errors.New("client origin is invalid")
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil {
		return nil, errors.New("plaintext client origin must use a literal IP address")
	}
	if address.Is6() {
		// Preserve the interface zone in parsed for link-local dialing, but CIDR
		// membership is defined only over the underlying address bits.
		address = address.WithZone("")
	}
	address = address.Unmap()
	if address.IsLoopback() {
		if policy.AllowLANHTTP || policy.TrustedLANCIDR != "" {
			return nil, errors.New("trusted-LAN policy is invalid for loopback")
		}
		return parsed, nil
	}
	if !policy.AllowLANHTTP || policy.TrustedLANCIDR == "" {
		return nil, errors.New("plaintext LAN HTTP requires explicit client acknowledgement")
	}
	prefix, err := netip.ParsePrefix(policy.TrustedLANCIDR)
	if err != nil || prefix != prefix.Masked() || !privatePrefix(prefix) || !prefix.Contains(address) {
		return nil, errors.New("trusted LAN is invalid or does not contain the origin")
	}
	return parsed, nil
}

// HardenClient returns an isolated client. Plaintext LAN traffic never uses an
// ambient proxy and never follows redirects, so credentials cannot leave the
// literal operator-pinned destination through process environment settings or
// a server response.
func HardenClient(provided *http.Client, raw string, policy Policy) (*http.Client, error) {
	parsed, err := ValidateOrigin(raw, policy)
	if err != nil {
		return nil, err
	}
	if provided == nil {
		provided = http.DefaultClient
	}
	client := *provided
	if parsed.Scheme == "http" && !loopback(parsed.Hostname()) {
		switch transport := client.Transport.(type) {
		case nil:
			base, ok := http.DefaultTransport.(*http.Transport)
			if !ok {
				return nil, errors.New("default HTTP transport is unavailable")
			}
			clone := base.Clone()
			clone.Proxy = nil
			client.Transport = clone
		case *http.Transport:
			clone := transport.Clone()
			clone.Proxy = nil
			client.Transport = clone
		default:
			return nil, errors.New("plaintext LAN HTTP requires a direct HTTP transport")
		}
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &client, nil
}

func validatePort(parsed *url.URL) error {
	if strings.HasSuffix(parsed.Host, ":") {
		return errors.New("invalid port")
	}
	port := parsed.Port()
	if port == "" {
		return nil
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != port {
		return errors.New("invalid port")
	}
	return nil
}

func privatePrefix(prefix netip.Prefix) bool {
	address := prefix.Addr().Unmap()
	if !address.IsPrivate() && !address.IsLinkLocalUnicast() {
		return false
	}
	allowed := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"}
	for _, raw := range allowed {
		parent := netip.MustParsePrefix(raw)
		if parent.Addr().BitLen() == address.BitLen() && prefix.Bits() >= parent.Bits() && parent.Contains(address) {
			return true
		}
	}
	return false
}

func loopback(host string) bool {
	address := net.ParseIP(strings.Split(host, "%")[0])
	return address != nil && address.IsLoopback()
}
