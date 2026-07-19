// Package ingress validates the transport boundary for device credentials.
package ingress

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Mode is one explicit operator-selected ingress profile.
type Mode string

const (
	// LAN permits an explicit private or link-local plaintext exception.
	LAN Mode = "lan"
	// Proxy requires a loopback listener behind a canonical HTTPS origin.
	Proxy Mode = "proxy"
	// Internet requires a loopback listener behind a canonical HTTPS origin.
	Internet Mode = "internet"
)

// Policy is the complete transport policy needed before credentials can be
// accepted. Forwarded headers are intentionally absent: a direct request
// cannot assert its own transport or source boundary.
type Policy struct {
	Mode           Mode
	ListenAddr     string
	PublicURL      string
	TrustedLAN     string
	AllowPlaintext bool

	trustedNetwork *net.IPNet
}

// Validate rejects ambiguous, wildcard, and publicly routable boundaries.
func (p *Policy) Validate() error {
	host, _, err := net.SplitHostPort(p.ListenAddr)
	if err != nil {
		return errors.New("ingress listen address must be a concrete IP and port")
	}
	bind := parseIP(host)
	if bind == nil || bind.IsUnspecified() || bind.IsMulticast() {
		return errors.New("ingress listen address must be a concrete IP and port")
	}
	switch p.Mode {
	case Internet, Proxy:
		if !bind.IsLoopback() {
			return errors.New("proxy and Internet origins must bind to loopback")
		}
		if err := validateHTTPSURL(p.PublicURL); err != nil {
			return err
		}
		if p.TrustedLAN != "" || p.AllowPlaintext {
			return errors.New("trusted-LAN plaintext is valid only in LAN mode")
		}
	case LAN:
		if !p.AllowPlaintext {
			return errors.New("LAN plaintext must be explicitly enabled")
		}
		if !privateOrLinkLocal(bind) {
			return errors.New("LAN bind must be private or link-local")
		}
		_, network, err := net.ParseCIDR(p.TrustedLAN)
		if err != nil || !privateNetwork(network) || !network.Contains(bind) {
			return errors.New("trusted LAN must be a private or link-local network containing the bind")
		}
		if p.PublicURL != "" {
			return errors.New("LAN mode does not accept a public URL")
		}
		p.trustedNetwork = network
	default:
		return errors.New("ingress mode must be lan, proxy, or internet")
	}
	return nil
}

// AllowsCredential admits TLS, same-host plaintext, or the exact explicit
// trusted-LAN exception. X-Forwarded-* is never consulted.
func (p *Policy) AllowsCredential(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	peer := parseIP(strings.Trim(host, "[]"))
	if peer == nil {
		return false
	}
	if peer.IsLoopback() {
		return true
	}
	if p.Mode != LAN || !p.AllowPlaintext || !privateOrLinkLocal(peer) {
		return false
	}
	if p.trustedNetwork == nil {
		if err := p.Validate(); err != nil {
			return false
		}
	}
	return p.trustedNetwork.Contains(peer)
}

func validateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("proxy and Internet modes require a canonical HTTPS public URL")
	}
	if net.ParseIP(u.Hostname()) != nil && (net.ParseIP(u.Hostname()).IsLoopback() || net.ParseIP(u.Hostname()).IsUnspecified()) {
		return errors.New("public URL must not name a loopback or wildcard address")
	}
	return nil
}

func privateOrLinkLocal(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func parseIP(host string) net.IP {
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	return net.ParseIP(host)
}

func privateNetwork(network *net.IPNet) bool {
	if network == nil {
		return false
	}
	ones, bits := network.Mask.Size()
	if ones < 0 {
		return false
	}
	allowed := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"}
	for _, raw := range allowed {
		_, parent, _ := net.ParseCIDR(raw)
		parentOnes, parentBits := parent.Mask.Size()
		if bits == parentBits && ones >= parentOnes && parent.Contains(network.IP) {
			return true
		}
	}
	return false
}
