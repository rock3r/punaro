// Package listener provides one canonical parser for configured TCP listeners.
package listener

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
)

// Endpoint is one validated, comparable configured listener.
type Endpoint struct {
	Address netip.Addr
	Port    uint16
}

// Parse accepts only a concrete IP and a canonical decimal port in 1..65535.
func Parse(address string) (Endpoint, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return Endpoint{}, errors.New("listener must be a concrete IP and port")
	}
	ip, ipErr := netip.ParseAddr(host)
	port, err := strconv.ParseUint(portText, 10, 16)
	if ipErr != nil || err != nil || port == 0 || portText != strconv.FormatUint(port, 10) {
		return Endpoint{}, errors.New("listener must use a concrete IP and canonical nonzero numeric port")
	}
	if ip.Is6() && ip.IsLinkLocalUnicast() != (ip.Zone() != "") {
		return Endpoint{}, errors.New("listener must use a concrete IP and canonical nonzero numeric port")
	}
	return Endpoint{Address: ip.Unmap(), Port: uint16(port)}, nil
}

// IsLoopback reports whether address is a valid canonical loopback listener.
func IsLoopback(address string) bool {
	endpoint, err := Parse(address)
	return err == nil && endpoint.Address.IsLoopback()
}

// Same reports whether two valid canonical listeners identify the same IP/port.
func Same(first, second string) bool {
	firstEndpoint, firstErr := Parse(first)
	secondEndpoint, secondErr := Parse(second)
	return firstErr == nil && secondErr == nil && firstEndpoint == secondEndpoint
}
