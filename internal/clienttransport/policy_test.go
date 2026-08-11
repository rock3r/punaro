package clienttransport

import (
	"net/http"
	"testing"
)

func TestPolicyValidatesExplicitTrustedLANHTTP(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		policy Policy
		ok     bool
	}{
		{name: "https", origin: "https://punaro.example", ok: true},
		{name: "loopback development", origin: "http://127.0.0.1:8080", ok: true},
		{name: "explicit private ipv4", origin: "http://192.168.1.4:8080", policy: Policy{AllowLANHTTP: true, TrustedLANCIDR: "192.168.1.0/24"}, ok: true},
		{name: "explicit private ipv6", origin: "http://[fd12:3456::4]:8080", policy: Policy{AllowLANHTTP: true, TrustedLANCIDR: "fd12:3456::/64"}, ok: true},
		{name: "explicit zoned link-local ipv6", origin: "http://[fe80::4%25en0]:8080", policy: Policy{AllowLANHTTP: true, TrustedLANCIDR: "fe80::/64"}, ok: true},
		{name: "implicit private plaintext", origin: "http://192.168.1.4:8080", ok: false},
		{name: "missing cidr", origin: "http://192.168.1.4:8080", policy: Policy{AllowLANHTTP: true}, ok: false},
		{name: "cidr without acknowledgement", origin: "http://192.168.1.4:8080", policy: Policy{TrustedLANCIDR: "192.168.1.0/24"}, ok: false},
		{name: "dns plaintext", origin: "http://punaro.lan:8080", policy: Policy{AllowLANHTTP: true, TrustedLANCIDR: "192.168.1.0/24"}, ok: false},
		{name: "outside cidr", origin: "http://192.168.2.4:8080", policy: Policy{AllowLANHTTP: true, TrustedLANCIDR: "192.168.1.0/24"}, ok: false},
		{name: "public cidr", origin: "http://203.0.113.4:8080", policy: Policy{AllowLANHTTP: true, TrustedLANCIDR: "203.0.113.0/24"}, ok: false},
		{name: "credentials", origin: "http://user@192.168.1.4:8080", policy: Policy{AllowLANHTTP: true, TrustedLANCIDR: "192.168.1.0/24"}, ok: false},
		{name: "path", origin: "http://192.168.1.4:8080/v1", policy: Policy{AllowLANHTTP: true, TrustedLANCIDR: "192.168.1.0/24"}, ok: false},
		{name: "stale lan policy on https", origin: "https://punaro.example", policy: Policy{AllowLANHTTP: true, TrustedLANCIDR: "192.168.1.0/24"}, ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateOrigin(test.origin, test.policy)
			if (err == nil) != test.ok {
				t.Fatalf("ValidateOrigin() error=%v, want success=%t", err, test.ok)
			}
		})
	}
}

func TestHardenClientDisablesAmbientProxyForPlaintextLAN(t *testing.T) {
	client, err := HardenClient(nil, "http://192.168.1.4:8080", Policy{AllowLANHTTP: true, TrustedLANCIDR: "192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("transport=%T has_proxy=%t, want direct transport", client.Transport, ok && transport.Proxy != nil)
	}
}
