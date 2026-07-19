package ingress

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestPolicyValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
	}{
		{name: "internet needs https", policy: Policy{Mode: Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "http://punaro.example"}},
		{name: "internet origin cannot be public", policy: Policy{Mode: Internet, ListenAddr: "203.0.113.4:8080", PublicURL: "https://punaro.example"}},
		{name: "proxy needs https", policy: Policy{Mode: Proxy, ListenAddr: "127.0.0.1:8080", PublicURL: ""}},
		{name: "lan wildcard", policy: Policy{Mode: LAN, ListenAddr: "0.0.0.0:8080", TrustedLAN: "192.168.1.0/24", AllowPlaintext: true}},
		{name: "lan public bind", policy: Policy{Mode: LAN, ListenAddr: "8.8.8.8:8080", TrustedLAN: "8.8.8.0/24", AllowPlaintext: true}},
		{name: "lan public network", policy: Policy{Mode: LAN, ListenAddr: "192.168.1.4:8080", TrustedLAN: "8.8.8.0/24", AllowPlaintext: true}},
		{name: "lan plaintext not explicit", policy: Policy{Mode: LAN, ListenAddr: "192.168.1.4:8080", TrustedLAN: "192.168.1.0/24"}},
		{name: "zero port", policy: Policy{Mode: Internet, ListenAddr: "127.0.0.1:0", PublicURL: "https://punaro.example"}},
		{name: "service port", policy: Policy{Mode: Internet, ListenAddr: "127.0.0.1:http", PublicURL: "https://punaro.example"}},
		{name: "out of range port", policy: Policy{Mode: Internet, ListenAddr: "127.0.0.1:65536", PublicURL: "https://punaro.example"}},
		{name: "noncanonical port", policy: Policy{Mode: Internet, ListenAddr: "127.0.0.1:08080", PublicURL: "https://punaro.example"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.policy.Validate(); err == nil {
				t.Fatal("unsafe ingress policy was accepted")
			}
		})
	}
}

func TestCredentialTransportAdmission(t *testing.T) {
	lan := Policy{Mode: LAN, ListenAddr: "192.168.1.4:8080", TrustedLAN: "192.168.1.0/24", AllowPlaintext: true}
	if err := lan.Validate(); err != nil {
		t.Fatal(err)
	}
	request := func(remote string, secure bool) *http.Request {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://punaro.invalid/v1/device/session", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.RemoteAddr = remote
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		return r
	}
	if !lan.AllowsCredential(request("192.168.1.20:41234", false)) {
		t.Fatal("explicit trusted-LAN peer was rejected")
	}
	spoofed := request("203.0.113.20:41234", false)
	spoofed.Header.Set("X-Forwarded-For", "192.168.1.20")
	spoofed.Header.Set("X-Forwarded-Proto", "https")
	if lan.AllowsCredential(spoofed) {
		t.Fatal("forwarded headers bypassed direct-origin transport policy")
	}
	if !lan.AllowsCredential(request("203.0.113.20:41234", true)) {
		t.Fatal("TLS peer was rejected")
	}

	internet := Policy{Mode: Internet, ListenAddr: "127.0.0.1:8080", PublicURL: "https://punaro.example"}
	if err := internet.Validate(); err != nil {
		t.Fatal(err)
	}
	if internet.AllowsCredential(request("203.0.113.20:41234", false)) {
		t.Fatal("internet profile accepted plaintext credential transport")
	}
	if !internet.AllowsCredential(request("127.0.0.1:41234", false)) {
		t.Fatal("same-host credential transport was rejected")
	}
}

func TestLinkLocalIPv6ZoneIsValidatedWithoutTrustingItAsAnAddress(t *testing.T) {
	policy := Policy{Mode: LAN, ListenAddr: "[fe80::1234%en0]:8080", TrustedLAN: "fe80::/64", AllowPlaintext: true}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://punaro.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = "[fe80::20%en0]:41234"
	if !policy.AllowsCredential(r) {
		t.Fatal("validated link-local IPv6 peer was rejected")
	}
}
