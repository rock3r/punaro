package clientidentity

import (
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/clienttransport"
)

func TestParseAcceptsVersionOneFreshAndMigratingStates(t *testing.T) {
	fresh, err := Parse([]byte(`{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111"}`))
	if err != nil {
		t.Fatalf("parse fresh state: %v", err)
	}
	if fresh.LegacyMachineID != "" || fresh.Origin != "https://punaro.example" {
		t.Fatalf("fresh state=%+v", fresh)
	}
	migrating, err := Parse([]byte(`{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"laptop-1"}`))
	if err != nil {
		t.Fatalf("parse migrating state: %v", err)
	}
	if migrating.LegacyMachineID != "laptop-1" {
		t.Fatalf("migrating state=%+v", migrating)
	}
	legacyRelayID, err := Parse([]byte(`{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"machine:west"}`))
	if err != nil || legacyRelayID.LegacyMachineID != "machine:west" {
		t.Fatalf("relay-compatible legacy state=%+v err=%v", legacyRelayID, err)
	}
}

func TestParseAcceptsVersionOneLoopbackHTTPWithoutLANPolicy(t *testing.T) {
	state, err := Parse([]byte(`{"version":1,"origin":"http://127.0.0.1:18080","client_binding":"11111111-1111-4111-8111-111111111111"}`))
	if err != nil {
		t.Fatalf("parse loopback state: %v", err)
	}
	if state.Origin != "http://127.0.0.1:18080" || state.TransportPolicy() != (clienttransport.Policy{}) {
		t.Fatalf("state=%#v policy=%#v", state, state.TransportPolicy())
	}
	if canonical, ok := CanonicalOriginWithPolicy("http://127.0.0.1:18080/", clienttransport.Policy{}); !ok || canonical != state.Origin {
		t.Fatalf("canonical loopback origin=%q ok=%t", canonical, ok)
	}
	if _, ok := CanonicalOriginWithPolicy("http://192.168.1.4:18080", clienttransport.Policy{}); ok {
		t.Fatal("private LAN HTTP was accepted without explicit policy")
	}
}

func TestParseAcceptsOnlyExplicitVersionTwoLANState(t *testing.T) {
	state, err := Parse([]byte(`{"version":2,"origin":"http://192.168.1.4:8080","client_binding":"11111111-1111-4111-8111-111111111111","allow_lan_http":true,"trusted_lan_cidr":"192.168.1.0/24"}`))
	if err != nil {
		t.Fatal(err)
	}
	policy := state.TransportPolicy()
	if state.Version != 2 || !policy.AllowLANHTTP || policy.TrustedLANCIDR != "192.168.1.0/24" {
		t.Fatalf("state=%#v policy=%#v", state, policy)
	}
	for name, raw := range map[string]string{
		"implicit plaintext":     `{"version":1,"origin":"http://192.168.1.4:8080","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"v1 explicit false":      `{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","allow_lan_http":false}`,
		"v1 explicit empty cidr": `{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","trusted_lan_cidr":""}`,
		"missing cidr":           `{"version":2,"origin":"http://192.168.1.4:8080","client_binding":"11111111-1111-4111-8111-111111111111","allow_lan_http":true}`,
		"dns plaintext":          `{"version":2,"origin":"http://punaro.lan:8080","client_binding":"11111111-1111-4111-8111-111111111111","allow_lan_http":true,"trusted_lan_cidr":"192.168.1.0/24"}`,
		"https downgrade fields": `{"version":2,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","allow_lan_http":true,"trusted_lan_cidr":"192.168.1.0/24"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("unsafe LAN state was accepted")
			}
		})
	}
}

func TestParseRejectsUnsafeOrAmbiguousState(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate":        `{"version":1,"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"unknown":          `{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","credential":"must-not-be-stored"}`,
		"unknown version":  `{"version":2,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"non HTTPS":        `{"version":1,"origin":"http://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"no hostname":      `{"version":1,"origin":"https://:443","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"bad IPv6 literal": `{"version":1,"origin":"https://[foo:bar]","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"empty IPv6 zone":  `{"version":1,"origin":"https://[fe80::1%25]","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"unsafe IPv6 zone": `{"version":1,"origin":"https://[fe80::1%25a]b]","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"empty DNS label":  `{"version":1,"origin":"https://foo..example","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"long DNS label":   `{"version":1,"origin":"https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"query":            `{"version":1,"origin":"https://punaro.example?token=no","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"relative":         `{"version":1,"origin":"/punaro","client_binding":"11111111-1111-4111-8111-111111111111"}`,
		"bad binding":      `{"version":1,"origin":"https://punaro.example","client_binding":"not-a-binding"}`,
		"bad machine":      `{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"other\nmachine"}`,
		"empty machine":    `{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":""}`,
		"null machine":     `{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":null}`,
		"trailing":         `{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111"} true`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("unsafe state was accepted")
			}
		})
	}
}

func TestStateMatchRejectsCrossDeviceOriginAndLegacyIdentity(t *testing.T) {
	state, err := Parse([]byte(`{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"laptop-1"}`))
	if err != nil {
		t.Fatalf("parse state: %v", err)
	}
	if err := state.Match("https://punaro.example", "11111111-1111-4111-8111-111111111111", "laptop-1"); err != nil {
		t.Fatalf("match state: %v", err)
	}
	if err := state.Match("https://punaro.example/", "11111111-1111-4111-8111-111111111111", "laptop-1"); err != nil {
		t.Fatalf("canonical trailing-slash match: %v", err)
	}
	if err := state.Match("https://Relay.Example/", "11111111-1111-4111-8111-111111111111", "laptop-1"); err == nil {
		t.Fatal("mixed-case origin unexpectedly matched a different relay")
	}
	mixedCaseState, err := Parse([]byte(`{"version":1,"origin":"https://relay.example","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"laptop-1"}`))
	if err != nil {
		t.Fatalf("parse lowercase canonical state: %v", err)
	}
	if err := mixedCaseState.Match("https://Relay.Example/", "11111111-1111-4111-8111-111111111111", "laptop-1"); err != nil {
		t.Fatalf("canonical mixed-case host match: %v", err)
	}
	if err := mixedCaseState.Match("https://Relay.Example:00443/", "11111111-1111-4111-8111-111111111111", "laptop-1"); err != nil {
		t.Fatalf("canonical default-port match: %v", err)
	}
	if err := mixedCaseState.Match("https://Relay.Example?", "11111111-1111-4111-8111-111111111111", "laptop-1"); err != nil {
		t.Fatalf("canonical empty-query match: %v", err)
	}
	zoneState, err := Parse([]byte(`{"version":1,"origin":"https://[fe80::1%25EtherNet]","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"laptop-1"}`))
	if err != nil {
		t.Fatalf("parse IPv6 zone state: %v", err)
	}
	if err := zoneState.Match("https://[FE80::1%25EtherNet]", "11111111-1111-4111-8111-111111111111", "laptop-1"); err != nil {
		t.Fatalf("canonical IPv6 zone match: %v", err)
	}
	multiPercentZoneState, err := Parse([]byte(`{"version":1,"origin":"https://[fe80::1%25Ether%25Net]","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"laptop-1"}`))
	if err != nil {
		t.Fatalf("parse IPv6 multi-percent zone state: %v", err)
	}
	if err := multiPercentZoneState.Match("https://[FE80::1%25Ether%25Net]", "11111111-1111-4111-8111-111111111111", "laptop-1"); err != nil {
		t.Fatalf("canonical IPv6 multi-percent zone match: %v", err)
	}
	spaceZoneState, err := Parse([]byte(`{"version":1,"origin":"https://[fe80::1%25Ethernet%202]","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"laptop-1"}`))
	if err != nil {
		t.Fatalf("parse IPv6 space-zone state: %v", err)
	}
	if err := spaceZoneState.Match("https://[FE80::1%25Ethernet%202]", "11111111-1111-4111-8111-111111111111", "laptop-1"); err != nil {
		t.Fatalf("canonical IPv6 space-zone match: %v", err)
	}
	ipv6State, err := Parse([]byte(`{"version":1,"origin":"https://[2001:db8::1]","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"laptop-1"}`))
	if err != nil {
		t.Fatalf("parse IPv6 state: %v", err)
	}
	if err := ipv6State.Match("https://[2001:0DB8:0000:0000:0000:0000:0000:0001]", "11111111-1111-4111-8111-111111111111", "laptop-1"); err != nil {
		t.Fatalf("canonical IPv6 spelling match: %v", err)
	}
	idnaState, err := Parse([]byte(`{"version":1,"origin":"https://xn--i-9bb.example","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"laptop-1"}`))
	if err != nil {
		t.Fatalf("parse IDNA state: %v", err)
	}
	if err := idnaState.Match("https://İ.example", "11111111-1111-4111-8111-111111111111", "laptop-1"); err != nil {
		t.Fatalf("canonical IDNA host match: %v", err)
	}
	fresh, err := Parse([]byte(`{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111"}`))
	if err != nil {
		t.Fatalf("parse fresh identity: %v", err)
	}
	if err := fresh.Match("https://punaro.example", "11111111-1111-4111-8111-111111111111", ""); err != nil {
		t.Fatalf("fresh identity match: %v", err)
	}
	if err := fresh.Match("https://punaro.example", "11111111-1111-4111-8111-111111111111", "adapter-machine"); err == nil {
		t.Fatal("fresh identity unexpectedly changed to legacy mode")
	}
	if err := fresh.MatchLegacyAdapter("https://punaro.example", "11111111-1111-4111-8111-111111111111", "adapter-machine"); err == nil {
		t.Fatal("fresh identity unexpectedly matched a legacy adapter")
	}
	for name, match := range map[string][3]string{
		"origin":         {"https://other.example", "11111111-1111-4111-8111-111111111111", "laptop-1"},
		"client binding": {"https://punaro.example", "22222222-2222-4222-8222-222222222222", "laptop-1"},
		"legacy machine": {"https://punaro.example", "11111111-1111-4111-8111-111111111111", "desktop-1"},
	} {
		t.Run(name, func(t *testing.T) {
			err := state.Match(match[0], match[1], match[2])
			if err == nil || strings.Contains(err.Error(), "punaro.example") || strings.Contains(err.Error(), "laptop-1") {
				t.Fatalf("match error=%v", err)
			}
		})
	}
}

func TestEncodeIsDeterministicAndNeverAcceptsSecretFields(t *testing.T) {
	state := State{Version: Version, Origin: "https://punaro.example", ClientBinding: "11111111-1111-4111-8111-111111111111", LegacyMachineID: "laptop-1"}
	raw, err := state.Encode()
	if err != nil {
		t.Fatalf("encode state: %v", err)
	}
	const expected = `{"version":1,"origin":"https://punaro.example","client_binding":"11111111-1111-4111-8111-111111111111","legacy_machine_id":"laptop-1"}`
	if string(raw) != expected {
		t.Fatalf("encoded state=%s", raw)
	}
	if strings.Contains(string(raw), "credential") || strings.Contains(string(raw), "private_key") {
		t.Fatalf("encoded state contains a secret field: %s", raw)
	}
}
