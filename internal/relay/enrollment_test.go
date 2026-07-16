package relay

import (
	"encoding/base64"
	"testing"
)

func TestParseMachineEnrollmentsAcceptsPublicKeysOnly(t *testing.T) {
	publicKey := make([]byte, 32)
	publicKey[0] = 1
	machines, err := ParseMachineEnrollments(`[{"id":"mac-review","public_key":"` + base64.RawURLEncoding.EncodeToString(publicKey) + `","endpoint_prefixes":["agent/mac-review/"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(machines) != 1 || machines[0].ID != "mac-review" || len(machines[0].PublicKey) != 32 {
		t.Fatalf("machines = %#v", machines)
	}
}

func TestParseMachineEnrollmentsAcceptsExactEndpoints(t *testing.T) {
	publicKey := make([]byte, 32)
	publicKey[0] = 1
	machines, err := ParseMachineEnrollments(`[{"id":"mac-review","public_key":"` + base64.RawURLEncoding.EncodeToString(publicKey) + `","endpoint_prefixes":["agent/mac-review/"],"endpoints":["claude/jbr-skia-reviewer"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(machines) != 1 || len(machines[0].Endpoints) != 1 || machines[0].Endpoints[0] != "claude/jbr-skia-reviewer" {
		t.Fatalf("machines = %#v", machines)
	}
}

func TestParseMachineEnrollmentsRejectsPrivateKeyFieldsAndMalformedKeys(t *testing.T) {
	if _, err := ParseMachineEnrollments(`[{"id":"machine-a","public_key":"not-base64","endpoint_prefixes":["agent/"]}]`); err == nil {
		t.Fatal("malformed public key accepted")
	}
	if _, err := ParseMachineEnrollments(`[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","private_key":"forbidden","endpoint_prefixes":["agent/"]}]`); err == nil {
		t.Fatal("private key field accepted")
	}
}

func TestParseMachineEnrollmentsDecodesAttachmentDeviceBinding(t *testing.T) {
	machines, err := ParseMachineEnrollments(`[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"],"attachment_device_id":"AQEBAQEBAQEBAQEBAQEBAQ"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if machines[0].AttachmentDeviceID[0] != 1 {
		t.Fatalf("attachment device binding = %x", machines[0].AttachmentDeviceID)
	}
}

func TestParseMachineEnrollmentsRejectsNonCanonicalAttachmentDeviceBinding(t *testing.T) {
	if _, err := ParseMachineEnrollments(`[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"],"attachment_device_id":"AQEBAQEBAQEBAQEBAQEBAQ=="}]`); err == nil {
		t.Fatal("non-canonical attachment device binding was accepted")
	}
}

func TestAuthenticatorRejectsDuplicatedAttachmentDeviceBinding(t *testing.T) {
	publicKey := make([]byte, 32)
	publicKey[0] = 1
	store, err := Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	device := [16]byte{1}
	if _, err := NewAuthenticator(store, []Machine{{ID: "machine-a", PublicKey: publicKey, EndpointPrefixes: []string{"agent/a/"}, AttachmentDeviceID: device}, {ID: "machine-b", PublicKey: publicKey, EndpointPrefixes: []string{"agent/b/"}, AttachmentDeviceID: device}}); err == nil {
		t.Fatal("duplicate attachment device binding was accepted")
	}
}
