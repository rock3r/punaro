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

func TestParseMachineEnrollmentsRejectsPrivateKeyFieldsAndMalformedKeys(t *testing.T) {
	if _, err := ParseMachineEnrollments(`[{"id":"machine-a","public_key":"not-base64","endpoint_prefixes":["agent/"]}]`); err == nil {
		t.Fatal("malformed public key accepted")
	}
	if _, err := ParseMachineEnrollments(`[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","private_key":"forbidden","endpoint_prefixes":["agent/"]}]`); err == nil {
		t.Fatal("private key field accepted")
	}
}
