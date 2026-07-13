package attachment

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestParseRuntimeConfigurationBuildsEnrollmentAndPolicy(t *testing.T) {
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	keysJSON := `{"sender":"` + base64.RawStdEncoding.EncodeToString(key) + `"}`
	keys, err := ParseDeviceKeys(keysJSON)
	if err != nil || len(keys["sender"]) != ed25519.PublicKeySize {
		t.Fatalf("ParseDeviceKeys() = %#v, %v", keys, err)
	}
	policy, err := ParsePolicy(`[{
        "sender":"sender", "conversation":"conversation", "recipient":"recipient",
        "actions":["create", "upload", "download"]
    }]`)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Allowed("sender", "conversation", "recipient", ActionDownload) {
		t.Fatal("parsed policy did not allow grant")
	}
}

func TestParsePolicyRejectsUnknownFields(t *testing.T) {
	if _, err := ParsePolicy(`[{"sender":"sender","conversation":"conversation","recipient":"recipient","actions":["create"],"admin":true}]`); err == nil {
		t.Fatal("ParsePolicy accepted unknown control field")
	}
}
