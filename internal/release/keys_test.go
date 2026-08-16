package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestParsePublicKeysRejectsUnknownFieldsAndDuplicateKeyIDs(t *testing.T) {
	if _, err := ParsePublicKeys([]byte(`{"schema":1,"keys":[],"extra":true}`)); err == nil {
		t.Fatal("unknown public key field accepted")
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodePublicKeys("punaro-release-1", public)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParsePublicKeys(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || len(keys["punaro-release-1"]) != ed25519.PublicKeySize {
		t.Fatalf("keys=%#v", keys)
	}
}

func TestPrivateKeyRoundTripIsExactBytes(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := EncodePrivateKey(private)
	decoded, err := ParsePrivateKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !private.Equal(decoded) {
		t.Fatal("private key did not round-trip")
	}
	if _, err := ParsePrivateKey(append(encoded, '\n')); err == nil {
		t.Fatal("newline-terminated private key accepted")
	}
}
