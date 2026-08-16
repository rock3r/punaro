package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignAndVerifyCoverExactDocumentBytes(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(validReleaseManifestJSON())
	envelope, err := Sign(document, "punaro-release-1", private)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(document, envelope, map[string]ed25519.PublicKey{"punaro-release-1": public}); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, document...)
	tampered[len(tampered)-2] ^= 0x01
	if err := Verify(tampered, envelope, map[string]ed25519.PublicKey{"punaro-release-1": public}); err == nil {
		t.Fatal("altered bytes verified")
	}
}

func TestVerifyRejectsUnknownKeyWrongKeyAndDuplicateSignatures(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(validCatalogJSON())
	envelope, err := Sign(document, "punaro-release-1", private)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(document, envelope, map[string]ed25519.PublicKey{"punaro-release-2": public}); err == nil {
		t.Fatal("unknown key id verified")
	}
	if err := Verify(document, envelope, map[string]ed25519.PublicKey{"punaro-release-1": otherPublic}); err == nil {
		t.Fatal("wrong public key verified")
	}
	if _, err := Sign(document, "punaro-release-1", otherPrivate); err != nil {
		t.Fatal(err)
	}
	duplicate, err := AppendSignature(envelope, document, "punaro-release-1", otherPrivate)
	if err == nil {
		t.Fatalf("duplicate key id accepted: %#v", duplicate)
	}
}

func TestParseEnvelopeRejectsUnknownFieldsAndMoreThanFourSignatures(t *testing.T) {
	if _, err := ParseEnvelope([]byte(`{"schema":1,"signatures":[],"extra":true}`)); err == nil {
		t.Fatal("unknown envelope field accepted")
	}
	body := `{"schema":1,"signatures":[` +
		`{"key_id":"k1","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},` +
		`{"key_id":"k2","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},` +
		`{"key_id":"k3","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},` +
		`{"key_id":"k4","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},` +
		`{"key_id":"k5","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`
	if _, err := ParseEnvelope([]byte(body)); err == nil {
		t.Fatal("five signatures accepted")
	}
}
