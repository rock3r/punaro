package v2

import (
	"bytes"
	"testing"
)

func TestEncodeDirectoryEntryMatchesTransparencyLeafPayload(t *testing.T) {
	entry := DirectoryEntry{Issuer: &DirectoryPermitIssuer{KeyID: bytes32(1), PublicKey: bytes32(2)}}
	encoded, err := EncodeDirectoryEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	want, err := entry.canonicalBytes()
	if err != nil || !bytes.Equal(encoded, want) {
		t.Fatalf("encoded=%x want=%x err=%v", encoded, want, err)
	}
}

func TestDecodeDirectoryEntryRequiresExactCanonicalLeaf(t *testing.T) {
	entry := DirectoryEntry{Issuer: &DirectoryPermitIssuer{KeyID: bytes32(1), PublicKey: bytes32(2)}}
	raw, err := EncodeDirectoryEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDirectoryEntry(raw)
	if err != nil || decoded.Issuer == nil || *decoded.Issuer != *entry.Issuer {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	if _, err := DecodeDirectoryEntry(append(raw, 0)); err == nil {
		t.Fatal("trailing entry data was accepted")
	}
}
