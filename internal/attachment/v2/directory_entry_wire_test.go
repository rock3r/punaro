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
