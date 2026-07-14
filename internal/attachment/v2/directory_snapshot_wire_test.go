package v2

import "testing"

func TestDirectorySnapshotWireRoundTripsCanonicalCompleteView(t *testing.T) {
	head, err := EncodeDirectoryHead(DirectoryHead{Audience: bytes32(1), RootKeyID: bytes32(2), TreeSize: 1, TreeRoot: bytes32(3), Sequence: 1, IssuedAt: 1, ExpiresAt: 2})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := DirectorySnapshot{RawHead: head, Entries: []DirectoryEntry{{Issuer: &DirectoryPermitIssuer{KeyID: bytes32(4), PublicKey: bytes32(5)}}}}
	raw, err := EncodeDirectorySnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDirectorySnapshot(raw)
	if err != nil || len(decoded.Entries) != 1 || decoded.Entries[0].Issuer == nil {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
}
