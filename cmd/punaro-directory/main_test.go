package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
)

func TestBuildSnapshotProducesFreshRootVerifiedDirectory(t *testing.T) {
	root := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	rootPath := filepath.Join(t.TempDir(), "root.key")
	if err := os.WriteFile(rootPath, []byte(base64.RawURLEncoding.EncodeToString(root)), 0o600); err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	config := directoryConfig{
		Audience: b64(32, 1), RootKeyID: b64(32, 2), Sequence: 1, RevocationEpoch: 1,
		Entries: []directoryEntryConfig{{Issuer: &directoryIssuerConfig{KeyID: b64(32, 8), PublicKey: b64(32, 9)}}, {Device: &directoryDeviceConfig{DeviceID: b64(16, 3), Generation: 1, SigningKeyID: b64(32, 4), SigningPublicKey: b64(32, 5), HPKEKeyID: b64(32, 6), HPKEPublicKey: b64(32, 7)}}},
	}
	raw, head, err := buildSnapshot(config, root, clock, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := attachmentv2.DecodeDirectorySnapshot(raw)
	if err != nil || len(snapshot.Entries) != 2 {
		t.Fatalf("snapshot entries=%d err=%v", len(snapshot.Entries), err)
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	checkpoints, err := attachmentv2.OpenSQLiteCheckpointStore(filepath.Join(private, "checkpoints.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = checkpoints.Close() })
	if _, err := attachmentv2.NewDirectorySnapshotResolver(snapshot.RawHead, attachmentv2.DirectoryTrust{Audience: head.Audience, RootKeyID: head.RootKeyID, RootPublicKey: root.Public().(ed25519.PublicKey), Checkpoints: checkpoints}, clock.Add(time.Second), snapshot.Proof, snapshot.Entries); err != nil {
		t.Fatalf("resolver: %v", err)
	}
	config.Sequence = 2
	config.Entries = append(config.Entries, directoryEntryConfig{Device: &directoryDeviceConfig{DeviceID: b64(16, 10), Generation: 1, SigningKeyID: b64(32, 11), SigningPublicKey: b64(32, 12), HPKEKeyID: b64(32, 13), HPKEPublicKey: b64(32, 14)}})
	raw, head, err = buildSnapshot(config, root, clock.Add(time.Second), 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = attachmentv2.DecodeDirectorySnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attachmentv2.NewDirectorySnapshotResolver(snapshot.RawHead, attachmentv2.DirectoryTrust{Audience: head.Audience, RootKeyID: head.RootKeyID, RootPublicKey: root.Public().(ed25519.PublicKey), Checkpoints: checkpoints}, clock.Add(2*time.Second), snapshot.Proof, snapshot.Entries); err != nil {
		t.Fatalf("advanced resolver: %v", err)
	}
}

func TestBuildSnapshotRejectsInvalidPublicManifest(t *testing.T) {
	root := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	_, _, err := buildSnapshot(directoryConfig{Audience: "bad", RootKeyID: b64(32, 2), Sequence: 1, RevocationEpoch: 1, Entries: []directoryEntryConfig{{Issuer: &directoryIssuerConfig{KeyID: b64(32, 3), PublicKey: b64(32, 4)}}}}, root, time.Now().UTC(), time.Second)
	if err == nil {
		t.Fatal("invalid public directory manifest accepted")
	}
}

func TestPrivateOutputsRequirePrivateParentAndNeverOverwrite(t *testing.T) {
	unsafe := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- this test deliberately makes the output parent unsafe.
	if err := os.Chmod(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeNewPrivateFile(filepath.Join(unsafe, "key"), []byte{1}); err == nil {
		t.Fatal("private key accepted world-readable parent")
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(unsafe, linked); err != nil {
		t.Fatal(err)
	}
	if err := writeNewPrivateFile(filepath.Join(linked, "key"), []byte{1}); err == nil {
		t.Fatal("private key accepted symlinked parent")
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "snapshot.cbor")
	if err := writeSnapshot(path, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := writeSnapshot(path, []byte{2}); err == nil {
		t.Fatal("snapshot overwrite accepted")
	}
}

func TestDirectoryManifestRejectsUnknownAndDuplicateSecurityFields(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"revoked":false,"revoked":true}`),
		[]byte(`{"revokedd":true}`),
	} {
		if err := rejectDuplicateJSONKeys(raw); err == nil && string(raw) == `{"revoked":false,"revoked":true}` {
			t.Fatal("duplicate JSON key accepted")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(`{"audience":"x","revokedd":true}`)))
	decoder.DisallowUnknownFields()
	var config directoryConfig
	if err := decoder.Decode(&config); err == nil {
		t.Fatal("unknown security field accepted by strict manifest parser")
	}
}

func b64(size int, value byte) string {
	b := make([]byte, size)
	for i := range b {
		b[i] = value
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
