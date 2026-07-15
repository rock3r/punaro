package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/config"
	"github.com/rock3r/punaro/internal/relay"
)

func TestBuildRelayHandlerRejectsInvalidEnrollment(t *testing.T) {
	_, closeRelay, err := buildRelayHandler(config.Config{DataDir: t.TempDir(), RelayEnabled: true, RelayMachinesJSON: `[{"id":"machine-a","public_key":"invalid","endpoint_prefixes":["agent/"]}]`})
	if closeRelay != nil {
		t.Fatal("invalid relay configuration returned a closer")
	}
	if err == nil {
		t.Fatal("invalid enrollment enabled relay routes")
	}
}

func TestBuildPermitHandlerRequiresEnrolledAttachmentDeviceBinding(t *testing.T) {
	privateDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(privateDir, "issuer.key")
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(issuerPrivate)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, store, err := buildRelayHandler(config.Config{DataDir: t.TempDir(), RelayEnabled: true, RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := permitHandlerConfig(t, privateDir, keyPath)
	if _, closePermit, _, err := buildPermitHandler(cfg, store); err == nil || closePermit != nil {
		t.Fatal("permit handler accepted no enrolled attachment device binding")
	}
}

func TestBuildV3AttachmentHandlersRequireEnrolledAttachmentDeviceBinding(t *testing.T) {
	privateDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(privateDir, "issuer.key")
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(issuerPrivate)), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	_, store, err := buildRelayHandler(config.Config{DataDir: dataDir, RelayEnabled: true, RelayMachinesJSON: `[{
"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := permitHandlerConfig(t, privateDir, keyPath)
	cfg.DataDir = dataDir
	cfg.AttachmentV3Enabled = true
	cfg.AttachmentV3SourceStoreFile = filepath.Join(privateDir, "v3-source.db")
	if _, _, closeV3, _, err := buildV3AttachmentHandlers(cfg, store); err == nil || closeV3 != nil {
		t.Fatal("v3 attachment handlers accepted no enrolled attachment device binding")
	}
}

func TestBuildPermitHandlerRejectsUnavailableDirectoryAtStartup(t *testing.T) {
	privateDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(privateDir, "issuer.key")
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(issuerPrivate)), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	machines := `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"],"attachment_device_id":"AQEBAQEBAQEBAQEBAQEBAQ"}]`
	_, store, err := buildRelayHandler(config.Config{DataDir: dataDir, RelayEnabled: true, RelayMachinesJSON: machines})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := permitHandlerConfig(t, privateDir, keyPath)
	cfg.DataDir = dataDir
	cfg.RelayMachinesJSON = machines
	if _, closePermit, _, err := buildPermitHandler(cfg, store); err == nil || closePermit != nil {
		t.Fatal("permit handler accepted unavailable directory snapshot")
	}
}

func TestPermitRuntimeMintsPermitOnlyForBoundMachineHolder(t *testing.T) {
	machinePublic, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machineBPublic, machineBPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, recipientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	senderID, recipientID, conversationID := [16]byte{1}, [16]byte{2}, [16]byte{3}
	membership := [32]byte{4}
	issuerID := [32]byte{5}
	entries := []attachmentv2.DirectoryEntry{
		{Device: &attachmentv2.DirectoryDevice{DeviceID: senderID, Generation: 1, SigningKeyID: [32]byte{6}, SigningPublicKey: [32]byte(holderPublic), HPKEKeyID: [32]byte{7}, HPKEPublicKey: [32]byte{8}}},
		{Device: &attachmentv2.DirectoryDevice{DeviceID: recipientID, Generation: 1, SigningKeyID: [32]byte{9}, SigningPublicKey: [32]byte(recipientPrivate), HPKEKeyID: [32]byte{10}, HPKEPublicKey: [32]byte{11}}},
		{Membership: &attachmentv2.DirectoryMembership{ConversationID: conversationID, SenderDeviceID: senderID, SenderGeneration: 1, RecipientDeviceID: recipientID, RecipientGeneration: 1, Commitment: membership}},
		{Issuer: &attachmentv2.DirectoryPermitIssuer{KeyID: issuerID, PublicKey: [32]byte(issuerPublic)}},
	}
	hashes, err := attachmentv2.DirectoryEntryHashes(entries)
	if err != nil {
		t.Fatal(err)
	}
	head := attachmentv2.DirectoryHead{Audience: [32]byte{12}, RootKeyID: [32]byte{13}, TreeSize: uint64(len(entries)), TreeRoot: attachmentv2.DirectoryMerkleRoot(hashes), Sequence: 1, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(20*time.Second)), RevocationEpoch: 1}
	if err := attachmentv2.SignDirectoryHead(&head, rootPrivate); err != nil {
		t.Fatal(err)
	}
	rawHead, err := attachmentv2.EncodeDirectoryHead(head)
	if err != nil {
		t.Fatal(err)
	}
	rawSnapshot, err := attachmentv2.EncodeDirectorySnapshot(attachmentv2.DirectorySnapshot{RawHead: rawHead, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	privateDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(privateDir, "directory.cbor")
	if err := os.WriteFile(snapshotPath, rawSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	issuerPath := filepath.Join(privateDir, "issuer.key")
	if err := os.WriteFile(issuerPath, []byte(base64.RawURLEncoding.EncodeToString(issuerPrivate)), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	machines := `[{"id":"machine-a","public_key":"` + base64.RawURLEncoding.EncodeToString(machinePublic) + `","endpoint_prefixes":["agent/a/"],"attachment_device_id":"` + base64.RawURLEncoding.EncodeToString(senderID[:]) + `"},{"id":"machine-b","public_key":"` + base64.RawURLEncoding.EncodeToString(machineBPublic) + `","endpoint_prefixes":["agent/b/"],"attachment_device_id":"` + base64.RawURLEncoding.EncodeToString(recipientID[:]) + `"}]`
	_, store, err := buildRelayHandler(config.Config{DataDir: dataDir, RelayEnabled: true, RelayMachinesJSON: machines})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := config.Config{DataDir: dataDir, PermitIssuanceEnabled: true, DirectoryEnabled: true, DirectorySnapshotFile: snapshotPath, DirectoryAudience: head.Audience, DirectoryRootKeyID: head.RootKeyID, DirectoryRootPublicKey: rootPublic, PermitIssuerKeyID: issuerID, PermitIssuerPrivateKeyFile: issuerPath, PermitMaxLifetimeSeconds: 15, PermitMaxBytes: 1024, PermitMaxChunks: 1, PermitMaxOperations: 1, PermitMaxActive: 4, RelayMachinesJSON: machines}
	handler, closePermit, readiness, err := buildPermitHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closePermit)
	if readiness == nil || readiness() != nil {
		t.Fatal("permit runtime was not ready with its verified directory snapshot")
	}
	permitRequest := attachmentv2.PermitRequest{RequestID: [16]byte{14}, HolderDeviceID: senderID, HolderGeneration: 1, HolderRole: attachmentv2.PermitHolderSender, TransferID: [16]byte{15}, ConversationID: conversationID, SenderDeviceID: senderID, SenderGeneration: 1, RecipientDeviceID: recipientID, RecipientGeneration: 1, AttemptGeneration: 1, Operation: attachmentv2.PermitOperationOffer, MembershipCommitment: membership, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(10*time.Second)), MaxBytes: 1024, MaxChunks: 1, MaxOperations: 1}
	if err := attachmentv2.SignPermitRequest(&permitRequest, holderPrivate); err != nil {
		t.Fatal(err)
	}
	body, err := attachmentv2.EncodePermitRequest(permitRequest)
	if err != nil {
		t.Fatal(err)
	}
	request := signedPermitHTTPTestRequest(t, machinePrivate, "machine-a", body, "request-1", clock)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%x", response.Code, response.Body.Bytes())
	}
	permit, err := attachmentv2.DecodePermit(response.Body.Bytes())
	if err != nil || permit.HolderDeviceID != senderID || permit.IssuerKeyID != issuerID {
		t.Fatalf("permit=%+v err=%v", permit, err)
	}
	badRequest := signedPermitHTTPTestRequest(t, machineBPrivate, "machine-b", body, "request-2", clock)
	badResponse := httptest.NewRecorder()
	handler.ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusForbidden {
		t.Fatalf("unbound machine status=%d", badResponse.Code)
	}
	if err := os.Remove(snapshotPath); err != nil {
		t.Fatal(err)
	}
	if err := readiness(); err == nil {
		t.Fatal("permit runtime remained ready after its current directory disappeared")
	}
}

func TestV3PermitRuntimeMintsOnlyForBoundMachineHolder(t *testing.T) {
	machinePublic, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machineBPublic, machineBPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderPublic, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	senderID, recipientID, conversationID := [16]byte{1}, [16]byte{2}, [16]byte{3}
	membership, issuerID := [32]byte{4}, [32]byte{5}
	entries := []attachmentv2.DirectoryEntry{
		{Device: &attachmentv2.DirectoryDevice{DeviceID: senderID, Generation: 1, SigningKeyID: [32]byte{6}, SigningPublicKey: [32]byte(holderPublic), HPKEKeyID: [32]byte{7}, HPKEPublicKey: [32]byte{8}}},
		{Device: &attachmentv2.DirectoryDevice{DeviceID: recipientID, Generation: 1, SigningKeyID: [32]byte{9}, SigningPublicKey: [32]byte(recipientPublic), HPKEKeyID: [32]byte{10}, HPKEPublicKey: [32]byte{11}}},
		{Membership: &attachmentv2.DirectoryMembership{ConversationID: conversationID, SenderDeviceID: senderID, SenderGeneration: 1, RecipientDeviceID: recipientID, RecipientGeneration: 1, Commitment: membership}},
		{Issuer: &attachmentv2.DirectoryPermitIssuer{KeyID: issuerID, PublicKey: [32]byte(issuerPublic)}},
	}
	hashes, err := attachmentv2.DirectoryEntryHashes(entries)
	if err != nil {
		t.Fatal(err)
	}
	head := attachmentv2.DirectoryHead{Audience: [32]byte{12}, RootKeyID: [32]byte{13}, TreeSize: uint64(len(entries)), TreeRoot: attachmentv2.DirectoryMerkleRoot(hashes), Sequence: 1, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(20*time.Second)), RevocationEpoch: 1}
	if err := attachmentv2.SignDirectoryHead(&head, rootPrivate); err != nil {
		t.Fatal(err)
	}
	rawHead, err := attachmentv2.EncodeDirectoryHead(head)
	if err != nil {
		t.Fatal(err)
	}
	rawSnapshot, err := attachmentv2.EncodeDirectorySnapshot(attachmentv2.DirectorySnapshot{RawHead: rawHead, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	privateDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(privateDir, "directory.cbor")
	if err := os.WriteFile(snapshotPath, rawSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	issuerPath := filepath.Join(privateDir, "issuer.key")
	if err := os.WriteFile(issuerPath, []byte(base64.RawURLEncoding.EncodeToString(issuerPrivate)), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	machines := `[{"id":"machine-a","public_key":"` + base64.RawURLEncoding.EncodeToString(machinePublic) + `","endpoint_prefixes":["agent/a/"],"attachment_device_id":"` + base64.RawURLEncoding.EncodeToString(senderID[:]) + `"},{"id":"machine-b","public_key":"` + base64.RawURLEncoding.EncodeToString(machineBPublic) + `","endpoint_prefixes":["agent/b/"],"attachment_device_id":"` + base64.RawURLEncoding.EncodeToString(recipientID[:]) + `"}]`
	_, store, err := buildRelayHandler(config.Config{DataDir: dataDir, RelayEnabled: true, RelayMachinesJSON: machines})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := config.Config{DataDir: dataDir, AttachmentV3Enabled: true, AttachmentV3SourceStoreFile: filepath.Join(privateDir, "v3-source.db"), DirectoryEnabled: true, DirectorySnapshotFile: snapshotPath, DirectoryAudience: head.Audience, DirectoryRootKeyID: head.RootKeyID, DirectoryRootPublicKey: rootPublic, PermitIssuerKeyID: issuerID, PermitIssuerPrivateKeyFile: issuerPath, PermitMaxLifetimeSeconds: 15, PermitMaxBytes: 1024, PermitMaxChunks: 1, PermitMaxOperations: 1, PermitMaxActive: 4, RelayMachinesJSON: machines}
	permitHandler, _, closeV3, readiness, err := buildV3AttachmentHandlers(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeV3)
	if readiness == nil || readiness() != nil {
		t.Fatal("v3 permit runtime was not ready with its verified directory snapshot")
	}
	permitRequest := attachmentv3.PermitRequest{RequestID: [16]byte{14}, HolderDeviceID: senderID, HolderGeneration: 1, HolderRole: attachmentv3.PermitHolderSender, TransferID: [16]byte{15}, ConversationID: conversationID, SenderDeviceID: senderID, SenderGeneration: 1, RecipientDeviceID: recipientID, RecipientGeneration: 1, Operation: attachmentv3.PermitOperationSourceInit, MembershipCommitment: membership, StagedManifestCommitment: [32]byte{16}, IssuedAt: testUnix(t, clock.Add(-time.Second)), ExpiresAt: testUnix(t, clock.Add(10*time.Second)), MaxBytes: 1024, MaxChunks: 1, MaxOperations: 1}
	if err := attachmentv3.SignPermitRequest(&permitRequest, holderPrivate); err != nil {
		t.Fatal(err)
	}
	body, err := attachmentv3.EncodePermitRequest(permitRequest)
	if err != nil {
		t.Fatal(err)
	}
	request := signedV3PermitHTTPTestRequest(t, machinePrivate, "machine-a", body, "request-1", clock)
	response := httptest.NewRecorder()
	permitHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%x", response.Code, response.Body.Bytes())
	}
	permit, err := attachmentv3.DecodePermit(response.Body.Bytes())
	if err != nil || permit.HolderDeviceID != senderID || permit.IssuerKeyID != issuerID || permit.StagedManifestCommitment != permitRequest.StagedManifestCommitment {
		t.Fatalf("permit=%+v err=%v", permit, err)
	}
	badRequest := signedV3PermitHTTPTestRequest(t, machineBPrivate, "machine-b", body, "request-2", clock)
	badResponse := httptest.NewRecorder()
	permitHandler.ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusForbidden {
		t.Fatalf("unbound machine status=%d", badResponse.Code)
	}
}

func testUnix(t testing.TB, value time.Time) uint64 {
	t.Helper()
	seconds := value.Unix()
	if seconds < 0 {
		t.Fatalf("time %s predates Unix epoch", value)
	}
	return uint64(seconds) // #nosec G115 -- negative values are rejected above.
}

func signedPermitHTTPTestRequest(t *testing.T, private ed25519.PrivateKey, machineID string, body []byte, nonce string, timestamp time.Time) *http.Request {
	t.Helper()
	signed := relay.SignedRequest{MachineID: machineID, Method: http.MethodPost, Path: "/v2/permits", Body: body, Timestamp: timestamp, Nonce: nonce}
	signed.Signature = ed25519.Sign(private, relay.CanonicalRequest(signed))
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v2/permits", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/cbor")
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	return request
}

func signedV3PermitHTTPTestRequest(t *testing.T, private ed25519.PrivateKey, machineID string, body []byte, nonce string, timestamp time.Time) *http.Request {
	t.Helper()
	signed := relay.SignedRequest{MachineID: machineID, Method: http.MethodPost, Path: "/v3/permits", Body: body, Timestamp: timestamp, Nonce: nonce}
	signed.Signature = ed25519.Sign(private, relay.CanonicalRequest(signed))
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v3/permits", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/cbor")
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	return request
}

func TestPermitIssuerLifetimeRejectsOutOfRangeConfiguration(t *testing.T) {
	if _, err := permitIssuerLifetime(0); err == nil {
		t.Fatal("zero permit lifetime was accepted")
	}
	if _, err := permitIssuerLifetime(61); err == nil {
		t.Fatal("oversized permit lifetime was accepted")
	}
	if lifetime, err := permitIssuerLifetime(60); err != nil || lifetime != 60*time.Second {
		t.Fatalf("lifetime=%v err=%v", lifetime, err)
	}
}

func permitHandlerConfig(t *testing.T, privateDir, keyPath string) config.Config {
	t.Helper()
	rootPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return config.Config{DataDir: t.TempDir(), PermitIssuanceEnabled: true, DirectoryEnabled: true, DirectorySnapshotFile: filepath.Join(privateDir, "directory.cbor"), DirectoryAudience: [32]byte{1}, DirectoryRootKeyID: [32]byte{2}, DirectoryRootPublicKey: rootPublic, PermitIssuerKeyID: [32]byte{3}, PermitIssuerPrivateKeyFile: keyPath, PermitMaxLifetimeSeconds: 30, PermitMaxBytes: 1 << 20, PermitMaxChunks: 4, PermitMaxOperations: 2, PermitMaxActive: 4, RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`}
}

func TestBuildDirectoryHandlerRequiresValidPrivateSnapshot(t *testing.T) {
	_, closeRelay, err := buildRelayHandler(config.Config{DataDir: t.TempDir(), RelayEnabled: true, RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeRelay.Close() })
	if _, err := buildDirectoryHandler(config.Config{DirectoryEnabled: true, DirectorySnapshotFile: "/does/not/exist", RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`}, closeRelay); err == nil {
		t.Fatal("missing snapshot source accepted")
	}
}
