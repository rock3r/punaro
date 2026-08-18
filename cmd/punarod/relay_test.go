package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/config"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
)

type transitionDatabaseDouble struct {
	legacyKey  ed25519.PublicKey
	credential string
	device     punaropostgres.AuthenticatedDevice
	err        error
}

func (d *transitionDatabaseDouble) ClientLifecycleRuntimeReady(context.Context) error { return d.err }

func (d *transitionDatabaseDouble) RedeemEnrollment(context.Context, punaropostgres.RedeemEnrollment) (punaropostgres.DeviceCredential, error) {
	return punaropostgres.DeviceCredential{}, errors.New("not used")
}

func (d *transitionDatabaseDouble) AuthenticateDevice(_ context.Context, credential string) (punaropostgres.AuthenticatedDevice, error) {
	if d.err != nil || credential != d.credential {
		return punaropostgres.AuthenticatedDevice{}, punaropostgres.ErrUnauthenticated
	}
	return d.device, nil
}

func (d *transitionDatabaseDouble) SelfRevokeDevice(context.Context, string, string) (punaropostgres.DeviceRevocation, error) {
	return punaropostgres.DeviceRevocation{}, errors.New("not used")
}

func (d *transitionDatabaseDouble) DeviceSessionCurrent(_ context.Context, authenticated punaropostgres.AuthenticatedDevice) (bool, error) {
	return d.err == nil && authenticated == d.device, d.err
}

func (d *transitionDatabaseDouble) ResolveLegacyMachine(_ context.Context, key ed25519.PublicKey) (string, error) {
	if d.err != nil || !bytes.Equal(key, d.legacyKey) {
		return "", punaropostgres.ErrUnauthenticated
	}
	return "11111111-1111-4111-8111-111111111111", nil
}

func (d *transitionDatabaseDouble) ResolveMigratedLegacyPublicKey(_ context.Context, authenticated punaropostgres.AuthenticatedDevice) (ed25519.PublicKey, error) {
	if d.err != nil || authenticated != d.device {
		return nil, punaropostgres.ErrUnauthenticated
	}
	return append(ed25519.PublicKey(nil), d.legacyKey...), nil
}

func TestBuildRelayHandlerRejectsInvalidEnrollment(t *testing.T) {
	_, closeRelay, err := buildRelayHandler(config.Config{DataDir: t.TempDir(), RelayEnabled: true, RelayMachinesJSON: `[{"id":"machine-a","public_key":"invalid","endpoint_prefixes":["agent/"]}]`})
	if closeRelay != nil {
		t.Fatal("invalid relay configuration returned a closer")
	}
	if err == nil {
		t.Fatal("invalid enrollment enabled relay routes")
	}
}

func TestBuildRelayHandlerRevokedEnrollmentFailsClosedAfterRestart(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	machines := `[{"id":"machine-a","public_key":"` + base64.RawURLEncoding.EncodeToString(public) + `","endpoint_prefixes":["agent/a/"]}]`
	dataDir := t.TempDir()
	first, firstStore, err := buildRelayHandler(config.Config{DataDir: dataDir, RelayEnabled: true, RelayMachinesJSON: machines})
	if err != nil {
		t.Fatal(err)
	}
	request := signedRelayRequest(t, private, "machine-a", "first-request")
	response := httptest.NewRecorder()
	first.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("initial status=%d body=%s", response.Code, response.Body.String())
	}
	if err := firstStore.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, restartedStore, err := buildRelayHandler(config.Config{DataDir: dataDir, RelayEnabled: true, RelayMachinesJSON: `[]`})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restartedStore.Close() })
	request = signedRelayRequest(t, private, "machine-a", "revoked-request")
	response = httptest.NewRecorder()
	restarted.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked status=%d body=%s", response.Code, response.Body.String())
	}
}

func signedRelayRequest(t *testing.T, private ed25519.PrivateKey, machineID, nonce string) *http.Request {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/v1/machines/me/endpoints", bytes.NewBufferString(`{"endpoints":["agent/a/session"]}`))
	signed := relay.SignedRequest{MachineID: machineID, Method: request.Method, Path: request.URL.Path, Body: []byte(`{"endpoints":["agent/a/session"]}`), Timestamp: time.Now().UTC(), Nonce: nonce}
	signed.Signature = ed25519.Sign(private, relay.CanonicalRequest(signed))
	request.Header.Set("X-Punaro-Machine", signed.MachineID)
	request.Header.Set("X-Punaro-Timestamp", signed.Timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-Punaro-Nonce", signed.Nonce)
	request.Header.Set("X-Punaro-Signature", base64.RawURLEncoding.EncodeToString(signed.Signature))
	return request
}

func TestBuildRelayCanSelectPostgresBackendWithoutOpeningSQLite(t *testing.T) {
	backend, err := relay.Open(filepath.Join(t.TempDir(), "postgres-backend-double.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	handler, sqliteStore, err := buildRelayHandler(config.Config{
		DataDir: t.TempDir(), RelayEnabled: true, RelayStore: "postgres",
		RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`,
	}, backend)
	if err != nil || handler == nil || sqliteStore != nil {
		t.Fatalf("handler=%v sqlite=%v err=%v", handler, sqliteStore, err)
	}
}

func TestPostgresTransitionAuthorityMapsBothPathsToExactLegacyKey(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	database := &transitionDatabaseDouble{legacyKey: public, credential: "not-secret", device: punaropostgres.AuthenticatedDevice{PrincipalID: "11111111-1111-4111-8111-111111111111", LookupID: "22222222-2222-4222-8222-222222222222", Generation: 1}}
	authority := postgresTransitionAuthority{database: database}
	legacyResult, err := authority.AuthorizeTransition(t.Context(), "", public)
	if err != nil || legacyResult.PrincipalID != "11111111-1111-4111-8111-111111111111" || !bytes.Equal(legacyResult.LegacyPublicKey, public) || legacyResult.Current(t.Context()) != nil {
		t.Fatalf("legacy result=%#v err=%v", legacyResult, err)
	}
	deviceResult, err := authority.AuthorizeTransition(t.Context(), database.credential, nil)
	if err != nil || deviceResult.PrincipalID != database.device.PrincipalID || deviceResult.CredentialLookupID != database.device.LookupID || deviceResult.CredentialGeneration != database.device.Generation || !bytes.Equal(deviceResult.LegacyPublicKey, public) || deviceResult.Current(t.Context()) != nil {
		t.Fatalf("device result=%#v err=%v", deviceResult, err)
	}
	database.err = errors.New("revoked")
	if err := legacyResult.Current(t.Context()); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("closed legacy session err=%v", err)
	}
	if err := deviceResult.Current(t.Context()); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("revoked device session err=%v", err)
	}
	database.err = nil
	if _, err := authority.AuthorizeTransition(t.Context(), "wrong", nil); !errors.Is(err, relay.ErrForbidden) {
		t.Fatalf("wrong credential err=%v", err)
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
	cfg := legacyAttachmentConfig{DataDir: dataDir, PermitIssuanceEnabled: true, DirectoryEnabled: true, DirectorySnapshotFile: snapshotPath, DirectoryAudience: head.Audience, DirectoryRootKeyID: head.RootKeyID, DirectoryRootPublicKey: rootPublic, PermitIssuerKeyID: issuerID, PermitIssuerPrivateKeyFile: issuerPath, PermitMaxLifetimeSeconds: 15, PermitMaxBytes: 1024, PermitMaxChunks: 1, PermitMaxOperations: 1, PermitMaxActive: 4, RelayMachinesJSON: machines}
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
	cfg := legacyAttachmentConfig{DataDir: dataDir, AttachmentV3Enabled: true, AttachmentV3SourceStoreFile: filepath.Join(privateDir, "v3-source.db"), DirectoryEnabled: true, DirectorySnapshotFile: snapshotPath, DirectoryAudience: head.Audience, DirectoryRootKeyID: head.RootKeyID, DirectoryRootPublicKey: rootPublic, PermitIssuerKeyID: issuerID, PermitIssuerPrivateKeyFile: issuerPath, PermitMaxLifetimeSeconds: 15, PermitMaxBytes: 1024, PermitMaxChunks: 1, PermitMaxOperations: 1, PermitMaxActive: 4, RelayMachinesJSON: machines}
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

func permitHandlerConfig(t *testing.T, privateDir, keyPath string) legacyAttachmentConfig {
	t.Helper()
	rootPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return legacyAttachmentConfig{DataDir: t.TempDir(), PermitIssuanceEnabled: true, DirectoryEnabled: true, DirectorySnapshotFile: filepath.Join(privateDir, "directory.cbor"), DirectoryAudience: [32]byte{1}, DirectoryRootKeyID: [32]byte{2}, DirectoryRootPublicKey: rootPublic, PermitIssuerKeyID: [32]byte{3}, PermitIssuerPrivateKeyFile: keyPath, PermitMaxLifetimeSeconds: 30, PermitMaxBytes: 1 << 20, PermitMaxChunks: 4, PermitMaxOperations: 2, PermitMaxActive: 4, RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`}
}

func TestBuildDirectoryHandlerRequiresValidPrivateSnapshot(t *testing.T) {
	_, closeRelay, err := buildRelayHandler(config.Config{DataDir: t.TempDir(), RelayEnabled: true, RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeRelay.Close() })
	if _, err := buildDirectoryHandler(legacyAttachmentConfig{DirectoryEnabled: true, DirectorySnapshotFile: "/does/not/exist", RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`}, closeRelay); err == nil {
		t.Fatal("missing snapshot source accepted")
	}
}

func TestBuildRelayHandlerRejectsInvalidRetentionPolicy(t *testing.T) {
	_, store, err := buildRelayHandler(config.Config{
		DataDir:                       t.TempDir(),
		RelayEnabled:                  true,
		RelayMachinesJSON:             `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`,
		RelayPendingMaxAgeSeconds:     0,
		RelayTerminalRetentionSeconds: 30,
		RelayDeliveryMaintenanceBatch: 10,
	})
	if err == nil {
		if store != nil {
			_ = store.Close()
		}
		t.Fatal("invalid retention policy enabled relay routes")
	}
}

func TestBuildRelayHandlerAppliesRetentionPolicy(t *testing.T) {
	_, store, err := buildRelayHandler(config.Config{
		DataDir:                       t.TempDir(),
		RelayEnabled:                  true,
		RelayMachinesJSON:             `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]},{"id":"machine-b","public_key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","endpoint_prefixes":["agent/b/"]}]`,
		RelayPendingMaxAgeSeconds:     60,
		RelayTerminalRetentionSeconds: 3600,
		RelayDeliveryMaintenanceBatch: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, time.August, 18, 21, 0, 0, 0, time.UTC)
	if err := store.AdvertiseEndpoints("machine-a", []string{"agent/a/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvertiseEndpoints("machine-b", []string{"agent/b/session"}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	conversation, err := store.CreateConversation("agent/a/session", []relay.Member{
		{Endpoint: "agent/a/session", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin},
		{Endpoint: "agent/b/session", Capabilities: relay.CapReceive},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AppendMessage(relay.AppendInput{ConversationID: conversation.ID, SenderMachineID: "machine-a", FromEndpoint: "agent/a/session", Body: "aged", IdempotencyKey: "aged-1", Now: now}); err != nil {
		t.Fatal(err)
	}
	if result, err := store.MaintainDeliveries(now.Add(60*time.Second - time.Millisecond)); err != nil || result.Expired != 0 {
		t.Fatalf("default policy would not expire this early: result=%#v err=%v", result, err)
	}
	if result, err := store.MaintainDeliveries(now.Add(60 * time.Second)); err != nil || result.Expired != 1 {
		t.Fatalf("configured max age did not expire result=%#v err=%v", result, err)
	}
}

type deliveryMaintainerStub struct {
	calls chan time.Time
}

func (s *deliveryMaintainerStub) MaintainDeliveries(now time.Time) (relay.MaintenanceResult, error) {
	s.calls <- now
	return relay.MaintenanceResult{}, nil
}

func TestDeliveryMaintenanceTickInvokesMaintainer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stub := &deliveryMaintainerStub{calls: make(chan time.Time, 1)}
	ticks := make(chan time.Time, 1)
	done := make(chan struct{})
	go func() {
		runDeliveryMaintenance(ctx, stub, ticks)
		close(done)
	}()
	tick := time.Date(2026, time.August, 18, 21, 1, 0, 0, time.UTC)
	ticks <- tick
	select {
	case got := <-stub.calls:
		if !got.Equal(tick.UTC()) {
			t.Fatalf("maintainer now=%s want %s", got, tick.UTC())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance tick was not delivered")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("maintenance loop did not stop")
	}
}
