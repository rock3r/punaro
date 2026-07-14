package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/config"
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
	if _, closePermit, err := buildPermitHandler(cfg, store); err == nil || closePermit != nil {
		t.Fatal("permit handler accepted no enrolled attachment device binding")
	}
}

func TestBuildPermitHandlerBuildsBoundedAuthenticatedIssuer(t *testing.T) {
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
	handler, closePermit, err := buildPermitHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil || closePermit == nil {
		t.Fatal("permit handler did not return a bounded runtime")
	}
	closePermit()
}

func TestBuildAttachmentRelayHandlerBuildsBoundedAuthenticatedFallback(t *testing.T) {
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
	cfg.AttachmentRelayEnabled = true
	handler, closeAttachment, err := buildAttachmentRelayHandler(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	if handler == nil || closeAttachment == nil {
		t.Fatal("attachment relay handler did not return a bounded runtime")
	}
	closeAttachment()
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
	return config.Config{DataDir: t.TempDir(), PermitIssuanceEnabled: true, DirectoryEnabled: true, DirectorySnapshotFile: filepath.Join(privateDir, "directory.cbor"), DirectoryAudience: [32]byte{1}, DirectoryRootKeyID: [32]byte{2}, DirectoryRootPublicKey: rootPublic, PermitIssuerKeyID: [32]byte{3}, PermitIssuerPrivateKeyFile: keyPath, PermitMaxLifetimeSeconds: 30, PermitMaxBytes: 1 << 20, PermitMaxChunks: 4, PermitMaxOperations: 2, RelayMachinesJSON: `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`}
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
