package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUsesExplicitDotEnvWithoutOverridingProcess(t *testing.T) {
	t.Setenv("PUNARO_LISTEN_ADDR", "127.0.0.1:9999")
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("PUNARO_LISTEN_ADDR=0.0.0.0:8080\nPUNARO_LOG_LEVEL=debug\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "127.0.0.1:9999" {
		t.Fatalf("listen address = %q", cfg.ListenAddr)
	}
}
func TestLoadRejectsInvalidLevel(t *testing.T) {
	t.Setenv("PUNARO_LOG_LEVEL", "nope")
	if _, err := Load(""); err == nil {
		t.Fatal("Load succeeded for invalid log level")
	}
}

func TestLoadRejectsEnabledAttachmentsWithoutEnrollment(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENTS_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("Load succeeded with attachments enabled but no enrollment configuration")
	}
}

func TestLoadRejectsNonLoopbackAttachmentListener(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENTS_ENABLED", "true")
	t.Setenv("PUNARO_ATTACHMENT_DEVICE_KEYS_JSON", `{}`)
	t.Setenv("PUNARO_ATTACHMENT_MEMBERSHIP_JSON", `[]`)
	t.Setenv("PUNARO_LISTEN_ADDR", "0.0.0.0:8080")
	if _, err := Load(""); err == nil {
		t.Fatal("Load accepted non-loopback listener for attachment bearer sessions")
	}
}

func TestLoadRejectsNonLoopbackListenerWhilePublicRuntimeIsUnavailable(t *testing.T) {
	t.Setenv("PUNARO_LISTEN_ADDR", "0.0.0.0:8080")
	if _, err := Load(""); err == nil {
		t.Fatal("Load accepted a public listener before the authenticated public runtime exists")
	}
}

func TestLoadRejectsLocalhostNameUntilResolvedBindingIsImplemented(t *testing.T) {
	t.Setenv("PUNARO_LISTEN_ADDR", "localhost:8080")
	if _, err := Load(""); err == nil {
		t.Fatal("Load accepted localhost without proving its resolved address is loopback")
	}
}

func TestLoadRequiresMachineEnrollmentWhenRelayIsEnabled(t *testing.T) {
	t.Setenv("PUNARO_RELAY_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_MACHINES_JSON", "")
	if _, err := Load(""); err == nil {
		t.Fatal("enabled relay without machine enrollment was accepted")
	}
}

func TestLoadRequiresAuthenticatedRelayAndPrivateSnapshotForDirectoryService(t *testing.T) {
	t.Setenv("PUNARO_DIRECTORY_ENABLED", "true")
	t.Setenv("PUNARO_DIRECTORY_SNAPSHOT_FILE", "/var/lib/punaro/private/directory.cbor")
	if _, err := Load(""); err == nil {
		t.Fatal("directory service without relay authentication was accepted")
	}
	t.Setenv("PUNARO_RELAY_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_MACHINES_JSON", `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`)
	config, err := Load("")
	if err != nil || !config.DirectoryEnabled || config.DirectorySnapshotFile == "" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	t.Setenv("PUNARO_DIRECTORY_SNAPSHOT_FILE", "relative/directory.cbor")
	if _, err := Load(""); err == nil {
		t.Fatal("relative directory snapshot path was accepted")
	}
}

func TestLoadAcceptsExplicitRelayMachineEnrollment(t *testing.T) {
	t.Setenv("PUNARO_RELAY_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_MACHINES_JSON", `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`)
	config, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !config.RelayEnabled || config.RelayMachinesJSON == "" {
		t.Fatalf("relay config = %#v", config)
	}
}

func TestLoadRejectsPartialCloudflareAccessVerifierConfiguration(t *testing.T) {
	t.Setenv("PUNARO_ACCESS_ISSUER", "https://team.cloudflareaccess.com")
	t.Setenv("PUNARO_ACCESS_AUDIENCE", "")
	t.Setenv("PUNARO_ACCESS_JWKS_URL", "")
	if _, err := Load(""); err == nil {
		t.Fatal("partial Access verifier configuration was accepted")
	}
}
