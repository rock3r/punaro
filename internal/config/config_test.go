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

func TestLoadPostgresDefaultsDisabled(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PostgresEnabled || cfg.PostgresDSNFile != "" {
		t.Fatalf("PostgreSQL unexpectedly enabled: %#v", cfg)
	}
}

func TestLoadRequiresAbsolutePostgresDSNFileWhenEnabled(t *testing.T) {
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("enabled PostgreSQL accepted without a DSN file")
	}
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "relative/postgres.dsn")
	if _, err := Load(""); err == nil {
		t.Fatal("enabled PostgreSQL accepted a relative DSN file")
	}
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-postgres-dsn")
	cfg, err := Load("")
	if err != nil || !cfg.PostgresEnabled || cfg.PostgresDSNFile == "" {
		t.Fatalf("config=%#v err=%v", cfg, err)
	}
}

func TestLoadRejectsPostgresDSNFileWhileDisabled(t *testing.T) {
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-postgres-dsn")
	if _, err := Load(""); err == nil {
		t.Fatal("disabled PostgreSQL accepted a dangling DSN file")
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

func TestLoadAcceptsOnlyValidatedDeviceIngressProfiles(t *testing.T) {
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-app-dsn")
	t.Setenv("PUNARO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("PUNARO_INGRESS_MODE", "internet")
	t.Setenv("PUNARO_PUBLIC_URL", "https://punaro.example")
	cfg, err := Load("")
	if err != nil || !cfg.DeviceAuthEnabled || cfg.IngressMode != "internet" {
		t.Fatalf("config=%#v err=%v", cfg, err)
	}

	t.Setenv("PUNARO_INGRESS_MODE", "lan")
	t.Setenv("PUNARO_PUBLIC_URL", "")
	t.Setenv("PUNARO_LISTEN_ADDR", "192.168.50.4:8080")
	t.Setenv("PUNARO_TRUSTED_LAN_CIDR", "192.168.50.0/24")
	t.Setenv("PUNARO_TRUSTED_LAN_HTTP", "true")
	cfg, err = Load("")
	if err != nil || cfg.IngressMode != "lan" || !cfg.TrustedLANHTTP {
		t.Fatalf("LAN config=%#v err=%v", cfg, err)
	}

	t.Setenv("PUNARO_LISTEN_ADDR", "0.0.0.0:8080")
	if _, err := Load(""); err == nil {
		t.Fatal("device ingress accepted a wildcard LAN bind")
	}
}

func TestLoadRequiresDistinctLoopbackHealthListener(t *testing.T) {
	cfg, err := Load("")
	if err != nil || cfg.HealthListenAddr != "127.0.0.1:8081" {
		t.Fatalf("config=%#v err=%v", cfg, err)
	}
	t.Setenv("PUNARO_HEALTH_LISTEN_ADDR", "192.168.50.4:8081")
	if _, err := Load(""); err == nil {
		t.Fatal("health listener accepted a non-loopback address")
	}
	t.Setenv("PUNARO_HEALTH_LISTEN_ADDR", "127.0.0.1:8080")
	if _, err := Load(""); err == nil {
		t.Fatal("health listener accepted the public listener address")
	}
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1:", "127.0.0.1:http", "127.0.0.1:65536"} {
		t.Setenv("PUNARO_HEALTH_LISTEN_ADDR", address)
		if _, err := Load(""); err == nil {
			t.Fatalf("health listener accepted invalid port in %q", address)
		}
	}
	t.Setenv("PUNARO_LISTEN_ADDR", "127.0.0.1:8081")
	t.Setenv("PUNARO_HEALTH_LISTEN_ADDR", "127.0.0.1:08081")
	if _, err := Load(""); err == nil {
		t.Fatal("health listener accepted a zero-padded alias of the public listener")
	}
}

func TestLoadRejectsLegacyRoutesOnNonLoopbackDeviceIngress(t *testing.T) {
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-app-dsn")
	t.Setenv("PUNARO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("PUNARO_INGRESS_MODE", "lan")
	t.Setenv("PUNARO_LISTEN_ADDR", "192.168.50.4:8080")
	t.Setenv("PUNARO_TRUSTED_LAN_CIDR", "192.168.50.0/24")
	t.Setenv("PUNARO_TRUSTED_LAN_HTTP", "true")
	t.Setenv("PUNARO_RELAY_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_MACHINES_JSON", `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`)
	if _, err := Load(""); err == nil {
		t.Fatal("non-loopback device ingress exposed legacy relay routes")
	}
}

func TestLoadRejectsDeviceIngressWithoutPostgres(t *testing.T) {
	t.Setenv("PUNARO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("PUNARO_INGRESS_MODE", "internet")
	t.Setenv("PUNARO_PUBLIC_URL", "https://punaro.example")
	if _, err := Load(""); err == nil {
		t.Fatal("device ingress accepted no PostgreSQL application store")
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

func TestLoadRequiresCompletePermitIssuanceTrustAndExplicitLimits(t *testing.T) {
	t.Setenv("PUNARO_PERMIT_ISSUANCE_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_MACHINES_JSON", `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"],"attachment_device_id":"AQEBAQEBAQEBAQEBAQEBAQ"}]`)
	t.Setenv("PUNARO_DIRECTORY_ENABLED", "true")
	t.Setenv("PUNARO_DIRECTORY_SNAPSHOT_FILE", "/var/lib/punaro/private/directory.cbor")
	if _, err := Load(""); err == nil {
		t.Fatal("permit issuance without pinned trust and issuer configuration was accepted")
	}
	t.Setenv("PUNARO_DIRECTORY_AUDIENCE", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
	t.Setenv("PUNARO_DIRECTORY_ROOT_KEY_ID", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI")
	t.Setenv("PUNARO_DIRECTORY_ROOT_PUBLIC_KEY", "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM")
	t.Setenv("PUNARO_PERMIT_ISSUER_KEY_ID", "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ")
	t.Setenv("PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE", "/var/lib/punaro/private/permit-issuer.key")
	t.Setenv("PUNARO_PERMIT_MAX_LIFETIME_SECONDS", "30")
	t.Setenv("PUNARO_PERMIT_MAX_BYTES", "1048576")
	t.Setenv("PUNARO_PERMIT_MAX_CHUNKS", "4")
	t.Setenv("PUNARO_PERMIT_MAX_OPERATIONS", "2")
	t.Setenv("PUNARO_PERMIT_MAX_ACTIVE", "8")
	cfg, err := Load("")
	if err != nil || !cfg.PermitIssuanceEnabled || cfg.PermitMaxLifetimeSeconds != 30 || cfg.PermitMaxActive != 8 {
		t.Fatalf("config=%#v err=%v", cfg, err)
	}
	t.Setenv("PUNARO_PERMIT_MAX_ACTIVE", "12305")
	if _, err := Load(""); err == nil {
		t.Fatal("permit issuance accepted an unbounded active permit ceiling")
	}
	t.Setenv("PUNARO_PERMIT_MAX_ACTIVE", "8")
	t.Setenv("PUNARO_ATTACHMENT_RELAY_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("withheld attachment relay was accepted")
	}
	t.Setenv("PUNARO_PERMIT_MAX_LIFETIME_SECONDS", "61")
	if _, err := Load(""); err == nil {
		t.Fatal("permit issuance accepted a lifetime over sixty seconds")
	}
}

func TestLoadRejectsWithheldAttachmentRelay(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENT_RELAY_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("withheld attachment relay was accepted")
	}
}

func TestLoadRequiresIndependentV3AttachmentRuntimeTrustAndPrivateStore(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENT_V3_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_MACHINES_JSON", `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"],"attachment_device_id":"AQEBAQEBAQEBAQEBAQEBAQ"}]`)
	t.Setenv("PUNARO_DIRECTORY_ENABLED", "true")
	t.Setenv("PUNARO_DIRECTORY_SNAPSHOT_FILE", "/var/lib/punaro/private/directory.cbor")
	if _, err := Load(""); err == nil {
		t.Fatal("v3 runtime without explicit permit trust was accepted")
	}
	t.Setenv("PUNARO_DIRECTORY_AUDIENCE", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
	t.Setenv("PUNARO_DIRECTORY_ROOT_KEY_ID", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI")
	t.Setenv("PUNARO_DIRECTORY_ROOT_PUBLIC_KEY", "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM")
	t.Setenv("PUNARO_PERMIT_ISSUER_KEY_ID", "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ")
	t.Setenv("PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE", "/var/lib/punaro/private/permit-issuer.key")
	t.Setenv("PUNARO_PERMIT_MAX_LIFETIME_SECONDS", "30")
	t.Setenv("PUNARO_PERMIT_MAX_BYTES", "1048576")
	t.Setenv("PUNARO_PERMIT_MAX_CHUNKS", "4")
	t.Setenv("PUNARO_PERMIT_MAX_OPERATIONS", "2")
	t.Setenv("PUNARO_PERMIT_MAX_ACTIVE", "8")
	if _, err := Load(""); err == nil {
		t.Fatal("v3 runtime without private source store was accepted")
	}
	t.Setenv("PUNARO_ATTACHMENT_V3_SOURCE_STORE_FILE", "relative/source.db")
	if _, err := Load(""); err == nil {
		t.Fatal("v3 runtime accepted a relative source store")
	}
	t.Setenv("PUNARO_ATTACHMENT_V3_SOURCE_STORE_FILE", "/var/lib/punaro/private/source.db")
	cfg, err := Load("")
	if err != nil || !cfg.AttachmentV3Enabled || cfg.AttachmentV3SourceStoreFile == "" || cfg.PermitIssuanceEnabled {
		t.Fatalf("config=%#v err=%v", cfg, err)
	}
	t.Setenv("PUNARO_PERMIT_MAX_LIFETIME_SECONDS", "31")
	if _, err := Load(""); err == nil {
		t.Fatal("v3 runtime accepted a permit lifetime over thirty seconds")
	}
	t.Setenv("PUNARO_PERMIT_MAX_LIFETIME_SECONDS", "30")
	t.Setenv("PUNARO_PERMIT_ISSUANCE_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("v3 runtime was combined with the v2 permit route")
	}
}

func TestLoadRejectsMalformedPinnedPermitTrust(t *testing.T) {
	t.Setenv("PUNARO_PERMIT_ISSUANCE_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_MACHINES_JSON", `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"],"attachment_device_id":"AQEBAQEBAQEBAQEBAQEBAQ"}]`)
	t.Setenv("PUNARO_DIRECTORY_ENABLED", "true")
	t.Setenv("PUNARO_DIRECTORY_SNAPSHOT_FILE", "/var/lib/punaro/private/directory.cbor")
	t.Setenv("PUNARO_DIRECTORY_AUDIENCE", "not-base64url")
	t.Setenv("PUNARO_DIRECTORY_ROOT_KEY_ID", "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI")
	t.Setenv("PUNARO_DIRECTORY_ROOT_PUBLIC_KEY", "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM")
	t.Setenv("PUNARO_PERMIT_ISSUER_KEY_ID", "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ")
	t.Setenv("PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE", "/var/lib/punaro/private/permit-issuer.key")
	t.Setenv("PUNARO_PERMIT_MAX_LIFETIME_SECONDS", "30")
	t.Setenv("PUNARO_PERMIT_MAX_BYTES", "1048576")
	t.Setenv("PUNARO_PERMIT_MAX_CHUNKS", "4")
	t.Setenv("PUNARO_PERMIT_MAX_OPERATIONS", "2")
	t.Setenv("PUNARO_PERMIT_MAX_ACTIVE", "8")
	if _, err := Load(""); err == nil {
		t.Fatal("permit issuance accepted malformed pinned root material")
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

func TestLoadAcceptsExactlyOneCloudflareAccessJWKSSource(t *testing.T) {
	t.Setenv("PUNARO_ACCESS_ISSUER", "https://team.cloudflareaccess.com")
	t.Setenv("PUNARO_ACCESS_AUDIENCE", "audience")
	t.Setenv("PUNARO_ACCESS_JWKS_FILE", "/etc/punaro/jwks/current.json")
	config, err := Load("")
	if err != nil || config.AccessJWKSFile != "/etc/punaro/jwks/current.json" {
		t.Fatalf("config=%#v err=%v", config, err)
	}
	t.Setenv("PUNARO_ACCESS_JWKS_URL", "https://team.cloudflareaccess.com/certs")
	if _, err := Load(""); err == nil {
		t.Fatal("multiple Access JWKS sources were accepted")
	}
	t.Setenv("PUNARO_ACCESS_JWKS_URL", "")
	t.Setenv("PUNARO_ACCESS_JWKS_FILE", "relative/current.json")
	if _, err := Load(""); err == nil {
		t.Fatal("relative Access JWKS snapshot was accepted")
	}
}
