package config

import (
	"os"
	"path/filepath"
	"strings"
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

func TestPostgresRelaySelectionIsExplicitAndRequiresPostgres(t *testing.T) {
	t.Setenv("PUNARO_RELAY_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_MACHINES_JSON", `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`)
	t.Setenv("PUNARO_RELAY_STORE", "postgres")
	if _, err := Load(""); err == nil {
		t.Fatal("PostgreSQL relay selection succeeded without PostgreSQL")
	}
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-postgres-dsn")
	cfg, err := Load("")
	if err != nil || cfg.RelayStore != "postgres" {
		t.Fatalf("config=%#v err=%v", cfg, err)
	}
}

func TestLoadRejectsPostgresDSNFileWhileDisabled(t *testing.T) {
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-postgres-dsn")
	if _, err := Load(""); err == nil {
		t.Fatal("disabled PostgreSQL accepted a dangling DSN file")
	}
}

func TestLoadRejectsRetiredAttachmentProductionConfiguration(t *testing.T) {
	retired := []string{
		"PUNARO_ATTACHMENTS_ENABLED",
		"PUNARO_ATTACHMENT_ARTIFACT_STORE",
		"PUNARO_ATTACHMENT_CONTROLLER_JOURNAL",
		"PUNARO_ATTACHMENT_DEVICE_KEYS_JSON",
		"PUNARO_ATTACHMENT_DIRECTORY_CHECKPOINT_FILE",
		"PUNARO_ATTACHMENT_HOST_CREDENTIAL_DIRECTORY",
		"PUNARO_ATTACHMENT_HOST_CREDENTIAL_NAME",
		"PUNARO_ATTACHMENT_HOST_DPAPI_FILE",
		"PUNARO_ATTACHMENT_HOST_KEY_ACCOUNT",
		"PUNARO_ATTACHMENT_HOST_KEY_SERVICE",
		"PUNARO_ATTACHMENT_MEMBERSHIP_JSON",
		"PUNARO_ATTACHMENT_OFFER_OUTBOX",
		"PUNARO_ATTACHMENT_RECIPIENT_GENERATION",
		"PUNARO_ATTACHMENT_RECIPIENT_HPKE_PRIVATE_KEY_FILE",
		"PUNARO_ATTACHMENT_RECIPIENT_ID",
		"PUNARO_ATTACHMENT_RECIPIENT_SIGNING_PRIVATE_KEY_FILE",
		"PUNARO_ATTACHMENT_RELAY_ENABLED",
		"PUNARO_ATTACHMENT_RELAY_URL",
		"PUNARO_ATTACHMENT_SENDER_GENERATION",
		"PUNARO_ATTACHMENT_SENDER_ID",
		"PUNARO_ATTACHMENT_SENDER_JOURNAL",
		"PUNARO_ATTACHMENT_SENDER_SIGNING_PRIVATE_KEY_FILE",
		"PUNARO_ATTACHMENT_V3_ENABLED",
		"PUNARO_ATTACHMENT_V3_SOURCE_STORE_FILE",
		"PUNARO_DIRECTORY_AUDIENCE",
		"PUNARO_DIRECTORY_BINARY",
		"PUNARO_DIRECTORY_ENABLED",
		"PUNARO_DIRECTORY_MANIFEST",
		"PUNARO_DIRECTORY_ROOT_KEY_ID",
		"PUNARO_DIRECTORY_ROOT_PRIVATE_KEY",
		"PUNARO_DIRECTORY_ROOT_PUBLIC_KEY",
		"PUNARO_DIRECTORY_SNAPSHOT_FILE",
		"PUNARO_PERMIT_ISSUANCE_ENABLED",
		"PUNARO_PERMIT_ISSUER_KEY_ID",
		"PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE",
		"PUNARO_PERMIT_MAX_ACTIVE",
		"PUNARO_PERMIT_MAX_BYTES",
		"PUNARO_PERMIT_MAX_CHUNKS",
		"PUNARO_PERMIT_MAX_LIFETIME_SECONDS",
		"PUNARO_PERMIT_MAX_OPERATIONS",
	}
	for _, name := range retired {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "retired")
			if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "retired") {
				t.Fatalf("retired setting error=%v", err)
			}
		})
	}
}

func TestLoadRejectsEmptyRetiredAttachmentConfiguration(t *testing.T) {
	t.Setenv("PUNARO_ATTACHMENT_RELAY_URL", "")
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("empty retired setting error = %v", err)
	}
}

func TestLoadRejectsRetiredAttachmentConfigurationFromDotEnv(t *testing.T) {
	const name = "PUNARO_ATTACHMENT_RECIPIENT_ID"
	previous, present := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv(name, previous)
		} else {
			_ = os.Unsetenv(name)
		}
	})
	path := filepath.Join(t.TempDir(), "retired.env")
	if err := os.WriteFile(path, []byte(name+"=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("dotenv retired setting error = %v", err)
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

func TestLoadRequiresCompleteTrustedAttachmentReleaseSurface(t *testing.T) {
	t.Setenv("PUNARO_TRUSTED_ATTACHMENTS_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("trusted attachments were enabled without PostgreSQL device authority")
	}
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-postgres-dsn")
	t.Setenv("PUNARO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("PUNARO_INGRESS_MODE", "internet")
	t.Setenv("PUNARO_PUBLIC_URL", "https://punaro.example")
	if _, err := Load(""); err == nil {
		t.Fatal("trusted attachments were enabled without a blob root")
	}
	t.Setenv("PUNARO_TRUSTED_ATTACHMENT_BLOB_DIR", "relative/blobs")
	if _, err := Load(""); err == nil {
		t.Fatal("trusted attachments accepted a relative blob root")
	}
	t.Setenv("PUNARO_TRUSTED_ATTACHMENT_BLOB_DIR", "/var/lib/punaro/blobs")
	cfg, err := Load("")
	if err != nil || !cfg.TrustedAttachmentsEnabled || cfg.TrustedAttachmentBlobDir != "/var/lib/punaro/blobs" {
		t.Fatalf("config=%#v err=%v", cfg, err)
	}
}

func TestLoadMemoryAPIIsDarkByDefaultAndRequiresPostgresDeviceAuthority(t *testing.T) {
	cfg, err := Load("")
	if err != nil || cfg.MemoryAPIEnabled || cfg.MemoryMutationsEnabled {
		t.Fatalf("default config=%#v err=%v", cfg, err)
	}
	t.Setenv("PUNARO_MEMORY_API_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("memory API was enabled without PostgreSQL device authority")
	}
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-app-dsn")
	t.Setenv("PUNARO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("PUNARO_INGRESS_MODE", "internet")
	t.Setenv("PUNARO_PUBLIC_URL", "https://punaro.example")
	cfg, err = Load("")
	if err != nil || !cfg.MemoryAPIEnabled {
		t.Fatalf("memory API config=%#v err=%v", cfg, err)
	}
	t.Setenv("PUNARO_MEMORY_API_ENABLED", "false")
	t.Setenv("PUNARO_MEMORY_MUTATIONS_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("memory mutations were enabled without the read API")
	}
	t.Setenv("PUNARO_MEMORY_API_ENABLED", "true")
	cfg, err = Load("")
	if err != nil || !cfg.MemoryMutationsEnabled {
		t.Fatalf("memory mutation config=%#v err=%v", cfg, err)
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

func TestLoadCredentialTransitionIsOffByDefaultAndRequiresCompletePostgresRuntime(t *testing.T) {
	config, err := Load("")
	if err != nil || config.CredentialTransitionEnabled {
		t.Fatalf("default config=%#v err=%v", config, err)
	}
	t.Setenv("PUNARO_CREDENTIAL_TRANSITION_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("credential transition was enabled without its PostgreSQL relay dependencies")
	}
	t.Setenv("PUNARO_RELAY_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_MACHINES_JSON", `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`)
	t.Setenv("PUNARO_RELAY_STORE", "postgres")
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-app-dsn")
	t.Setenv("PUNARO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("PUNARO_INGRESS_MODE", "proxy")
	t.Setenv("PUNARO_PUBLIC_URL", "https://punaro.example.test")
	config, err = Load("")
	if err != nil || !config.CredentialTransitionEnabled {
		t.Fatalf("complete transition config=%#v err=%v", config, err)
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
