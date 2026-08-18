package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/relay"
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
	if got, want := cfg.RelayRateLimits(), relay.DefaultRateLimitConfig(); got != want {
		t.Fatalf("unexpected default rate limits: %#v", got)
	}
	if got, want := cfg.RelayQuotaLimits(), relay.DefaultQuotaConfig(); got != want {
		t.Fatalf("unexpected default pending quota: %#v", got)
	}
}

func TestLoadAcceptsProductionComposeRuntimeConfiguration(t *testing.T) {
	for key, value := range map[string]string{
		"PUNARO_LISTEN_ADDR":         "127.0.0.1:8080",
		"PUNARO_HEALTH_LISTEN_ADDR":  "127.0.0.1:8081",
		"PUNARO_POSTGRES_ENABLED":    "true",
		"PUNARO_POSTGRES_DSN_FILE":   "/run/secrets/postgres_app_dsn",
		"PUNARO_DEVICE_AUTH_ENABLED": "true",
		"PUNARO_RELAY_ENABLED":       "false",
		"PUNARO_RELAY_STORE":         "sqlite",
		"PUNARO_INGRESS_MODE":        "proxy",
		"PUNARO_PUBLIC_URL":          "https://punaro.example",
		"PUNARO_TRUSTED_LAN_HTTP":    "false",
	} {
		t.Setenv(key, value)
	}
	if _, err := Load(""); err != nil {
		t.Fatalf("production Compose configuration rejected: %v", err)
	}
}

func TestLoadRemoteMCPTokenValidationRequiresCanonicalOAuthAuthority(t *testing.T) {
	t.Setenv("PUNARO_REMOTE_MCP_TOKEN_VALIDATION_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP token validation accepted without remote MCP metadata")
	}
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-postgres-dsn")
	t.Setenv("PUNARO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("PUNARO_INGRESS_MODE", "internet")
	t.Setenv("PUNARO_PUBLIC_URL", "https://punaro.example")
	t.Setenv("PUNARO_REMOTE_MCP_METADATA_ENABLED", "true")
	t.Setenv("PUNARO_REMOTE_MCP_RESOURCE_URL", "https://punaro.example/mcp")
	t.Setenv("PUNARO_REMOTE_MCP_AUTHORIZATION_SERVERS", "https://auth.example")
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP token validation accepted without issuer and JWKS URL")
	}
	t.Setenv("PUNARO_REMOTE_MCP_ISSUER", "https://other.example")
	t.Setenv("PUNARO_REMOTE_MCP_JWKS_URL", "https://auth.example/jwks")
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP token validation accepted an unadvertised issuer")
	}
	t.Setenv("PUNARO_REMOTE_MCP_ISSUER", "https://auth.example")
	t.Setenv("PUNARO_REMOTE_MCP_JWKS_URL", "http://auth.example/jwks")
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP token validation accepted plaintext JWKS")
	}
	t.Setenv("PUNARO_REMOTE_MCP_JWKS_URL", "https://auth.example/jwks")
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP token validation accepted without subject bindings")
	}
	t.Setenv("PUNARO_REMOTE_MCP_SUBJECT_BINDINGS_JSON", `[{"subject":"operator-1","principal_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}]`)
	cfg, err := Load("")
	if err != nil || !cfg.RemoteMCPTokenValidationEnabled || cfg.RemoteMCPIssuer != "https://auth.example" {
		t.Fatalf("config=%#v err=%v", cfg, err)
	}
	t.Setenv("PUNARO_REMOTE_MCP_SUBJECT_BINDINGS_JSON", `[{"subject":"operator-1","principal_id":"00000000-0000-0000-0000-000000000000"}]`)
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP token validation accepted a nil principal binding")
	}
	t.Setenv("PUNARO_REMOTE_MCP_SUBJECT_BINDINGS_JSON", `[{"subject":"operator-1","principal_id":"11111111-1111-4111-8111-111111111111"},{"subject":"operator-1","principal_id":"22222222-2222-4222-8222-222222222222"}]`)
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP token validation accepted duplicate subject bindings")
	}
	t.Setenv("PUNARO_REMOTE_MCP_SUBJECT_BINDINGS_JSON", `[{"subject":"operator-1","principal_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},{"subject":"operator-2","principal_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}]`)
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP token validation accepted duplicate principal bindings")
	}
	t.Setenv("PUNARO_REMOTE_MCP_SUBJECT_BINDINGS_JSON", `[{"subject":"operator-1","principal_id":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}]`)
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP token validation accepted a noncanonical principal binding UUID")
	}
	t.Setenv("PUNARO_REMOTE_MCP_SUBJECT_BINDINGS_JSON", `[{"subject":"operator-1","principal_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","principal_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}]`)
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP token validation accepted duplicate binding fields")
	}
}

func TestLoadOpenAIEmbeddingProviderRequiresCompleteSafeConfiguration(t *testing.T) {
	t.Setenv("PUNARO_MEMORY_OPENAI_EMBEDDINGS_URL", "https://embeddings.example/v1/embeddings")
	if _, err := Load(""); err == nil {
		t.Fatal("embedding endpoint accepted without credential file")
	}
	t.Setenv("PUNARO_MEMORY_OPENAI_API_KEY_FILE", "relative/key")
	if _, err := Load(""); err == nil {
		t.Fatal("embedding credential accepted a relative path")
	}
	t.Setenv("PUNARO_MEMORY_OPENAI_API_KEY_FILE", "/run/secrets/embedding-api-key")
	t.Setenv("PUNARO_MEMORY_OPENAI_EMBEDDINGS_URL", "http://embeddings.example/v1/embeddings")
	if _, err := Load(""); err == nil {
		t.Fatal("embedding endpoint accepted plaintext HTTP")
	}
	t.Setenv("PUNARO_MEMORY_OPENAI_EMBEDDINGS_URL", "https://embeddings.example/v1/embeddings?token=leak")
	if _, err := Load(""); err == nil {
		t.Fatal("embedding endpoint accepted query data")
	}
	t.Setenv("PUNARO_MEMORY_OPENAI_EMBEDDINGS_URL", "https://embeddings.example/v1/embeddings")
	if _, err := Load(""); err == nil {
		t.Fatal("embedding provider accepted without PostgreSQL")
	}
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-postgres-dsn")
	cfg, err := Load("")
	if err != nil || cfg.MemoryOpenAIEmbeddingsURL != "https://embeddings.example/v1/embeddings" || cfg.MemoryOpenAIAPIKeyFile != "/run/secrets/embedding-api-key" {
		t.Fatalf("config=%#v err=%v", cfg, err)
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

func TestLoadAcceptsSignedRelayOnExplicitTrustedLANDeviceIngress(t *testing.T) {
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-app-dsn")
	t.Setenv("PUNARO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("PUNARO_INGRESS_MODE", "lan")
	t.Setenv("PUNARO_LISTEN_ADDR", "192.168.50.4:8080")
	t.Setenv("PUNARO_TRUSTED_LAN_CIDR", "192.168.50.0/24")
	t.Setenv("PUNARO_TRUSTED_LAN_HTTP", "true")
	t.Setenv("PUNARO_RELAY_ENABLED", "true")
	t.Setenv("PUNARO_RELAY_MACHINES_JSON", `[{"id":"machine-a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/a/"]}]`)
	t.Setenv("PUNARO_RELAY_STORE", "postgres")
	config, err := Load("")
	if err != nil || !config.RelayEnabled || config.RelayStore != "postgres" || config.IngressMode != "lan" {
		t.Fatalf("trusted-LAN relay config=%#v err=%v", config, err)
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

func TestLoadRemoteMCPMetadataIsDarkByDefaultAndRequiresCanonicalOAuthAuthority(t *testing.T) {
	cfg, err := Load("")
	if err != nil || cfg.RemoteMCPMetadataEnabled {
		t.Fatalf("default config=%#v err=%v", cfg, err)
	}
	t.Setenv("PUNARO_REMOTE_MCP_METADATA_ENABLED", "true")
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP metadata was enabled without its authority configuration")
	}
	t.Setenv("PUNARO_POSTGRES_ENABLED", "true")
	t.Setenv("PUNARO_POSTGRES_DSN_FILE", "/run/secrets/punaro-app-dsn")
	t.Setenv("PUNARO_DEVICE_AUTH_ENABLED", "true")
	t.Setenv("PUNARO_INGRESS_MODE", "internet")
	t.Setenv("PUNARO_PUBLIC_URL", "https://punaro.example")
	t.Setenv("PUNARO_REMOTE_MCP_RESOURCE_URL", "https://punaro.example/mcp")
	t.Setenv("PUNARO_REMOTE_MCP_AUTHORIZATION_SERVERS", "https://auth.example")
	cfg, err = Load("")
	if err != nil || !cfg.RemoteMCPMetadataEnabled || cfg.RemoteMCPResourceURL != "https://punaro.example/mcp" || cfg.RemoteMCPAuthorizationServers != "https://auth.example" {
		t.Fatalf("remote MCP config=%#v err=%v", cfg, err)
	}
	t.Setenv("PUNARO_PUBLIC_URL", "https://punaro.example/")
	cfg, err = Load("")
	if err != nil || cfg.RemoteMCPResourceURL != "https://punaro.example/mcp" {
		t.Fatalf("trailing-slash config=%#v err=%v", cfg, err)
	}
	t.Setenv("PUNARO_REMOTE_MCP_RESOURCE_URL", "http://punaro.example/mcp")
	if _, err := Load(""); err == nil {
		t.Fatal("remote MCP metadata accepted an unsafe resource URL")
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

func TestLoadRejectsInvalidRelayRateLimits(t *testing.T) {
	t.Setenv("PUNARO_RELAY_SENDER_RATE_BURST", "0")
	if _, err := Load(""); err == nil {
		t.Fatal("zero sender burst was accepted")
	}
	t.Setenv("PUNARO_RELAY_SENDER_RATE_BURST", "60")
	t.Setenv("PUNARO_RELAY_CONVERSATION_RATE_REFILL_PER_MINUTE", "10001")
	if _, err := Load(""); err == nil {
		t.Fatal("oversized conversation refill was accepted")
	}
	t.Setenv("PUNARO_RELAY_CONVERSATION_RATE_REFILL_PER_MINUTE", "120")
	t.Setenv("PUNARO_RELAY_RATE_RETRY_AFTER_MAX_SECONDS", "nope")
	if _, err := Load(""); err == nil {
		t.Fatal("non-integer retry-after cap was accepted")
	}
}

func TestLoadAcceptsExplicitRelayRateLimits(t *testing.T) {
	t.Setenv("PUNARO_RELAY_SENDER_RATE_BURST", "4")
	t.Setenv("PUNARO_RELAY_SENDER_RATE_REFILL_PER_MINUTE", "12")
	t.Setenv("PUNARO_RELAY_CONVERSATION_RATE_BURST", "8")
	t.Setenv("PUNARO_RELAY_CONVERSATION_RATE_REFILL_PER_MINUTE", "24")
	t.Setenv("PUNARO_RELAY_RATE_RETRY_AFTER_MAX_SECONDS", "9")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.RelayRateLimits()
	want := relay.RateLimitConfig{SenderBurst: 4, SenderRefillPerMinute: 12, ConversationBurst: 8, ConversationRefillPerMinute: 24, RetryAfterMaxSeconds: 9}
	if got != want {
		t.Fatalf("rate limits=%#v want %#v", got, want)
	}
}

func TestLoadRejectsInvalidRelayQuotaLimits(t *testing.T) {
	t.Setenv("PUNARO_RELAY_PENDING_RECIPIENT_COUNT", "0")
	if _, err := Load(""); err == nil {
		t.Fatal("zero pending recipient count was accepted")
	}
	t.Setenv("PUNARO_RELAY_PENDING_RECIPIENT_COUNT", "10000")
	t.Setenv("PUNARO_RELAY_PENDING_INSTALLATION_BYTES", "0")
	if _, err := Load(""); err == nil {
		t.Fatal("zero pending installation bytes were accepted")
	}
	t.Setenv("PUNARO_RELAY_PENDING_INSTALLATION_BYTES", "268435456")
	t.Setenv("PUNARO_RELAY_PENDING_RETRY_AFTER_SECONDS", "nope")
	if _, err := Load(""); err == nil {
		t.Fatal("non-integer pending retry-after was accepted")
	}
}

func TestLoadRejectsInvalidRelayRetention(t *testing.T) {
	t.Setenv("PUNARO_RELAY_PENDING_MAX_AGE_SECONDS", "0")
	if _, err := Load(""); err == nil {
		t.Fatal("zero pending max age was accepted")
	}
	t.Setenv("PUNARO_RELAY_PENDING_MAX_AGE_SECONDS", "604800")
	t.Setenv("PUNARO_RELAY_TERMINAL_RETENTION_SECONDS", "nope")
	if _, err := Load(""); err == nil {
		t.Fatal("non-integer terminal retention was accepted")
	}
}

func TestLoadAcceptsExplicitRelayRetention(t *testing.T) {
	t.Setenv("PUNARO_RELAY_PENDING_MAX_AGE_SECONDS", "90")
	t.Setenv("PUNARO_RELAY_TERMINAL_RETENTION_SECONDS", "180")
	t.Setenv("PUNARO_RELAY_DELIVERY_MAINTENANCE_BATCH", "7")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.RelayRetentionPolicy()
	want := relay.RetentionConfig{PendingMaxAgeSeconds: 90, TerminalRetentionSeconds: 180, MaintenanceBatch: 7}
	if got != want {
		t.Fatalf("retention=%#v want %#v", got, want)
	}
}

func TestLoadAcceptsExplicitRelayQuotaLimits(t *testing.T) {
	t.Setenv("PUNARO_RELAY_PENDING_RECIPIENT_COUNT", "2")
	t.Setenv("PUNARO_RELAY_PENDING_RECIPIENT_BYTES", "64")
	t.Setenv("PUNARO_RELAY_PENDING_INSTALLATION_COUNT", "8")
	t.Setenv("PUNARO_RELAY_PENDING_INSTALLATION_BYTES", "256")
	t.Setenv("PUNARO_RELAY_PENDING_RETRY_AFTER_SECONDS", "9")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.RelayQuotaLimits()
	want := relay.QuotaConfig{RecipientCount: 2, RecipientBytes: 64, InstallationCount: 8, InstallationBytes: 256, RetryAfterSeconds: 9}
	if got != want {
		t.Fatalf("quota limits=%#v want %#v", got, want)
	}
}
