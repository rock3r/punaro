// Package config loads explicit, environment-based Punaro configuration.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rock3r/punaro/internal/listener"

	"github.com/rock3r/punaro/internal/ingress"
)

// Config is the explicit environment-derived daemon configuration.
type Config struct {
	ListenAddr                  string
	HealthListenAddr            string
	DataDir                     string
	LogLevel                    string
	RelayEnabled                bool
	RelayMachinesJSON           string
	RelayStore                  string
	AccessIssuer                string
	AccessAudience              string
	AccessJWKSURL               string
	AccessJWKSFile              string
	PostgresEnabled             bool
	PostgresDSNFile             string
	DeviceAuthEnabled           bool
	MemoryAPIEnabled            bool
	MemoryMutationsEnabled      bool
	TrustedAttachmentsEnabled   bool
	TrustedAttachmentBlobDir    string
	CredentialTransitionEnabled bool
	IngressMode                 string
	PublicURL                   string
	TrustedLANCIDR              string
	TrustedLANHTTP              bool
}

// Load reads configuration and optionally loads an explicitly named dotenv file.
func Load(explicitEnvFile string) (Config, error) {
	envFile := explicitEnvFile
	if envFile == "" {
		envFile = os.Getenv("PUNARO_ENV_FILE")
	}
	if envFile != "" {
		if err := loadDotEnv(envFile); err != nil {
			return Config{}, err
		}
	}
	if err := rejectRetiredAttachmentConfiguration(); err != nil {
		return Config{}, err
	}
	level, err := parseLogLevel(value("PUNARO_LOG_LEVEL", "info"))
	if err != nil {
		return Config{}, err
	}
	dataDir := value("PUNARO_DATA_DIR", "./data")
	if !filepath.IsAbs(dataDir) {
		absolute, err := filepath.Abs(dataDir)
		if err != nil {
			return Config{}, fmt.Errorf("resolve PUNARO_DATA_DIR: %w", err)
		}
		dataDir = absolute
	}
	relayEnabled, err := strconv.ParseBool(value("PUNARO_RELAY_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_RELAY_ENABLED: %w", err)
	}
	relayMachines := value("PUNARO_RELAY_MACHINES_JSON", "")
	relayStore := strings.ToLower(value("PUNARO_RELAY_STORE", "sqlite"))
	accessIssuer := value("PUNARO_ACCESS_ISSUER", "")
	accessAudience := value("PUNARO_ACCESS_AUDIENCE", "")
	accessJWKSURL := value("PUNARO_ACCESS_JWKS_URL", "")
	accessJWKSFile := value("PUNARO_ACCESS_JWKS_FILE", "")
	postgresEnabled, err := strconv.ParseBool(value("PUNARO_POSTGRES_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_POSTGRES_ENABLED: %w", err)
	}
	postgresDSNFile := value("PUNARO_POSTGRES_DSN_FILE", "")
	deviceAuthEnabled, err := strconv.ParseBool(value("PUNARO_DEVICE_AUTH_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_DEVICE_AUTH_ENABLED: %w", err)
	}
	memoryAPIEnabled, err := strconv.ParseBool(value("PUNARO_MEMORY_API_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_MEMORY_API_ENABLED: %w", err)
	}
	memoryMutationsEnabled, err := strconv.ParseBool(value("PUNARO_MEMORY_MUTATIONS_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_MEMORY_MUTATIONS_ENABLED: %w", err)
	}
	trustedAttachmentsEnabled, err := strconv.ParseBool(value("PUNARO_TRUSTED_ATTACHMENTS_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_TRUSTED_ATTACHMENTS_ENABLED: %w", err)
	}
	trustedAttachmentBlobDir := value("PUNARO_TRUSTED_ATTACHMENT_BLOB_DIR", "")
	credentialTransitionEnabled, err := strconv.ParseBool(value("PUNARO_CREDENTIAL_TRANSITION_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_CREDENTIAL_TRANSITION_ENABLED: %w", err)
	}
	ingressMode := value("PUNARO_INGRESS_MODE", "")
	publicURL := value("PUNARO_PUBLIC_URL", "")
	trustedLANCIDR := value("PUNARO_TRUSTED_LAN_CIDR", "")
	trustedLANHTTP, err := strconv.ParseBool(value("PUNARO_TRUSTED_LAN_HTTP", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_TRUSTED_LAN_HTTP: %w", err)
	}
	listenAddr := value("PUNARO_LISTEN_ADDR", "127.0.0.1:8080")
	healthListenAddr := value("PUNARO_HEALTH_LISTEN_ADDR", "127.0.0.1:8081")
	if !listener.IsLoopback(healthListenAddr) || listener.Same(listenAddr, healthListenAddr) {
		return Config{}, fmt.Errorf("PUNARO_HEALTH_LISTEN_ADDR must be a distinct concrete loopback address")
	}
	// The legacy relay origin stays loopback-only. A non-loopback listener is
	// admitted only when the complete device-ingress policy is validated below
	// and no legacy route can share that listener.
	if !listener.IsLoopback(listenAddr) && (!deviceAuthEnabled || relayEnabled) {
		return Config{}, fmt.Errorf("PUNARO_LISTEN_ADDR must be a loopback address until the authenticated public runtime is released")
	}
	if deviceAuthEnabled {
		if !postgresEnabled {
			return Config{}, fmt.Errorf("device authentication requires PUNARO_POSTGRES_ENABLED")
		}
		policy := ingress.Policy{Mode: ingress.Mode(ingressMode), ListenAddr: listenAddr, PublicURL: publicURL, TrustedLAN: trustedLANCIDR, AllowPlaintext: trustedLANHTTP}
		if err := policy.Validate(); err != nil {
			return Config{}, fmt.Errorf("device ingress policy: %w", err)
		}
	} else if ingressMode != "" || publicURL != "" || trustedLANCIDR != "" || trustedLANHTTP {
		return Config{}, fmt.Errorf("ingress policy requires PUNARO_DEVICE_AUTH_ENABLED")
	}
	if trustedAttachmentsEnabled {
		if !postgresEnabled || !deviceAuthEnabled {
			return Config{}, fmt.Errorf("trusted attachments require PostgreSQL device authentication")
		}
		if trustedAttachmentBlobDir == "" || !filepath.IsAbs(trustedAttachmentBlobDir) || filepath.Clean(trustedAttachmentBlobDir) != trustedAttachmentBlobDir {
			return Config{}, fmt.Errorf("trusted attachments require an absolute clean PUNARO_TRUSTED_ATTACHMENT_BLOB_DIR")
		}
	} else if trustedAttachmentBlobDir != "" {
		return Config{}, fmt.Errorf("PUNARO_TRUSTED_ATTACHMENT_BLOB_DIR requires PUNARO_TRUSTED_ATTACHMENTS_ENABLED")
	}
	if memoryAPIEnabled && (!postgresEnabled || !deviceAuthEnabled) {
		return Config{}, fmt.Errorf("memory API requires PostgreSQL device authentication")
	}
	if memoryMutationsEnabled && !memoryAPIEnabled {
		return Config{}, fmt.Errorf("memory mutations require PUNARO_MEMORY_API_ENABLED")
	}
	if relayEnabled && relayMachines == "" {
		return Config{}, fmt.Errorf("enabled relay requires PUNARO_RELAY_MACHINES_JSON")
	}
	if relayStore != "sqlite" && relayStore != "postgres" {
		return Config{}, fmt.Errorf("PUNARO_RELAY_STORE must be sqlite or postgres")
	}
	if relayStore == "postgres" && (!relayEnabled || !postgresEnabled) {
		return Config{}, fmt.Errorf("PostgreSQL relay store requires PUNARO_RELAY_ENABLED and PUNARO_POSTGRES_ENABLED")
	}
	if credentialTransitionEnabled && (!relayEnabled || relayStore != "postgres" || !postgresEnabled || !deviceAuthEnabled) {
		return Config{}, fmt.Errorf("credential transition requires enabled PostgreSQL relay and device authentication")
	}
	if (accessIssuer == "") != (accessAudience == "") || (accessIssuer == "") != (accessJWKSURL == "" && accessJWKSFile == "") || (accessJWKSURL != "" && accessJWKSFile != "") {
		return Config{}, fmt.Errorf("PUNARO_ACCESS_ISSUER and PUNARO_ACCESS_AUDIENCE require exactly one of PUNARO_ACCESS_JWKS_URL or PUNARO_ACCESS_JWKS_FILE")
	}
	if accessJWKSFile != "" && !filepath.IsAbs(accessJWKSFile) {
		return Config{}, fmt.Errorf("PUNARO_ACCESS_JWKS_FILE must be absolute")
	}
	if postgresEnabled && (postgresDSNFile == "" || !filepath.IsAbs(postgresDSNFile)) {
		return Config{}, fmt.Errorf("enabled PostgreSQL requires an absolute PUNARO_POSTGRES_DSN_FILE")
	}
	if !postgresEnabled && postgresDSNFile != "" {
		return Config{}, fmt.Errorf("PUNARO_POSTGRES_DSN_FILE requires PUNARO_POSTGRES_ENABLED")
	}
	return Config{ListenAddr: listenAddr, HealthListenAddr: healthListenAddr, DataDir: dataDir, LogLevel: level, RelayEnabled: relayEnabled, RelayMachinesJSON: relayMachines, RelayStore: relayStore, AccessIssuer: accessIssuer, AccessAudience: accessAudience, AccessJWKSURL: accessJWKSURL, AccessJWKSFile: accessJWKSFile, PostgresEnabled: postgresEnabled, PostgresDSNFile: postgresDSNFile, DeviceAuthEnabled: deviceAuthEnabled, MemoryAPIEnabled: memoryAPIEnabled, MemoryMutationsEnabled: memoryMutationsEnabled, TrustedAttachmentsEnabled: trustedAttachmentsEnabled, TrustedAttachmentBlobDir: trustedAttachmentBlobDir, CredentialTransitionEnabled: credentialTransitionEnabled, IngressMode: ingressMode, PublicURL: publicURL, TrustedLANCIDR: trustedLANCIDR, TrustedLANHTTP: trustedLANHTTP}, nil
}

func rejectRetiredAttachmentConfiguration() error {
	for _, name := range []string{
		"PUNARO_ATTACHMENTS_ENABLED", "PUNARO_ATTACHMENT_RELAY_ENABLED",
		"PUNARO_ATTACHMENT_DEVICE_KEYS_JSON", "PUNARO_ATTACHMENT_MEMBERSHIP_JSON",
		"PUNARO_ATTACHMENT_V3_ENABLED", "PUNARO_ATTACHMENT_V3_SOURCE_STORE_FILE",
		"PUNARO_ATTACHMENT_RELAY_URL", "PUNARO_ATTACHMENT_DIRECTORY_CHECKPOINT_FILE",
		"PUNARO_ATTACHMENT_CONTROLLER_JOURNAL", "PUNARO_ATTACHMENT_ARTIFACT_STORE", "PUNARO_ATTACHMENT_OFFER_OUTBOX",
		"PUNARO_ATTACHMENT_RECIPIENT_ID", "PUNARO_ATTACHMENT_RECIPIENT_GENERATION",
		"PUNARO_ATTACHMENT_RECIPIENT_SIGNING_PRIVATE_KEY_FILE", "PUNARO_ATTACHMENT_RECIPIENT_HPKE_PRIVATE_KEY_FILE",
		"PUNARO_ATTACHMENT_SENDER_ID", "PUNARO_ATTACHMENT_SENDER_GENERATION",
		"PUNARO_ATTACHMENT_SENDER_JOURNAL", "PUNARO_ATTACHMENT_SENDER_SIGNING_PRIVATE_KEY_FILE",
		"PUNARO_ATTACHMENT_HOST_KEY_SERVICE", "PUNARO_ATTACHMENT_HOST_KEY_ACCOUNT",
		"PUNARO_ATTACHMENT_HOST_CREDENTIAL_DIRECTORY", "PUNARO_ATTACHMENT_HOST_CREDENTIAL_NAME", "PUNARO_ATTACHMENT_HOST_DPAPI_FILE",
		"PUNARO_DIRECTORY_ENABLED", "PUNARO_DIRECTORY_SNAPSHOT_FILE",
		"PUNARO_DIRECTORY_AUDIENCE", "PUNARO_DIRECTORY_ROOT_KEY_ID", "PUNARO_DIRECTORY_ROOT_PUBLIC_KEY",
		"PUNARO_DIRECTORY_ROOT_PRIVATE_KEY", "PUNARO_DIRECTORY_BINARY", "PUNARO_DIRECTORY_MANIFEST",
		"PUNARO_PERMIT_ISSUANCE_ENABLED", "PUNARO_PERMIT_ISSUER_KEY_ID", "PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE",
		"PUNARO_PERMIT_MAX_LIFETIME_SECONDS", "PUNARO_PERMIT_MAX_BYTES", "PUNARO_PERMIT_MAX_CHUNKS",
		"PUNARO_PERMIT_MAX_OPERATIONS", "PUNARO_PERMIT_MAX_ACTIVE",
	} {
		if _, present := os.LookupEnv(name); present {
			return fmt.Errorf("%s is retired; remove legacy attachment v2/v3 configuration and use PUNARO_TRUSTED_ATTACHMENTS_ENABLED", name)
		}
	}
	return nil
}

func value(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}
func parseLogLevel(raw string) (string, error) {
	switch strings.ToLower(raw) {
	case "debug", "info", "warn", "error":
		return strings.ToLower(raw), nil
	default:
		return "", fmt.Errorf("invalid PUNARO_LOG_LEVEL %q", raw)
	}
}

// loadDotEnv supports the deliberately small KEY=VALUE subset needed for local
// development. Existing process variables win over dotenv values.
func loadDotEnv(path string) error {
	// #nosec G304,G703 -- the operator explicitly chooses this local dotenv
	// path via CLI or PUNARO_ENV_FILE; it is never derived from remote input.
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read dotenv file: %w", err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		key, v, found := strings.Cut(raw, "=")
		key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
		if !found || key == "" || strings.ContainsAny(key, " \t") {
			return fmt.Errorf("parse dotenv file line %d", line)
		}
		if _, present := os.LookupEnv(key); !present {
			if err := os.Setenv(key, strings.Trim(strings.TrimSpace(v), "\"'")); err != nil {
				return fmt.Errorf("set dotenv value line %d: %w", line, err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan dotenv file: %w", err)
	}
	return nil
}
