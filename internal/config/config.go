// Package config loads explicit, environment-based Punaro configuration.
package config

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is the explicit environment-derived daemon configuration.
type Config struct {
	ListenAddr                 string
	DataDir                    string
	LogLevel                   string
	AttachmentsEnabled         bool
	AttachmentDeviceKeysJSON   string
	AttachmentMembershipJSON   string
	DirectoryEnabled           bool
	DirectorySnapshotFile      string
	PermitIssuanceEnabled      bool
	DirectoryAudience          [32]byte
	DirectoryRootKeyID         [32]byte
	DirectoryRootPublicKey     ed25519.PublicKey
	PermitIssuerKeyID          [32]byte
	PermitIssuerPrivateKeyFile string
	PermitMaxLifetimeSeconds   uint64
	PermitMaxBytes             uint64
	PermitMaxChunks            uint64
	PermitMaxOperations        uint64
	PermitMaxActive            uint64
	RelayEnabled               bool
	RelayMachinesJSON          string
	AccessIssuer               string
	AccessAudience             string
	AccessJWKSURL              string
	AccessJWKSFile             string
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
	attachmentsEnabled, err := strconv.ParseBool(value("PUNARO_ATTACHMENTS_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_ATTACHMENTS_ENABLED: %w", err)
	}
	relayEnabled, err := strconv.ParseBool(value("PUNARO_RELAY_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_RELAY_ENABLED: %w", err)
	}
	deviceKeys := value("PUNARO_ATTACHMENT_DEVICE_KEYS_JSON", "")
	membership := value("PUNARO_ATTACHMENT_MEMBERSHIP_JSON", "")
	directoryEnabled, err := strconv.ParseBool(value("PUNARO_DIRECTORY_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_DIRECTORY_ENABLED: %w", err)
	}
	directorySnapshotFile := value("PUNARO_DIRECTORY_SNAPSHOT_FILE", "")
	permitIssuanceEnabled, err := strconv.ParseBool(value("PUNARO_PERMIT_ISSUANCE_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_PERMIT_ISSUANCE_ENABLED: %w", err)
	}
	directoryAudience := value("PUNARO_DIRECTORY_AUDIENCE", "")
	directoryRootKeyID := value("PUNARO_DIRECTORY_ROOT_KEY_ID", "")
	directoryRootPublicKey := value("PUNARO_DIRECTORY_ROOT_PUBLIC_KEY", "")
	permitIssuerKeyID := value("PUNARO_PERMIT_ISSUER_KEY_ID", "")
	permitIssuerPrivateKeyFile := value("PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE", "")
	permitMaxLifetimeSeconds := value("PUNARO_PERMIT_MAX_LIFETIME_SECONDS", "")
	permitMaxBytes := value("PUNARO_PERMIT_MAX_BYTES", "")
	permitMaxChunks := value("PUNARO_PERMIT_MAX_CHUNKS", "")
	permitMaxOperations := value("PUNARO_PERMIT_MAX_OPERATIONS", "")
	permitMaxActive := value("PUNARO_PERMIT_MAX_ACTIVE", "")
	relayMachines := value("PUNARO_RELAY_MACHINES_JSON", "")
	accessIssuer := value("PUNARO_ACCESS_ISSUER", "")
	accessAudience := value("PUNARO_ACCESS_AUDIENCE", "")
	accessJWKSURL := value("PUNARO_ACCESS_JWKS_URL", "")
	accessJWKSFile := value("PUNARO_ACCESS_JWKS_FILE", "")
	listenAddr := value("PUNARO_LISTEN_ADDR", "127.0.0.1:8080")
	// The relay origin stays loopback-only even when Cloudflare Access protects
	// the public hostname. This prevents an operator from accidentally creating
	// a direct-origin path that could bypass the Access and tunnel boundary.
	if !isLoopbackListener(listenAddr) {
		return Config{}, fmt.Errorf("PUNARO_LISTEN_ADDR must be a loopback address until the authenticated public runtime is released")
	}
	if attachmentsEnabled && (deviceKeys == "" || membership == "") {
		return Config{}, fmt.Errorf("attachments require PUNARO_ATTACHMENT_DEVICE_KEYS_JSON and PUNARO_ATTACHMENT_MEMBERSHIP_JSON")
	}
	if relayEnabled && relayMachines == "" {
		return Config{}, fmt.Errorf("enabled relay requires PUNARO_RELAY_MACHINES_JSON")
	}
	if directoryEnabled && !relayEnabled {
		return Config{}, fmt.Errorf("directory service requires PUNARO_RELAY_ENABLED")
	}
	if directoryEnabled && (directorySnapshotFile == "" || !filepath.IsAbs(directorySnapshotFile)) {
		return Config{}, fmt.Errorf("directory service requires an absolute PUNARO_DIRECTORY_SNAPSHOT_FILE")
	}
	var audience, rootKeyID, issuerKeyID [32]byte
	var rootPublicKey ed25519.PublicKey
	var maxLifetime, maxBytes, maxChunks, maxOperations, maxActive uint64
	if permitIssuanceEnabled {
		if !directoryEnabled {
			return Config{}, fmt.Errorf("permit issuance requires PUNARO_DIRECTORY_ENABLED")
		}
		var decodeErr error
		if audience, decodeErr = decodeFixedBase64URL("PUNARO_DIRECTORY_AUDIENCE", directoryAudience, 32); decodeErr != nil {
			return Config{}, decodeErr
		}
		if rootKeyID, decodeErr = decodeFixedBase64URL("PUNARO_DIRECTORY_ROOT_KEY_ID", directoryRootKeyID, 32); decodeErr != nil {
			return Config{}, decodeErr
		}
		var rootRaw [32]byte
		if rootRaw, decodeErr = decodeFixedBase64URL("PUNARO_DIRECTORY_ROOT_PUBLIC_KEY", directoryRootPublicKey, ed25519.PublicKeySize); decodeErr != nil {
			return Config{}, decodeErr
		}
		rootPublicKey = append(ed25519.PublicKey(nil), rootRaw[:]...)
		if issuerKeyID, decodeErr = decodeFixedBase64URL("PUNARO_PERMIT_ISSUER_KEY_ID", permitIssuerKeyID, 32); decodeErr != nil {
			return Config{}, decodeErr
		}
		if permitIssuerPrivateKeyFile == "" || !filepath.IsAbs(permitIssuerPrivateKeyFile) {
			return Config{}, fmt.Errorf("permit issuance requires an absolute PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE")
		}
		if maxLifetime, decodeErr = parsePositiveUint64("PUNARO_PERMIT_MAX_LIFETIME_SECONDS", permitMaxLifetimeSeconds, 60); decodeErr != nil {
			return Config{}, decodeErr
		}
		if maxBytes, decodeErr = parsePositiveUint64("PUNARO_PERMIT_MAX_BYTES", permitMaxBytes, 64<<20); decodeErr != nil {
			return Config{}, decodeErr
		}
		if maxChunks, decodeErr = parsePositiveUint64("PUNARO_PERMIT_MAX_CHUNKS", permitMaxChunks, 4096); decodeErr != nil {
			return Config{}, decodeErr
		}
		if maxOperations, decodeErr = parsePositiveUint64("PUNARO_PERMIT_MAX_OPERATIONS", permitMaxOperations, 4096); decodeErr != nil {
			return Config{}, decodeErr
		}
		if maxActive, decodeErr = parsePositiveUint64("PUNARO_PERMIT_MAX_ACTIVE", permitMaxActive, 4096); decodeErr != nil {
			return Config{}, decodeErr
		}
	}
	attachmentRelayEnabled, err := strconv.ParseBool(value("PUNARO_ATTACHMENT_RELAY_ENABLED", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("parse PUNARO_ATTACHMENT_RELAY_ENABLED: %w", err)
	}
	if attachmentRelayEnabled {
		return Config{}, fmt.Errorf("PUNARO_ATTACHMENT_RELAY_ENABLED is withheld until attachment v2 release gates are complete")
	}
	if (accessIssuer == "") != (accessAudience == "") || (accessIssuer == "") != (accessJWKSURL == "" && accessJWKSFile == "") || (accessJWKSURL != "" && accessJWKSFile != "") {
		return Config{}, fmt.Errorf("PUNARO_ACCESS_ISSUER and PUNARO_ACCESS_AUDIENCE require exactly one of PUNARO_ACCESS_JWKS_URL or PUNARO_ACCESS_JWKS_FILE")
	}
	if accessJWKSFile != "" && !filepath.IsAbs(accessJWKSFile) {
		return Config{}, fmt.Errorf("PUNARO_ACCESS_JWKS_FILE must be absolute")
	}
	return Config{ListenAddr: listenAddr, DataDir: dataDir, LogLevel: level, AttachmentsEnabled: attachmentsEnabled, AttachmentDeviceKeysJSON: deviceKeys, AttachmentMembershipJSON: membership, DirectoryEnabled: directoryEnabled, DirectorySnapshotFile: directorySnapshotFile, PermitIssuanceEnabled: permitIssuanceEnabled, DirectoryAudience: audience, DirectoryRootKeyID: rootKeyID, DirectoryRootPublicKey: rootPublicKey, PermitIssuerKeyID: issuerKeyID, PermitIssuerPrivateKeyFile: permitIssuerPrivateKeyFile, PermitMaxLifetimeSeconds: maxLifetime, PermitMaxBytes: maxBytes, PermitMaxChunks: maxChunks, PermitMaxOperations: maxOperations, PermitMaxActive: maxActive, RelayEnabled: relayEnabled, RelayMachinesJSON: relayMachines, AccessIssuer: accessIssuer, AccessAudience: accessAudience, AccessJWKSURL: accessJWKSURL, AccessJWKSFile: accessJWKSFile}, nil
}

func decodeFixedBase64URL(name, value string, size int) ([32]byte, error) {
	var result [32]byte
	if value == "" || size != len(result) {
		return result, fmt.Errorf("%s must be canonical base64url %d-byte material", name, size)
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != size || base64.RawURLEncoding.EncodeToString(raw) != value {
		return result, fmt.Errorf("%s must be canonical base64url %d-byte material", name, size)
	}
	copy(result[:], raw)
	return result, nil
}

func parsePositiveUint64(name, value string, maximum uint64) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 || parsed > maximum {
		return 0, fmt.Errorf("%s must be an integer from 1 to %d", name, maximum)
	}
	return parsed, nil
}

func isLoopbackListener(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
