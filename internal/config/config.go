// Package config loads explicit, environment-based Punaro configuration.
package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is the explicit environment-derived daemon configuration.
type Config struct {
	ListenAddr               string
	DataDir                  string
	LogLevel                 string
	AttachmentsEnabled       bool
	AttachmentDeviceKeysJSON string
	AttachmentMembershipJSON string
	DirectoryEnabled         bool
	DirectorySnapshotFile    string
	RelayEnabled             bool
	RelayMachinesJSON        string
	AccessIssuer             string
	AccessAudience           string
	AccessJWKSURL            string
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
	relayMachines := value("PUNARO_RELAY_MACHINES_JSON", "")
	accessIssuer := value("PUNARO_ACCESS_ISSUER", "")
	accessAudience := value("PUNARO_ACCESS_AUDIENCE", "")
	accessJWKSURL := value("PUNARO_ACCESS_JWKS_URL", "")
	listenAddr := value("PUNARO_LISTEN_ADDR", "127.0.0.1:8080")
	// The authenticated public relay runtime does not exist yet. Keeping even
	// the health-only draft on loopback prevents an operator from accidentally
	// creating a direct-origin path that future routes could inherit.
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
	if (accessIssuer == "") != (accessAudience == "") || (accessIssuer == "") != (accessJWKSURL == "") {
		return Config{}, fmt.Errorf("PUNARO_ACCESS_ISSUER, PUNARO_ACCESS_AUDIENCE, and PUNARO_ACCESS_JWKS_URL must be set together")
	}
	return Config{ListenAddr: listenAddr, DataDir: dataDir, LogLevel: level, AttachmentsEnabled: attachmentsEnabled, AttachmentDeviceKeysJSON: deviceKeys, AttachmentMembershipJSON: membership, DirectoryEnabled: directoryEnabled, DirectorySnapshotFile: directorySnapshotFile, RelayEnabled: relayEnabled, RelayMachinesJSON: relayMachines, AccessIssuer: accessIssuer, AccessAudience: accessAudience, AccessJWKSURL: accessJWKSURL}, nil
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
