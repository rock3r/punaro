// Package operator implements host-local Punaro installation workflows.
package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/rock3r/punaro/internal/ingress"
	"github.com/rock3r/punaro/internal/listener"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

const (
	configName              = "installation.json"
	pendingName             = ".installation.pending.json"
	envName                 = "punarod.env"
	overrideName            = "compose.operator.yaml"
	defaultHealthListenAddr = "127.0.0.1:8081"
)

// EnvFile returns the generated daemon dotenv path for one installation.
func EnvFile(directory string) string { return filepath.Join(directory, envName) }

// ConfigFile returns the final published installation marker path.
func ConfigFile(directory string) string { return filepath.Join(directory, configName) }

// OverrideFile returns the generated immutable-image Compose file.
func OverrideFile(directory string) string { return filepath.Join(directory, overrideName) }

// ComposeProjectName returns the stable, installation-specific Docker Compose
// project name derived from the persisted and database-verified owner identity.
func ComposeProjectName(installation Installation) (string, error) {
	ownerID, err := uuid.Parse(installation.OwnerPrincipalID)
	if err != nil {
		return "", errors.New("installation owner identity is invalid")
	}
	return "punaro-" + strings.ReplaceAll(ownerID.String(), "-", ""), nil
}

// Installation is the content-free operator configuration. DSN values remain
// in separately protected files and are never copied here.
type Installation struct {
	Version          int                     `json:"version"`
	Directory        string                  `json:"-"`
	DataDir          string                  `json:"data_dir"`
	BackupDir        string                  `json:"backup_dir"`
	Image            string                  `json:"image"`
	OwnerDSNFile     string                  `json:"owner_dsn_file"`
	AppDSNFile       string                  `json:"app_dsn_file"`
	OwnerPrincipalID string                  `json:"owner_principal_id"`
	OwnerName        string                  `json:"owner_name"`
	RuntimeUID       string                  `json:"runtime_uid"`
	RuntimeGID       string                  `json:"runtime_gid"`
	Ingress          ingress.Policy          `json:"ingress"`
	HealthListenAddr string                  `json:"health_listen_addr"`
	HealthURL        string                  `json:"health_url"`
	MailCutover      *MailCutoverPublication `json:"mail_cutover,omitempty"`
}

// InitOptions is the complete explicit input to a first installation.
type InitOptions struct {
	Directory        string
	DataDir          string
	BackupDir        string
	Image            string
	OwnerDSNFile     string
	AppDSNFile       string
	OwnerName        string
	Ingress          ingress.Policy
	HealthListenAddr string
}

// BootstrapOwner is the only database mutation performed by Init.
type BootstrapOwner func(context.Context, string, string) (punaropostgres.Principal, error)

// RecoverOwner resolves or creates the exact owner during a resumed init.
type RecoverOwner func(context.Context, Installation) (punaropostgres.Principal, error)

// ErrBootstrapNotAttempted tells Init that validation refused before any
// database mutation, so its private stage may be removed safely.
var ErrBootstrapNotAttempted = errors.New("owner bootstrap was not attempted")

// Init reserves a new installation directory, prepares every generated file,
// bootstraps ownership, and publishes installation.json as the final marker.
func Init(ctx context.Context, options InitOptions, bootstrap BootstrapOwner) (Installation, error) {
	installation, err := validateInit(options)
	if err != nil {
		return Installation{}, err
	}
	if bootstrap == nil {
		return Installation{}, errors.New("owner bootstrap is unavailable")
	}
	if err := os.Mkdir(options.Directory, 0o700); err != nil {
		return Installation{}, errors.New("installation directory must be new")
	}
	if err := requireTrustedPrivateDirectory(options.Directory); err != nil {
		_ = os.Remove(options.Directory)
		return Installation{}, errors.New("installation directory must have trusted ancestors")
	}
	preserveStage := false
	defer func() {
		if !preserveStage {
			_ = os.Remove(filepath.Join(options.Directory, pendingName))
			_ = os.Remove(filepath.Join(options.Directory, envName))
			_ = os.Remove(filepath.Join(options.Directory, overrideName))
			_ = os.Remove(options.Directory)
		}
	}()
	if err := writeExclusiveJSON(filepath.Join(options.Directory, pendingName), installation); err != nil {
		return Installation{}, errors.New("generated configuration could not be staged")
	}
	if err := writeExclusive(filepath.Join(options.Directory, envName), []byte(daemonEnv(installation))); err != nil {
		return Installation{}, errors.New("generated daemon environment could not be staged")
	}
	if err := writeExclusive(filepath.Join(options.Directory, overrideName), []byte(composeOverride())); err != nil {
		return Installation{}, errors.New("generated Compose override could not be staged")
	}
	if err := syncDirectory(options.Directory); err != nil || syncDirectory(filepath.Dir(options.Directory)) != nil {
		return Installation{}, errors.New("generated configuration staging could not be made durable")
	}
	preserveStage = true
	owner, err := bootstrap(ctx, options.OwnerDSNFile, options.OwnerName)
	if err != nil {
		if errors.Is(err, ErrBootstrapNotAttempted) {
			preserveStage = false
			return Installation{}, errors.New("fresh initialization requires a pristine database")
		}
		return Installation{}, errors.New("first operator outcome is uncertain; rerun punaro init --resume for this directory")
	}
	if uuid.Validate(owner.ID) != nil {
		return Installation{}, errors.New("first operator was created; rerun punaro init --resume for this directory")
	}
	installation.OwnerPrincipalID = owner.ID
	finalPending := filepath.Join(options.Directory, ".installation.final.json")
	if err := writeExclusiveJSON(finalPending, installation); err != nil {
		return Installation{}, errors.New("first operator was created; rerun punaro init --resume for this directory")
	}
	if err := os.Rename(finalPending, filepath.Join(options.Directory, configName)); err != nil {
		return Installation{}, errors.New("first operator was created; rerun punaro init --resume for this directory")
	}
	if err := syncDirectory(options.Directory); err != nil {
		return Installation{}, errors.New("configuration was published but durability verification failed")
	}
	_ = os.Remove(filepath.Join(options.Directory, pendingName))
	if err := syncDirectory(options.Directory); err != nil {
		return Installation{}, errors.New("configuration was published but staging cleanup durability failed")
	}
	return installation, nil
}

// Resume completes an initialization whose durable staging directory survived
// an uncertain database outcome or post-bootstrap publication failure.
func Resume(ctx context.Context, directory string, recoverOwner RecoverOwner) (Installation, error) {
	if recoverOwner == nil || !filepath.IsAbs(directory) {
		return Installation{}, errors.New("initialization recovery input is invalid")
	}
	if installation, err := Load(directory); err == nil {
		_ = os.Remove(filepath.Join(directory, pendingName))
		_ = os.Remove(filepath.Join(directory, ".installation.final.json"))
		if err := syncDirectory(directory); err != nil {
			return Installation{}, errors.New("published initialization staging cleanup failed")
		}
		return installation, nil
	}
	if err := requireTrustedPrivateDirectory(directory); err != nil {
		return Installation{}, errors.New("initialization staging directory is unavailable or unsafe")
	}
	pendingPath := filepath.Join(directory, pendingName)
	installation, err := readInstallation(pendingPath)
	if err != nil || installation.Version != 1 || installation.OwnerPrincipalID != "" || !numericIdentity(installation.RuntimeUID) || !numericIdentity(installation.RuntimeGID) || !runtimeIdentityMatches(installation) {
		return Installation{}, errors.New("initialization staging configuration is corrupt")
	}
	installation.Directory = directory
	if _, err := validateStatic(InitOptions{Directory: directory, DataDir: installation.DataDir, BackupDir: installation.BackupDir, Image: installation.Image, OwnerDSNFile: installation.OwnerDSNFile, AppDSNFile: installation.AppDSNFile, OwnerName: installation.OwnerName, Ingress: installation.Ingress, HealthListenAddr: installation.HealthListenAddr}); err != nil {
		return Installation{}, errors.New("initialization staging configuration is invalid")
	}
	if failures := CheckPaths(installation); len(failures) != 0 {
		return Installation{}, fmt.Errorf("initialization recovery refused: %s", strings.Join(failures, ", "))
	}
	owner, err := recoverOwner(ctx, installation)
	if err != nil || uuid.Validate(owner.ID) != nil || owner.DisplayName != installation.OwnerName {
		return Installation{}, errors.New("installation owner could not be recovered safely")
	}
	installation.OwnerPrincipalID = owner.ID
	finalPending := filepath.Join(directory, ".installation.final.json")
	if err := os.Remove(finalPending); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Installation{}, errors.New("initialization publication staging could not be reset")
	}
	if err := writeExclusiveJSON(finalPending, installation); err != nil || os.Rename(finalPending, filepath.Join(directory, configName)) != nil {
		return Installation{}, errors.New("installation owner was recovered; rerun punaro init --resume")
	}
	if err := syncDirectory(directory); err != nil {
		return Installation{}, errors.New("configuration was published but durability verification failed")
	}
	_ = os.Remove(pendingPath)
	if err := syncDirectory(directory); err != nil {
		return Installation{}, errors.New("configuration was published but staging cleanup durability failed")
	}
	return installation, nil
}

func validateInit(options InitOptions) (Installation, error) {
	installation, err := validateStatic(options)
	if err != nil {
		return Installation{}, err
	}
	if err := requireTrustedDirectoryAncestors(filepath.Dir(options.Directory)); err != nil {
		return Installation{}, errors.New("installation parent path is unavailable or unsafe")
	}
	if err := requireTrustedPrivateDirectory(options.DataDir); err != nil {
		return Installation{}, fmt.Errorf("data directory: %w", err)
	}
	if err := requireTrustedPrivateDirectory(options.BackupDir); err != nil {
		return Installation{}, fmt.Errorf("backup directory: %w", err)
	}
	dataInfo, dataErr := os.Stat(options.DataDir)
	backupInfo, backupErr := os.Stat(options.BackupDir)
	overlaps, overlapErr := canonicalDirectoriesOverlap(options.DataDir, options.BackupDir)
	if dataErr != nil || backupErr != nil || overlapErr != nil || os.SameFile(dataInfo, backupInfo) || overlaps {
		return Installation{}, errors.New("data and backup directories must be separate non-overlapping locations")
	}
	if err := requireTrustedProtectedFile(options.OwnerDSNFile, 64<<10); err != nil {
		return Installation{}, fmt.Errorf("owner DSN file: %w", err)
	}
	if _, err := punaropostgres.ReadDSNFile(options.OwnerDSNFile); err != nil {
		return Installation{}, fmt.Errorf("owner DSN file: %w", err)
	}
	if err := requireTrustedProtectedFile(options.AppDSNFile, 64<<10); err != nil {
		return Installation{}, fmt.Errorf("application DSN file: %w", err)
	}
	if _, err := punaropostgres.ReadDSNFile(options.AppDSNFile); err != nil {
		return Installation{}, fmt.Errorf("application DSN file: %w", err)
	}
	daemonOverlap, daemonOverlapErr := daemonWritableOverlap(options.DataDir, options.Directory, options.OwnerDSNFile, options.AppDSNFile, false)
	if daemonOverlapErr != nil || daemonOverlap {
		return Installation{}, errors.New("daemon-writable data directory must not contain database credentials or operator state")
	}
	ownerInfo, ownerErr := os.Stat(options.OwnerDSNFile)
	appInfo, appErr := os.Stat(options.AppDSNFile)
	if ownerErr != nil || appErr != nil || os.SameFile(ownerInfo, appInfo) {
		return Installation{}, errors.New("owner and application DSN files must be distinct")
	}
	uid, gid, err := runtimeIdentity()
	if err != nil {
		return Installation{}, err
	}
	installation.RuntimeUID = uid
	installation.RuntimeGID = gid
	return installation, nil
}

func validateStatic(options InitOptions) (Installation, error) {
	for _, path := range []string{options.Directory, options.DataDir, options.BackupDir, options.OwnerDSNFile, options.AppDSNFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !safeEnvPath(path) {
			return Installation{}, errors.New("installation paths must be absolute, canonical, and single-line")
		}
	}
	if filepath.Clean(options.DataDir) == filepath.Clean(options.BackupDir) || strings.TrimSpace(options.OwnerName) == "" || strings.ContainsAny(options.OwnerName, "\r\n") {
		return Installation{}, errors.New("data, backup, and owner inputs are invalid")
	}
	if !validImageDigest(options.Image) {
		return Installation{}, errors.New("image must be an explicit repository reference pinned by sha256 digest")
	}
	for _, value := range []string{options.Ingress.ListenAddr, options.Ingress.PublicURL, options.Ingress.TrustedLAN} {
		if strings.ContainsAny(value, " \t\r\n#$'\"\\") {
			return Installation{}, errors.New("ingress values contain characters unsafe for generated configuration")
		}
	}
	policy := options.Ingress
	if err := policy.Validate(); err != nil {
		return Installation{}, err
	}
	healthListenAddr := options.HealthListenAddr
	if healthListenAddr == "" {
		healthListenAddr = defaultHealthListenAddr
	}
	if !listener.IsLoopback(healthListenAddr) || listener.Same(policy.ListenAddr, healthListenAddr) {
		return Installation{}, errors.New("health listener must be a distinct concrete loopback address")
	}
	return Installation{Version: 1, Directory: options.Directory, DataDir: options.DataDir, BackupDir: options.BackupDir, Image: options.Image, OwnerDSNFile: options.OwnerDSNFile, AppDSNFile: options.AppDSNFile, OwnerName: options.OwnerName, Ingress: policy, HealthListenAddr: healthListenAddr, HealthURL: localURL(healthListenAddr)}, nil
}

// Load reads only a completely published installation marker.
func Load(directory string) (Installation, error) {
	if !filepath.IsAbs(directory) {
		return Installation{}, errors.New("installation directory must be absolute")
	}
	if err := requireTrustedPrivateDirectory(directory); err != nil {
		return Installation{}, errors.New("installation directory is unavailable")
	}
	path := filepath.Join(directory, configName)
	if err := requireTrustedProtectedFile(path, 64<<10); err != nil {
		return Installation{}, errors.New("published installation configuration is unavailable or unsafe")
	}
	installation, err := readInstallation(path)
	if err != nil {
		return Installation{}, errors.New("published installation configuration is corrupt")
	}
	if installation.Version != 1 || uuid.Validate(installation.OwnerPrincipalID) != nil || !numericIdentity(installation.RuntimeUID) || !numericIdentity(installation.RuntimeGID) || !runtimeIdentityMatches(installation) {
		return Installation{}, errors.New("published installation configuration is corrupt")
	}
	if installation.MailCutover != nil && installation.MailCutover.Validate() != nil {
		return Installation{}, errors.New("published installation mail cutover is invalid")
	}
	validated, err := validateStatic(InitOptions{Directory: directory, DataDir: installation.DataDir, BackupDir: installation.BackupDir, Image: installation.Image, OwnerDSNFile: installation.OwnerDSNFile, AppDSNFile: installation.AppDSNFile, OwnerName: installation.OwnerName, Ingress: installation.Ingress, HealthListenAddr: installation.HealthListenAddr})
	if err != nil {
		return Installation{}, errors.New("published installation configuration is invalid")
	}
	if installation.HealthListenAddr != validated.HealthListenAddr || installation.HealthURL != validated.HealthURL {
		return Installation{}, errors.New("published installation health URL is invalid")
	}
	installation.Directory = directory
	return installation, nil
}

func readInstallation(path string) (Installation, error) {
	if err := requireTrustedProtectedFile(path, 64<<10); err != nil {
		return Installation{}, err
	}
	file, err := os.Open(path) // #nosec G304 -- fixed file below an explicit private installation directory.
	if err != nil {
		return Installation{}, err
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	var installation Installation
	if err := decoder.Decode(&installation); err != nil {
		return Installation{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Installation{}, err
	}
	return installation, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func writeExclusiveJSON(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return writeExclusive(path, body)
}

func writeExclusive(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- validated installation-local output.
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return errors.New("must be an existing non-symlink directory inaccessible to group and other")
	}
	return nil
}

func requireProtectedFile(path string, maximum int64) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return errors.New("must be a regular file inaccessible to group and other")
	}
	return nil
}

// CheckPaths returns actionable, content-free failures for installation paths.
func CheckPaths(installation Installation) []string {
	var failures []string
	if err := requireTrustedPrivateDirectory(installation.Directory); err != nil {
		failures = append(failures, "installation directory unavailable or unsafe")
	}
	if err := requireTrustedPrivateDirectory(installation.DataDir); err != nil {
		failures = append(failures, "data directory unavailable or unsafe")
	}
	if err := requireTrustedPrivateDirectory(installation.BackupDir); err != nil {
		failures = append(failures, "backup directory unavailable or unsafe")
	}
	if overlaps, err := canonicalDirectoriesOverlap(installation.DataDir, installation.BackupDir); err == nil && overlaps {
		failures = append(failures, "data and backup directories overlap")
	}
	if err := requireTrustedProtectedFile(installation.OwnerDSNFile, 64<<10); err != nil {
		failures = append(failures, "owner DSN file unavailable or unsafe")
	} else if _, err := punaropostgres.ReadDSNFile(installation.OwnerDSNFile); err != nil {
		failures = append(failures, "owner DSN file unavailable or unsafe")
	}
	if err := requireTrustedProtectedFile(installation.AppDSNFile, 64<<10); err != nil {
		failures = append(failures, "application DSN file unavailable or unsafe")
	} else if _, err := punaropostgres.ReadDSNFile(installation.AppDSNFile); err != nil {
		failures = append(failures, "application DSN file unavailable or unsafe")
	}
	if overlaps, err := daemonWritableOverlap(installation.DataDir, installation.Directory, installation.OwnerDSNFile, installation.AppDSNFile, true); err == nil && overlaps {
		failures = append(failures, "daemon-writable data directory overlaps database credentials or operator state")
	}
	envPath := EnvFile(installation.Directory)
	if err := requireTrustedProtectedFile(envPath, 64<<10); err != nil {
		failures = append(failures, "generated daemon environment unavailable or unsafe")
	} else {
		// #nosec G304 -- fixed generated file below the explicit validated installation directory.
		body, err := os.ReadFile(envPath)
		if err != nil || string(body) != daemonEnv(installation) {
			failures = append(failures, "generated daemon environment does not match installation configuration")
		}
	}
	overridePath := OverrideFile(installation.Directory)
	if err := requireTrustedProtectedFile(overridePath, 64<<10); err != nil {
		failures = append(failures, "generated Compose override unavailable or unsafe")
	} else {
		// #nosec G304 -- fixed generated file below the explicit validated installation directory.
		body, err := os.ReadFile(overridePath)
		if err != nil || string(body) != composeOverride() {
			failures = append(failures, "generated Compose override does not match installation configuration")
		}
	}
	return failures
}

func syncDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- explicit validated installation directory.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func localURL(listenAddr string) string {
	return (&url.URL{Scheme: "http", Host: listenAddr}).String()
}

func daemonEnv(installation Installation) string {
	relayStore, credentialTransition := "sqlite", "false"
	if installation.MailCutover != nil {
		relayStore, credentialTransition = "postgres", "true"
	}
	return strings.Join([]string{
		"PUNARO_IMAGE=" + installation.Image,
		"PUNARO_HOST_DATA_DIR=" + installation.DataDir,
		"PUNARO_DATA_DIR=/var/lib/punaro",
		"PUNARO_LISTEN_ADDR=" + installation.Ingress.ListenAddr,
		"PUNARO_HEALTH_LISTEN_ADDR=" + installation.HealthListenAddr,
		"PUNARO_POSTGRES_ENABLED=true",
		"PUNARO_POSTGRES_DSN_FILE=" + installation.AppDSNFile,
		"PUNARO_DEVICE_AUTH_ENABLED=true",
		"PUNARO_RELAY_STORE=" + relayStore,
		"PUNARO_CREDENTIAL_TRANSITION_ENABLED=" + credentialTransition,
		"PUNARO_INGRESS_MODE=" + string(installation.Ingress.Mode),
		"PUNARO_PUBLIC_URL=" + installation.Ingress.PublicURL,
		"PUNARO_TRUSTED_LAN_CIDR=" + installation.Ingress.TrustedLAN,
		fmt.Sprintf("PUNARO_TRUSTED_LAN_HTTP=%t", installation.Ingress.AllowPlaintext),
		"PUNARO_RUNTIME_UID=" + installation.RuntimeUID,
		"PUNARO_RUNTIME_GID=" + installation.RuntimeGID,
	}, "\n") + "\n"
}

func composeOverride() string {
	return `services:
  punarod:
    image: ${PUNARO_IMAGE:?required}
    init: true
    network_mode: host
    user: ${PUNARO_RUNTIME_UID:?required}:${PUNARO_RUNTIME_GID:?required}
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:mode=1777,noexec,nosuid,nodev
    restart: unless-stopped
    environment:
      PUNARO_DATA_DIR: /var/lib/punaro
      PUNARO_LISTEN_ADDR: ${PUNARO_LISTEN_ADDR:?required}
      PUNARO_HEALTH_LISTEN_ADDR: ${PUNARO_HEALTH_LISTEN_ADDR:?required}
      PUNARO_POSTGRES_ENABLED: ${PUNARO_POSTGRES_ENABLED:?required}
      PUNARO_POSTGRES_DSN_FILE: ${PUNARO_POSTGRES_DSN_FILE:?required}
      PUNARO_DEVICE_AUTH_ENABLED: ${PUNARO_DEVICE_AUTH_ENABLED:?required}
      PUNARO_RELAY_STORE: ${PUNARO_RELAY_STORE:?required}
      PUNARO_CREDENTIAL_TRANSITION_ENABLED: ${PUNARO_CREDENTIAL_TRANSITION_ENABLED:?required}
      PUNARO_INGRESS_MODE: ${PUNARO_INGRESS_MODE:?required}
      PUNARO_PUBLIC_URL: ${PUNARO_PUBLIC_URL:-}
      PUNARO_TRUSTED_LAN_CIDR: ${PUNARO_TRUSTED_LAN_CIDR:-}
      PUNARO_TRUSTED_LAN_HTTP: ${PUNARO_TRUSTED_LAN_HTTP:?required}
    volumes:
      - type: bind
        source: ${PUNARO_HOST_DATA_DIR:?required}
        target: /var/lib/punaro
      - type: bind
        source: ${PUNARO_POSTGRES_DSN_FILE:?required}
        target: ${PUNARO_POSTGRES_DSN_FILE:?required}
        read_only: true
`
}

func numericIdentity(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 32)
	return err == nil && parsed > 0 && strconv.FormatUint(parsed, 10) == value
}

func safeEnvPath(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("/._-+@", char) {
			continue
		}
		return false
	}
	return true
}

func nestedPath(parent, child string) bool {
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func canonicalDirectoriesOverlap(first, second string) (bool, error) {
	canonicalFirst, err := filepath.EvalSymlinks(first)
	if err != nil {
		return false, err
	}
	canonicalSecond, err := filepath.EvalSymlinks(second)
	if err != nil {
		return false, err
	}
	return filepath.Clean(canonicalFirst) == filepath.Clean(canonicalSecond) || nestedPath(canonicalFirst, canonicalSecond) || nestedPath(canonicalSecond, canonicalFirst), nil
}

func daemonWritableOverlap(dataDir, directory, ownerDSNFile, appDSNFile string, directoryExists bool) (bool, error) {
	canonicalData, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return false, err
	}
	canonicalDirectory := ""
	if directoryExists {
		canonicalDirectory, err = filepath.EvalSymlinks(directory)
	} else {
		var canonicalParent string
		canonicalParent, err = filepath.EvalSymlinks(filepath.Dir(filepath.Clean(directory)))
		canonicalDirectory = filepath.Join(canonicalParent, filepath.Base(filepath.Clean(directory)))
	}
	if err != nil {
		return false, err
	}
	canonicalOwner, err := filepath.EvalSymlinks(ownerDSNFile)
	if err != nil {
		return false, err
	}
	canonicalApp, err := filepath.EvalSymlinks(appDSNFile)
	if err != nil {
		return false, err
	}
	for _, protectedPath := range []string{canonicalDirectory, canonicalOwner, canonicalApp} {
		if filepath.Clean(canonicalData) == filepath.Clean(protectedPath) || nestedPath(canonicalData, protectedPath) {
			return true, nil
		}
	}
	return false, nil
}

func validImageDigest(value string) bool {
	repository, digest, found := strings.Cut(value, "@sha256:")
	if !found || !imageRepositoryPattern.MatchString(repository) || len(digest) != 64 {
		return false
	}
	for _, char := range digest {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

var imageRepositoryPattern = regexp.MustCompile(`^(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?))*(?::[0-9]+)?/)?[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)

// UpAction is the only allowed pre-start transition for one schema state.
type UpAction string

const (
	// StartCompatible permits startup without changing the schema.
	StartCompatible UpAction = "start_compatible"
	// RefuseUpgradeRequired keeps this staged release from migrating in place.
	RefuseUpgradeRequired UpAction = "refuse_upgrade_required"
	// RefuseAndRecover directs the operator to documented recovery.
	RefuseAndRecover UpAction = "refuse_and_recover"
)

// DecideUp ensures ordinary startup never upgrades an existing schema.
func DecideUp(state punaropostgres.SchemaState) UpAction {
	switch state.Classification {
	case punaropostgres.Compatible:
		return StartCompatible
	case punaropostgres.UpgradeRequired:
		return RefuseUpgradeRequired
	default:
		return RefuseAndRecover
	}
}
