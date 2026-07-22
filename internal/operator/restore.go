package operator

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
)

// RestoreOptions maps one verified installation artifact onto explicit new
// host paths. The database itself is restored separately before publication.
type RestoreOptions struct {
	Source       Installation
	Directory    string
	DataDir      string
	BackupDir    string
	OwnerDSNFile string
	AppDSNFile   string
}

// ReadInstallationArtifact strictly reads a verified backup's installation
// configuration without requiring its historical host paths to still exist.
func ReadInstallationArtifact(path string) (Installation, error) {
	body, err := os.ReadFile(path) // #nosec G304 -- explicit protected backup artifact path.
	if err != nil {
		return Installation{}, errors.New("backup installation configuration is invalid")
	}
	return ParseInstallationArtifact(body)
}

// ParseInstallationArtifact strictly parses bytes already bound to a verified
// backup manifest, avoiding a second path lookup after verification.
func ParseInstallationArtifact(body []byte) (Installation, error) {
	if len(body) == 0 || len(body) > 64<<10 {
		return Installation{}, errors.New("backup installation configuration is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var installation Installation
	err := decoder.Decode(&installation)
	var trailing any
	if err == nil {
		err = decoder.Decode(&trailing)
		if errors.Is(err, io.EOF) {
			err = nil
		}
	}
	if err != nil || installation.Version != 1 || uuid.Validate(installation.OwnerPrincipalID) != nil || !validImageDigest(installation.Image) || strings.TrimSpace(installation.OwnerName) == "" {
		return Installation{}, errors.New("backup installation configuration is invalid")
	}
	validationDirectory := filepath.Join(filepath.VolumeName(os.TempDir())+string(filepath.Separator), ".punaro-backup-source")
	validated, err := validateStatic(InitOptions{Directory: validationDirectory, DataDir: installation.DataDir, BackupDir: installation.BackupDir, Image: installation.Image, OwnerDSNFile: installation.OwnerDSNFile, AppDSNFile: installation.AppDSNFile, OwnerName: installation.OwnerName, Ingress: installation.Ingress, HealthListenAddr: installation.HealthListenAddr, MemoryAPIEnabled: installation.MemoryAPIEnabled})
	if err != nil || validated.HealthURL != installation.HealthURL {
		return Installation{}, errors.New("backup installation configuration is invalid")
	}
	return installation, nil
}

// PrepareRestore validates every target before the database restore begins and
// performs no filesystem mutation.
func PrepareRestore(options RestoreOptions) (Installation, error) {
	if options.Source.Version != 1 || uuid.Validate(options.Source.OwnerPrincipalID) != nil || !validImageDigest(options.Source.Image) || strings.TrimSpace(options.Source.OwnerName) == "" {
		return Installation{}, errors.New("restore source installation is invalid")
	}
	for _, path := range []string{options.Directory, options.DataDir, options.BackupDir, options.OwnerDSNFile, options.AppDSNFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || !safeEnvPath(path) {
			return Installation{}, errors.New("restore paths must be absolute, canonical, and single-line")
		}
	}
	_, directoryErr := os.Lstat(options.Directory)
	if directoryErr != nil && !errors.Is(directoryErr, os.ErrNotExist) {
		return Installation{}, errors.New("restore installation target is unsafe")
	}
	if requireTrustedDirectoryAncestors(filepath.Dir(options.Directory)) != nil || requireTrustedDirectoryAncestors(filepath.Dir(options.DataDir)) != nil || requireTrustedPrivateDirectory(options.BackupDir) != nil {
		return Installation{}, errors.New("restore target ancestors or backup directory are unsafe")
	}
	if requireTrustedProtectedFile(options.OwnerDSNFile, 64<<10) != nil || requireTrustedProtectedFile(options.AppDSNFile, 64<<10) != nil {
		return Installation{}, errors.New("restore database credentials are unavailable or unsafe")
	}
	if _, err := punaropostgres.ReadDSNFile(options.OwnerDSNFile); err != nil {
		return Installation{}, errors.New("restore owner database credential is invalid")
	}
	if _, err := punaropostgres.ReadDSNFile(options.AppDSNFile); err != nil {
		return Installation{}, errors.New("restore application database credential is invalid")
	}
	ownerInfo, ownerErr := os.Stat(options.OwnerDSNFile)
	appInfo, appErr := os.Stat(options.AppDSNFile)
	if ownerErr != nil || appErr != nil || os.SameFile(ownerInfo, appInfo) {
		return Installation{}, errors.New("restore database credentials must be distinct")
	}
	plannedDirectory, err := canonicalPlannedPath(options.Directory)
	if err != nil {
		return Installation{}, errors.New("restore installation target is invalid")
	}
	plannedData, err := canonicalPlannedPath(options.DataDir)
	if err != nil {
		return Installation{}, errors.New("restore data target is invalid")
	}
	canonicalBackup, err := filepath.EvalSymlinks(options.BackupDir)
	if err != nil || pathOverlap(plannedData, canonicalBackup) || pathOverlap(plannedData, plannedDirectory) {
		return Installation{}, errors.New("restore data, backup, and operator paths must not overlap")
	}
	for _, protectedPath := range []string{options.OwnerDSNFile, options.AppDSNFile} {
		canonical, canonicalErr := filepath.EvalSymlinks(protectedPath)
		if canonicalErr != nil || pathOverlap(plannedData, canonical) {
			return Installation{}, errors.New("restore data must not contain credentials")
		}
	}
	uid, gid, err := runtimeIdentity()
	if err != nil {
		return Installation{}, err
	}
	installation, err := validateStatic(InitOptions{Directory: options.Directory, DataDir: options.DataDir, BackupDir: options.BackupDir, Image: options.Source.Image, OwnerDSNFile: options.OwnerDSNFile, AppDSNFile: options.AppDSNFile, OwnerName: options.Source.OwnerName, Ingress: options.Source.Ingress, HealthListenAddr: options.Source.HealthListenAddr, MemoryAPIEnabled: options.Source.MemoryAPIEnabled})
	if err != nil {
		return Installation{}, err
	}
	installation.OwnerPrincipalID = options.Source.OwnerPrincipalID
	installation.RuntimeUID = uid
	installation.RuntimeGID = gid
	if directoryErr == nil {
		existing, loadErr := Load(options.Directory)
		if loadErr != nil || existing != installation {
			return Installation{}, errors.New("restore installation target belongs to a different request")
		}
		return existing, nil
	}
	return installation, nil
}

// PublishRestore atomically publishes generated configuration after verified
// database/timeline/blob restore has created the new data directory.
func PublishRestore(installation Installation) error {
	if uuid.Validate(installation.OwnerPrincipalID) != nil || requireTrustedPrivateDirectory(installation.DataDir) != nil || requireTrustedPrivateDirectory(installation.BackupDir) != nil || requireTrustedProtectedFile(installation.OwnerDSNFile, 64<<10) != nil || requireTrustedProtectedFile(installation.AppDSNFile, 64<<10) != nil {
		return errors.New("restored installation inputs are unavailable or unsafe")
	}
	if existing, err := Load(installation.Directory); err == nil {
		if existing == installation {
			return nil
		}
		return errors.New("restored installation target belongs to a different request")
	}
	stage := filepath.Join(filepath.Dir(installation.Directory), "."+filepath.Base(installation.Directory)+".restore-"+installation.OwnerPrincipalID+".pending")
	if _, err := os.Lstat(installation.Directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("restored installation target must be new")
	}
	if err := os.RemoveAll(stage); err != nil || os.Mkdir(stage, 0o700) != nil {
		return errors.New("restored installation staging cannot be reserved")
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(stage)
		}
	}()
	if requireTrustedPrivateDirectory(stage) != nil || writeExclusive(EnvFile(stage), []byte(daemonEnv(installation))) != nil || writeExclusive(OverrideFile(stage), []byte(composeOverride())) != nil || writeExclusiveJSON(filepath.Join(stage, configName), installation) != nil {
		return errors.New("restored installation configuration could not be staged")
	}
	if syncDirectory(stage) != nil || os.Rename(stage, installation.Directory) != nil || syncDirectory(filepath.Dir(installation.Directory)) != nil {
		return errors.New("restored installation configuration durability failed")
	}
	published = true
	return nil
}

func canonicalPlannedPath(path string) (string, error) {
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func pathOverlap(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	if first == second {
		return true
	}
	relative, err := filepath.Rel(first, second)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	relative, err = filepath.Rel(second, first)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
