package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/adapter"
	punarobackup "github.com/rock3r/punaro/internal/backup"
	"github.com/rock3r/punaro/internal/clienttransport"
	"github.com/rock3r/punaro/internal/incrementalfs"
	"github.com/rock3r/punaro/internal/listener"
	"github.com/rock3r/punaro/internal/operator"
	punaropostgres "github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
	punarorelease "github.com/rock3r/punaro/internal/release"
)

const (
	serverDoctorTimeout        = 15 * time.Second
	serverDoctorCommandTimeout = 3 * time.Second
	serverDoctorOutputLimit    = 4 << 10
	serverDoctorMinimumFree    = 512 << 20
	serverDoctorBackupFresh    = 24 * time.Hour
)

type boundedServerDoctorOutput struct {
	buffer   strings.Builder
	maximum  int
	overflow bool
}

type serverDoctorCredentialContextKey struct{}

type serverDoctorCredentials struct {
	values map[string]string
}

var serverDoctorDSNRead = isolatedServerDoctorDSN

type serverDoctorPathRequest struct {
	Directory    string                `json:"directory"`
	Installation operator.Installation `json:"installation"`
}

type serverDoctorBackupState struct {
	Available knownDoctorBool `json:"available"`
	Fresh     knownDoctorBool `json:"fresh"`
}

type serverDoctorProfilePayload struct {
	RelayURL       string `json:"relay_url"`
	MachineID      string `json:"machine_id"`
	SigningKey     string `json:"signing_key"`
	AccessID       string `json:"access_id"`
	AccessMaterial string `json:"access_material"`
}

type serverDoctorRecoveryReceiptRequest struct {
	Directory      string `json:"directory"`
	ExpectAbsent   bool   `json:"expect_absent"`
	UpdateID       string `json:"update_id,omitempty"`
	BackupID       string `json:"backup_id,omitempty"`
	TargetRelease  string `json:"target_release,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
}

var (
	serverDoctorPathCheck                 = isolatedServerDoctorPaths
	serverDoctorPathExecutable            = os.Executable
	serverDoctorStorageCheck              = isolatedServerDoctorStorage
	serverDoctorStorageExecutable         = os.Executable
	serverDoctorBackupCheck               = isolatedServerDoctorBackups
	serverDoctorBackupExecutable          = os.Executable
	serverDoctorUpdateStageCheck          = isolatedServerDoctorUpdateStage
	serverDoctorUpdateStageExecutable     = os.Executable
	serverDoctorProfileLoad               = isolatedServerDoctorProfile
	serverDoctorProfileExecutable         = os.Executable
	serverDoctorRecoveryReceiptCheck      = isolatedServerDoctorRecoveryReceipt
	serverDoctorRecoveryReceiptExecutable = os.Executable
)

func isolatedServerDoctorProfile(ctx context.Context, path string) (serverDoctorProfile, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return serverDoctorProfile{}, errors.New("server doctor profile unavailable")
	}
	executable, err := serverDoctorProfileExecutable()
	if err != nil {
		return serverDoctorProfile{}, errors.New("server doctor profile unavailable")
	}
	output, ok := boundedCommandLimit(ctx, 16<<10, executable, "doctor-relay-profile-check", "--path", path)
	if !ok {
		return serverDoctorProfile{}, errors.New("server doctor profile unavailable")
	}
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.DisallowUnknownFields()
	var payload serverDoctorProfilePayload
	if decoder.Decode(&payload) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return serverDoctorProfile{}, errors.New("server doctor profile unavailable")
	}
	key, err := base64.RawURLEncoding.DecodeString(payload.SigningKey)
	if err != nil || len(key) != ed25519.PrivateKeySize || payload.RelayURL == "" || payload.MachineID == "" || payload.AccessID == "" || payload.AccessMaterial == "" {
		return serverDoctorProfile{}, errors.New("server doctor profile unavailable")
	}
	return serverDoctorProfile{RelayURL: payload.RelayURL, MachineID: payload.MachineID, PrivateKey: ed25519.PrivateKey(key), AccessToken: adapter.AccessServiceToken{ClientID: payload.AccessID, ClientSecret: payload.AccessMaterial}}, nil
}

func runDoctorRelayProfileCheck(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro doctor-relay-profile-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("path", "", "protected relay doctor profile")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" || !filepath.IsAbs(*path) || filepath.Clean(*path) != *path {
		return 2
	}
	profile, err := loadServerDoctorProfile(context.Background(), *path)
	if err != nil {
		return 1
	}
	payload := serverDoctorProfilePayload{RelayURL: profile.RelayURL, MachineID: profile.MachineID, SigningKey: base64.RawURLEncoding.EncodeToString(profile.PrivateKey), AccessID: profile.AccessToken.ClientID, AccessMaterial: profile.AccessToken.ClientSecret}
	if json.NewEncoder(stdout).Encode(payload) != nil {
		return 1
	}
	return 0
}

func encodeServerDoctorRecoveryReceiptRequest(request serverDoctorRecoveryReceiptRequest) (string, bool) {
	body, err := json.Marshal(request)
	if err != nil || len(body) == 0 || len(body) > 8<<10 {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(body), true
}

func isolatedServerDoctorRecoveryReceipt(ctx context.Context, request serverDoctorRecoveryReceiptRequest) knownDoctorBool {
	encoded, ok := encodeServerDoctorRecoveryReceiptRequest(request)
	if !ok {
		return knownDoctorBool{}
	}
	executable, err := serverDoctorRecoveryReceiptExecutable()
	if err != nil {
		return knownDoctorBool{}
	}
	output, ok := boundedCommandLimit(ctx, 256, executable, "doctor-recovery-receipt-check", "--request", encoded)
	if !ok {
		return knownDoctorBool{}
	}
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.DisallowUnknownFields()
	var state knownDoctorBool
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || !state.Known {
		return knownDoctorBool{}
	}
	return state
}

func runDoctorRecoveryReceiptCheck(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro doctor-recovery-receipt-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	raw := flags.String("request", "", "bounded recovery receipt request")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *raw == "" || len(*raw) > base64.RawURLEncoding.EncodedLen(8<<10) {
		return 2
	}
	body, err := base64.RawURLEncoding.DecodeString(*raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != *raw || len(body) == 0 || len(body) > 8<<10 {
		return 2
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var request serverDoctorRecoveryReceiptRequest
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.Directory == "" || !filepath.IsAbs(request.Directory) || filepath.Clean(request.Directory) != request.Directory {
		return 2
	}
	state := inspectServerDoctorRecoveryReceipt(request)
	if !state.Known || json.NewEncoder(stdout).Encode(state) != nil {
		return 1
	}
	return 0
}

func inspectServerDoctorRecoveryReceipt(request serverDoctorRecoveryReceiptRequest) knownDoctorBool {
	path := operator.UpdateRecoveryReceiptFile(request.Directory)
	if request.ExpectAbsent {
		_, err := os.Lstat(path) // #nosec G703 -- fixed installation receipt path inside deadline-killed helper.
		switch {
		case err == nil:
			return known(true, false)
		case errors.Is(err, os.ErrNotExist):
			return known(true, true)
		default:
			return knownDoctorBool{}
		}
	}
	receipt, _, err := operator.LoadUpdateRecoveryReceipt(path)
	ok := err == nil && receipt.UpdateID == request.UpdateID && receipt.BackupID == request.BackupID && receipt.TargetRelease == request.TargetRelease && receipt.ManifestSHA256 == request.ManifestSHA256
	return known(true, ok)
}

func isolatedServerDoctorUpdateStage(ctx context.Context, directory string) knownDoctorBool {
	executable, err := serverDoctorUpdateStageExecutable()
	if err != nil {
		return knownDoctorBool{}
	}
	output, ok := boundedCommandLimit(ctx, 256, executable, "doctor-update-stage-check", "--directory", directory)
	if !ok {
		return knownDoctorBool{}
	}
	decoder := json.NewDecoder(strings.NewReader(output))
	var state knownDoctorBool
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || !state.Known {
		return knownDoctorBool{}
	}
	return state
}

func directServerDoctorUpdateStage(_ context.Context, directory string) knownDoctorBool {
	return inspectServerDoctorUpdateStage(directory)
}

func inspectServerDoctorUpdateStage(directory string) knownDoctorBool {
	if _, err := operator.ExistingUpdateStage(directory); err == nil {
		return knownDoctorBool{Known: true}
	} else if errors.Is(err, operator.ErrUpdateStageNotFound) {
		return knownDoctorBool{Known: true, OK: true}
	}
	return knownDoctorBool{}
}

func runDoctorUpdateStageCheck(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro doctor-update-stage-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "installation directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *directory == "" || !filepath.IsAbs(*directory) || filepath.Clean(*directory) != *directory {
		return 2
	}
	state := inspectServerDoctorUpdateStage(*directory)
	if !state.Known || json.NewEncoder(stdout).Encode(state) != nil {
		return 1
	}
	return 0
}

func isolatedServerDoctorBackups(ctx context.Context, root string, now time.Time) (knownDoctorBool, knownDoctorBool) {
	executable, err := serverDoctorBackupExecutable()
	if err != nil {
		return knownDoctorBool{}, knownDoctorBool{}
	}
	output, ok := boundedCommandLimit(ctx, 512, executable, "doctor-backup-check", "--root", root, "--now", now.UTC().Format(time.RFC3339Nano))
	if !ok {
		return knownDoctorBool{}, knownDoctorBool{}
	}
	decoder := json.NewDecoder(strings.NewReader(output))
	var state serverDoctorBackupState
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || !state.Available.Known || !state.Fresh.Known {
		return knownDoctorBool{}, knownDoctorBool{}
	}
	return state.Available, state.Fresh
}

func directServerDoctorBackups(ctx context.Context, root string, now time.Time) (knownDoctorBool, knownDoctorBool) {
	return inspectServerBackups(ctx, root, now)
}

func runDoctorBackupCheck(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro doctor-backup-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "installation backup directory")
	rawNow := flags.String("now", "", "diagnostic observation time")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *root == "" || !filepath.IsAbs(*root) || filepath.Clean(*root) != *root || *rawNow == "" {
		return 2
	}
	now, err := time.Parse(time.RFC3339Nano, *rawNow)
	if err != nil {
		return 2
	}
	available, fresh := inspectServerBackups(context.Background(), *root, now.UTC())
	if !available.Known || !fresh.Known {
		return 1
	}
	if json.NewEncoder(stdout).Encode(serverDoctorBackupState{Available: available, Fresh: fresh}) != nil {
		return 1
	}
	return 0
}

func isolatedServerDoctorStorage(ctx context.Context, path string, minimum uint64) knownDoctorBool {
	executable, err := serverDoctorStorageExecutable()
	if err != nil {
		return knownDoctorBool{}
	}
	output, ok := boundedCommandLimit(ctx, 256, executable, "doctor-storage-check", "--path", path, "--minimum", strconv.FormatUint(minimum, 10))
	if !ok {
		return knownDoctorBool{}
	}
	decoder := json.NewDecoder(strings.NewReader(output))
	var state knownDoctorBool
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || !state.Known {
		return knownDoctorBool{}
	}
	return state
}

func directServerDoctorStorage(_ context.Context, path string, minimum uint64) knownDoctorBool {
	return inspectServerStorage(path, minimum)
}

func runDoctorStorageCheck(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro doctor-storage-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("path", "", "installation data directory")
	minimum := flags.Uint64("minimum", 0, "minimum available bytes")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" || !filepath.IsAbs(*path) || filepath.Clean(*path) != *path || *minimum == 0 {
		return 2
	}
	state := inspectServerStorage(*path, *minimum)
	if !state.Known {
		return 1
	}
	if json.NewEncoder(stdout).Encode(state) != nil {
		return 1
	}
	return 0
}

func encodeServerDoctorPathRequest(installation operator.Installation) (string, bool) {
	body, err := json.Marshal(serverDoctorPathRequest{Directory: installation.Directory, Installation: installation})
	if err != nil || len(body) == 0 || len(body) > 128<<10 {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(body), true
}

func isolatedServerDoctorPaths(ctx context.Context, installation operator.Installation) ([]string, bool) {
	request, ok := encodeServerDoctorPathRequest(installation)
	if !ok {
		return nil, false
	}
	executable, err := serverDoctorPathExecutable()
	if err != nil {
		return nil, false
	}
	output, ok := boundedCommandLimit(ctx, 16<<10, executable, "doctor-path-check", "--request", request)
	if !ok {
		return nil, false
	}
	decoder := json.NewDecoder(strings.NewReader(output))
	var failures []string
	if decoder.Decode(&failures) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(failures) > 32 {
		return nil, false
	}
	for _, failure := range failures {
		if failure == "" || len(failure) > 256 || strings.ContainsAny(failure, "\r\n\x00") {
			return nil, false
		}
	}
	return failures, true
}

func directServerDoctorPaths(_ context.Context, installation operator.Installation) ([]string, bool) {
	return operator.CheckPaths(installation), true
}

func runDoctorPathCheck(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro doctor-path-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	encoded := flags.String("request", "", "encoded content-free installation")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *encoded == "" || len(*encoded) > 192<<10 {
		return 2
	}
	body, err := base64.RawURLEncoding.DecodeString(*encoded)
	if err != nil || len(body) == 0 || len(body) > 128<<10 {
		return 2
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var request serverDoctorPathRequest
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.Directory == "" || !filepath.IsAbs(request.Directory) || filepath.Clean(request.Directory) != request.Directory {
		return 2
	}
	request.Installation.Directory = request.Directory
	if json.NewEncoder(stdout).Encode(operator.CheckPaths(request.Installation)) != nil {
		return 1
	}
	return 0
}

func withServerDoctorCredentials(ctx context.Context, installation operator.Installation) context.Context {
	credentials := serverDoctorCredentials{values: map[string]string{}}
	for _, path := range []string{installation.AppDSNFile, installation.OwnerDSNFile} {
		if _, attempted := credentials.values[path]; attempted {
			continue
		}
		dsn, ok := serverDoctorDSNRead(ctx, path)
		if ok {
			credentials.values[path] = dsn
		} else {
			credentials.values[path] = ""
		}
	}
	return context.WithValue(ctx, serverDoctorCredentialContextKey{}, credentials)
}

func serverDoctorCredential(ctx context.Context, path string) (string, bool, bool) {
	credentials, diagnostic := ctx.Value(serverDoctorCredentialContextKey{}).(serverDoctorCredentials)
	if !diagnostic {
		return "", false, false
	}
	dsn, attempted := credentials.values[path]
	return dsn, true, attempted && dsn != ""
}

func openServerDoctorApplication(ctx context.Context, path string) (*punaropostgres.Database, error) {
	if dsn, diagnostic, ok := serverDoctorCredential(ctx, path); diagnostic {
		if !ok {
			return nil, errors.New("PostgreSQL application credential is unavailable")
		}
		return punaropostgres.OpenApplicationDSN(ctx, dsn)
	}
	return punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: path})
}

func openServerDoctorAdministration(ctx context.Context, path string) (*punaropostgres.Administration, error) {
	if dsn, diagnostic, ok := serverDoctorCredential(ctx, path); diagnostic {
		if !ok {
			return nil, errors.New("PostgreSQL owner credential is unavailable")
		}
		return punaropostgres.OpenAdministrationDSN(ctx, dsn)
	}
	return punaropostgres.OpenAdministration(ctx, punaropostgres.Config{DSNFile: path})
}

func isolatedServerDoctorDSN(ctx context.Context, path string) (string, bool) {
	executable, err := os.Executable()
	if err != nil {
		return "", false
	}
	output, ok := boundedCommandLimit(ctx, 16<<10, executable, "doctor-dsn-read", "--path", path)
	if !ok || strings.TrimSpace(output) == "" {
		return "", false
	}
	return strings.TrimSpace(output), true
}

func directServerDoctorDSN(_ context.Context, path string) (string, bool) {
	dsn, err := punaropostgres.ReadDSNFile(path)
	return dsn, err == nil
}

func runDoctorDSNRead(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro doctor-dsn-read", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("path", "", "protected PostgreSQL DSN file")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	dsn, err := punaropostgres.ReadDSNFile(*path)
	if err != nil {
		return 1
	}
	_, _ = io.WriteString(stdout, dsn)
	return 0
}

func (output *boundedServerDoctorOutput) Write(value []byte) (int, error) {
	remaining := output.maximum - output.buffer.Len()
	if remaining > 0 {
		retained := value
		if len(retained) > remaining {
			retained = retained[:remaining]
		}
		_, _ = output.buffer.Write(retained)
	}
	if len(value) > remaining {
		output.overflow = true
	}
	return len(value), nil
}

func inspectServerDoctorState(parent context.Context, installation operator.Installation, machineID string, gatewayColocated bool, relayProfile string) serverDoctorState {
	ctx, cancel := context.WithTimeout(parent, serverDoctorTimeout)
	defer cancel()

	state := serverDoctorState{MachineID: validServerMachineID(machineID), Release: serverBuildRelease, Protocol: relay.ProtocolVersion, ExpectedPostgresMajor: punarorelease.ProductionPostgreSQLMajor}
	state.ReleaseSequence, _ = strconv.ParseInt(serverBuildSequence, 10, 64)
	state.CatalogSequence, _ = strconv.ParseInt(serverBuildCatalogSequence, 10, 64)
	state.InstalledRelease = inspectInstalledRelease(installation.Image)
	state.ComposeBinding = fileDigestMatches(ctx, operator.OverrideFile(installation.Directory), serverBuildComposeSHA256)
	state.MigrationBinding = known(serverBuildMigrationSHA256 != "", serverBuildMigrationSHA256 == punaropostgres.MigrationManifestSHA256())
	state.RunningImage = inspectRunningImage(ctx, installation)
	state.Storage = serverDoctorStorageCheck(ctx, installation.DataDir, serverDoctorMinimumFree)
	state.BackupAvailable, state.BackupFresh = serverDoctorBackupCheck(ctx, installation.BackupDir, time.Now().UTC())
	state.HealthPrivate = known(true, listener.IsLoopback(installation.HealthListenAddr))
	state.BlobPrivate = known(true, serverBlobTopologyPrivate(installation))
	state.TunnelRoute, state.TunnelOrigin, state.AccessAdmission, state.RelayEnrollment, state.RelayProtocol = inspectServerRelay(ctx, installation, relayProfile)
	if gatewayColocated {
		state.GatewayInstalled, state.GatewayEnabled, state.GatewayRunning, state.GatewayExecutable, state.GatewayExitStatus, state.GatewayRestartState, state.GatewayRelease = inspectGatewayService(ctx, serverBuildRelease)
	}

	database, err := openServerDoctorApplication(ctx, installation.AppDSNFile)
	if err == nil {
		private, listenerErr := database.ListenerPrivate(ctx)
		state.DatabasePrivate = known(listenerErr == nil, private)
		state.PostgresMajor, err = database.PostgreSQLMajor(ctx)
		state.PostgresKnown = err == nil
		_ = database.Close()
	}
	administration, err := openServerDoctorAdministration(ctx, installation.OwnerDSNFile)
	if err == nil {
		private, listenerErr := administration.ListenerPrivate(ctx)
		state.AdminPrivate = known(listenerErr == nil, private)
		_ = administration.Close()
	}
	state.UpdateTransaction, state.RecoveryReceipt, state.UpdateRecovery = inspectUpdateState(ctx, installation)
	return state
}

func validServerMachineID(value string) string {
	if value == "" || len(value) > 64 {
		return ""
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return ""
	}
	return value
}

func known(isKnown, ok bool) knownDoctorBool {
	return knownDoctorBool{Known: isKnown, OK: isKnown && ok}
}

func fileDigestMatches(ctx context.Context, path, expected string) knownDoctorBool {
	if len(expected) != 64 {
		return knownDoctorBool{}
	}
	if ctx.Err() != nil {
		return knownDoctorBool{}
	}
	info, err := os.Lstat(path) // #nosec G703 -- fixed generated file below the validated installation root.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return known(true, false)
	}
	digest, ok := serverDoctorFileDigest(ctx, path)
	if ctx.Err() != nil || !ok {
		return knownDoctorBool{}
	}
	return known(true, digest == expected)
}

var serverDoctorFileDigest = isolatedServerDoctorFileDigest

func isolatedServerDoctorFileDigest(ctx context.Context, path string) (string, bool) {
	executable, err := os.Executable()
	if err != nil {
		return "", false
	}
	output, ok := boundedCommand(ctx, executable, "doctor-file-digest", "--path", path)
	digest := strings.TrimSpace(output)
	if !ok || len(digest) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", false
	}
	return digest, true
}

func directServerDoctorFileDigest(_ context.Context, path string) (string, bool) {
	var output strings.Builder
	if runDoctorFileDigest([]string{"--path", path}, &output) != 0 {
		return "", false
	}
	return strings.TrimSpace(output.String()), true
}

func runDoctorFileDigest(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro doctor-file-digest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("path", "", "generated Compose file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *path == "" || !filepath.IsAbs(*path) || filepath.Clean(*path) != *path {
		return 2
	}
	expected, err := os.Lstat(*path) // #nosec G703 -- explicit fixed doctor input.
	if err != nil || !expected.Mode().IsRegular() || expected.Mode()&os.ModeSymlink != 0 || expected.Size() < 1 || expected.Size() > 1<<20 {
		return 1
	}
	file, err := os.Open(*path) // #nosec G304,G703 -- child-isolated validated doctor input.
	if err != nil {
		return 1
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) || opened.Size() != expected.Size() {
		return 1
	}
	hash := sha256.New()
	written, err := io.CopyN(hash, file, (1<<20)+1)
	if err != nil && !errors.Is(err, io.EOF) || written != opened.Size() {
		return 1
	}
	_, _ = fmt.Fprintln(stdout, hex.EncodeToString(hash.Sum(nil)))
	return 0
}

func inspectInstalledRelease(image string) knownDoctorBool {
	if serverBuildRelease == "" {
		return knownDoctorBool{}
	}
	if serverBuildImage == "" {
		return knownDoctorBool{}
	}
	return known(true, installedReleaseMatchesBuildIdentity(serverBuildImage, image, serverBuildRelease))
}

func installedReleaseMatchesBuildIdentity(expected, installed, release string) bool {
	if expected == installed {
		return strings.Contains(expected, "@sha256:")
	}
	tag := ":" + release
	if release == "" || !strings.HasSuffix(expected, tag) {
		return false
	}
	repository := strings.TrimSuffix(expected, tag)
	prefix := repository + "@sha256:"
	if repository == "" || !strings.HasPrefix(installed, prefix) || len(installed) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(installed, prefix))
	return err == nil
}

type serverDoctorContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader serverDoctorContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func inspectRunningImage(parent context.Context, installation operator.Installation) knownDoctorBool {
	project, err := operator.ComposeProjectName(installation)
	if err != nil {
		return knownDoctorBool{}
	}
	container, ok := boundedCommand(parent, "docker", "compose", "--project-name", project, "--env-file", operator.EnvFile(installation.Directory), "-f", operator.OverrideFile(installation.Directory), "ps", "--quiet", "punarod")
	if !ok || strings.TrimSpace(container) == "" || strings.Contains(strings.TrimSpace(container), "\n") {
		return known(ok, false)
	}
	image, ok := boundedCommand(parent, "docker", "inspect", "--format", "{{.Config.Image}}", strings.TrimSpace(container))
	return known(ok, strings.TrimSpace(image) == installation.Image)
}

func inspectServerBackups(ctx context.Context, root string, now time.Time) (knownDoctorBool, knownDoctorBool) {
	if ctx.Err() != nil {
		return knownDoctorBool{}, knownDoctorBool{}
	}
	backups, err := punarobackup.ListContextLimit(ctx, root, 128)
	if err != nil {
		return knownDoctorBool{}, knownDoctorBool{}
	}
	if len(backups) == 0 {
		return known(true, false), known(true, false)
	}
	latest := backups[len(backups)-1]
	age := now.Sub(latest.CreatedAt)
	return known(true, true), known(true, age >= 0 && age <= serverDoctorBackupFresh)
}

func serverBlobTopologyPrivate(installation operator.Installation) bool {
	if !installation.TrustedAttachmentsEnabled {
		return true
	}
	cleanData := filepath.Clean(installation.DataDir) + string(filepath.Separator)
	cleanBlob := filepath.Clean(installation.TrustedAttachmentBlobDir) + string(filepath.Separator)
	return strings.HasPrefix(cleanBlob, cleanData)
}

func inspectServerRelay(parent context.Context, installation operator.Installation, relayProfile string) (knownDoctorBool, knownDoctorBool, knownDoctorBool, knownDoctorBool, knownDoctorBool) {
	if installation.Ingress.PublicURL == "" && installation.Ingress.Mode == "lan" {
		passed := known(true, true)
		if installation.RelayEnabled {
			return passed, passed, passed, knownDoctorBool{}, knownDoctorBool{}
		}
		return passed, passed, passed, passed, passed
	}
	profile, err := serverDoctorProfileLoad(parent, relayProfile)
	if err != nil {
		return knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}
	}
	if strings.TrimSuffix(profile.RelayURL, "/") != strings.TrimSuffix(installation.Ingress.PublicURL, "/") {
		failed := known(true, false)
		return failed, failed, failed, knownDoctorBool{}, knownDoctorBool{}
	}
	if !installation.RelayEnabled {
		route, origin, access := inspectServerPublicEdge(parent, installation.Ingress.PublicURL, profile, &http.Client{Timeout: 5 * time.Second})
		return route, origin, access, knownDoctorBool{}, knownDoctorBool{}
	}
	client, err := adapter.NewHTTPRelayClient(profile.RelayURL, profile.MachineID, profile.PrivateKey, &http.Client{Timeout: 5 * time.Second}, profile.AccessToken)
	if err != nil {
		return knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}
	}
	result, _ := client.Doctor(parent)
	return known(true, result.Transport), known(result.Transport, result.Origin), known(result.Transport, result.Access), known(result.Origin, result.Enrolled), known(result.Enrolled, result.Protocol)
}

func inspectServerPublicEdge(ctx context.Context, publicURL string, profile serverDoctorProfile, baseClient *http.Client) (knownDoctorBool, knownDoctorBool, knownDoctorBool) {
	if strings.TrimSuffix(profile.RelayURL, "/") != strings.TrimSuffix(publicURL, "/") {
		failed := known(true, false)
		return failed, failed, failed
	}
	client, err := adapter.OpenAccessSession(ctx, profile.RelayURL, baseClient, profile.AccessToken)
	if err != nil {
		failed := known(true, false)
		return failed, failed, failed
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, strings.TrimSuffix(profile.RelayURL, "/")+"/", nil)
	if err != nil {
		failed := known(true, false)
		return failed, failed, failed
	}
	if profile.AccessToken.ClientID != "" {
		request.Header.Set("CF-Access-Client-Id", profile.AccessToken.ClientID)
		request.Header.Set("CF-Access-Client-Secret", profile.AccessToken.ClientSecret)
	}
	response, err := client.Do(request)
	if err != nil {
		return known(true, false), knownDoctorBool{}, knownDoctorBool{}
	}
	defer func() { _ = response.Body.Close() }()
	origin := serverPublicEdgeOrigin(response)
	if !origin || profile.AccessToken.ClientID == "" {
		return known(true, true), known(true, origin), known(true, origin)
	}
	negativeClient, err := adapter.OpenAccessSession(ctx, profile.RelayURL, baseClient, adapter.AccessServiceToken{})
	if err != nil {
		return known(true, true), known(true, true), knownDoctorBool{}
	}
	negativeClient.Jar = nil
	negativeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	negativeRequest, err := http.NewRequestWithContext(ctx, http.MethodHead, strings.TrimSuffix(profile.RelayURL, "/")+"/", nil)
	if err != nil {
		return known(true, true), known(true, true), knownDoctorBool{}
	}
	negativeResponse, err := negativeClient.Do(negativeRequest)
	if err != nil {
		return known(true, true), known(true, true), knownDoctorBool{}
	}
	defer func() { _ = negativeResponse.Body.Close() }()
	protected := !serverPublicEdgeOrigin(negativeResponse) && serverAccessRejectionStatus(negativeResponse.StatusCode)
	return known(true, true), known(true, true), known(true, protected)
}

func serverPublicEdgeOrigin(response *http.Response) bool {
	return response != nil && response.StatusCode == http.StatusNotFound && response.Header.Get("Cache-Control") == "no-store" && response.Header.Get("X-Content-Type-Options") == "nosniff" && response.Header.Get("X-Frame-Options") == "DENY"
}

func serverAccessRejectionStatus(status int) bool {
	return status >= http.StatusMultipleChoices && status < http.StatusBadRequest || status == http.StatusUnauthorized || status == http.StatusForbidden
}

type serverDoctorProfile struct {
	RelayURL    string
	MachineID   string
	PrivateKey  ed25519.PrivateKey
	AccessToken adapter.AccessServiceToken
}

func loadServerDoctorProfile(ctx context.Context, path string) (serverDoctorProfile, error) {
	body, err := readProtectedServerDoctorFile(ctx, path, 8<<10)
	if err != nil {
		return serverDoctorProfile{}, errors.New("server doctor profile unavailable")
	}
	return parseServerDoctorProfile(ctx, body)
}

func parseServerDoctorProfile(ctx context.Context, body []byte) (serverDoctorProfile, error) {
	values := map[string]string{}
	allowed := map[string]bool{"PUNARO_SERVER_DOCTOR_RELAY_URL": true, "PUNARO_SERVER_DOCTOR_MACHINE_ID": true, "PUNARO_SERVER_DOCTOR_PRIVATE_KEY_FILE": true, "PUNARO_SERVER_DOCTOR_ACCESS_TOKEN_FILE": true}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || value == "" || !allowed[key] || values[key] != "" || strings.ContainsAny(value, "\r\x00") {
			return serverDoctorProfile{}, errors.New("server doctor profile invalid")
		}
		values[key] = value
	}
	if len(values) != len(allowed) {
		return serverDoctorProfile{}, errors.New("server doctor profile invalid")
	}
	keyBody, err := readProtectedServerDoctorFile(ctx, values["PUNARO_SERVER_DOCTOR_PRIVATE_KEY_FILE"], 4<<10)
	if err != nil {
		return serverDoctorProfile{}, errors.New("server doctor credential unavailable")
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(keyBody)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return serverDoctorProfile{}, errors.New("server doctor credential invalid")
	}
	accessBody, err := readProtectedServerDoctorFile(ctx, values["PUNARO_SERVER_DOCTOR_ACCESS_TOKEN_FILE"], 4<<10)
	if err != nil {
		return serverDoctorProfile{}, errors.New("server doctor Access credential unavailable")
	}
	accessValues := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(accessBody)), "\n") {
		name, value, found := strings.Cut(line, "=")
		if !found || value == "" || name != "PUNARO_CF_ACCESS_CLIENT_ID" && name != "PUNARO_CF_ACCESS_CLIENT_SECRET" || accessValues[name] != "" || strings.ContainsAny(value, "\r\x00") {
			return serverDoctorProfile{}, errors.New("server doctor Access credential invalid")
		}
		accessValues[name] = value
	}
	profile := serverDoctorProfile{
		RelayURL: values["PUNARO_SERVER_DOCTOR_RELAY_URL"], MachineID: values["PUNARO_SERVER_DOCTOR_MACHINE_ID"], PrivateKey: ed25519.PrivateKey(key),
		AccessToken: adapter.AccessServiceToken{ClientID: accessValues["PUNARO_CF_ACCESS_CLIENT_ID"], ClientSecret: accessValues["PUNARO_CF_ACCESS_CLIENT_SECRET"]},
	}
	if profile.RelayURL == "" || validServerMachineID(profile.MachineID) == "" || profile.AccessToken.ClientID == "" || profile.AccessToken.ClientSecret == "" {
		return serverDoctorProfile{}, errors.New("server doctor profile invalid")
	}
	if _, err := clienttransport.ValidateOrigin(profile.RelayURL, clienttransport.Policy{}); err != nil {
		return serverDoctorProfile{}, errors.New("server doctor profile invalid")
	}
	return profile, nil
}

func writeServerDoctorProfile(path, relayURL, machineID, privateKeyFile, accessTokenFile string) error {
	for _, value := range []string{relayURL, machineID, privateKeyFile, accessTokenFile} {
		if value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("server doctor profile invalid")
		}
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("server doctor profile path invalid")
	}
	body := []byte(
		"PUNARO_SERVER_DOCTOR_RELAY_URL=" + relayURL + "\n" +
			"PUNARO_SERVER_DOCTOR_MACHINE_ID=" + machineID + "\n" +
			"PUNARO_SERVER_DOCTOR_PRIVATE_KEY_FILE=" + privateKeyFile + "\n" +
			"PUNARO_SERVER_DOCTOR_ACCESS_TOKEN_FILE=" + accessTokenFile + "\n",
	)
	ctx, cancel := context.WithTimeout(context.Background(), serverDoctorCommandTimeout)
	defer cancel()
	if _, err := parseServerDoctorProfile(ctx, body); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304,G703 -- explicit operator-owned output; O_EXCL refuses replacement and symlinks.
	if err != nil {
		return errors.New("server doctor profile create failed")
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path) // #nosec G703 -- removes only the exact O_EXCL file created above after an incomplete write.
		}
	}()
	if _, err := file.Write(body); err != nil {
		return errors.New("server doctor profile write failed")
	}
	if err := file.Sync(); err != nil {
		return errors.New("server doctor profile write failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("server doctor profile write failed")
	}
	complete = true
	return nil
}

func readProtectedServerDoctorFile(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("protected doctor file invalid")
	}
	expected, err := os.Lstat(path) // #nosec G703 -- explicit local protected diagnostic file.
	if err != nil || !expected.Mode().IsRegular() || expected.Mode()&os.ModeSymlink != 0 || expected.Size() < 1 || expected.Size() > maximum || runtime.GOOS != "windows" && expected.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("protected doctor file invalid")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- validated explicit protected file.
	if err != nil {
		return nil, errors.New("protected doctor file invalid")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) || opened.Size() < 1 || opened.Size() > maximum || runtime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("protected doctor file invalid")
	}
	body, err := io.ReadAll(io.LimitReader(serverDoctorContextReader{ctx: ctx, reader: file}, maximum+1))
	if ctx.Err() != nil || err != nil || len(body) == 0 || int64(len(body)) != opened.Size() || int64(len(body)) > maximum {
		return nil, errors.New("protected doctor file invalid")
	}
	return body, nil
}

func inspectGatewayService(parent context.Context, expectedRelease string) (knownDoctorBool, knownDoctorBool, knownDoctorBool, knownDoctorBool, knownDoctorBool, knownDoctorBool, knownDoctorBool) {
	loadState, loaded := boundedCommand(parent, "systemctl", "show", "--property=LoadState", "--value", "punaro-telegram.service")
	if !loaded {
		return knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}
	}
	installed := strings.TrimSpace(loadState) == "loaded"
	_, enabled := boundedCommand(parent, "systemctl", "is-enabled", "--quiet", "punaro-telegram.service")
	activeState, activeKnown := boundedCommand(parent, "systemctl", "show", "--property=ActiveState", "--value", "punaro-telegram.service")
	running := activeKnown && strings.TrimSpace(activeState) == "active"
	exitStatus, exitKnown := boundedCommand(parent, "systemctl", "show", "--property=ExecMainStatus", "--value", "punaro-telegram.service")
	serviceResult, resultKnown := boundedCommand(parent, "systemctl", "show", "--property=Result", "--value", "punaro-telegram.service")
	effectiveExecStart, effectiveKnown := boundedCommand(parent, "systemctl", "show", "--property=ExecStart", "--value", "punaro-telegram.service")
	executable := known(effectiveKnown, serverGatewayServiceFileBound(parent, "/etc/systemd/system/punaro-telegram.service") && serverGatewaySystemdExecStartBound(effectiveExecStart))
	release, releaseKnown := boundedCommand(parent, "/usr/local/bin/punaro-telegram", "version")
	return known(true, installed), known(true, enabled), known(activeKnown, running), executable,
		known(exitKnown, strings.TrimSpace(exitStatus) == "0"), known(resultKnown, strings.TrimSpace(serviceResult) == "success"),
		known(releaseKnown && expectedRelease != "", strings.TrimSpace(release) == expectedRelease)
}

func serverGatewayServiceFileBound(ctx context.Context, path string) bool {
	body, err := incrementalfs.ReadFile(ctx, path, 64<<10)
	if err != nil {
		return false
	}
	count := 0
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "ExecStart=/usr/local/bin/punaro-telegram" {
			count++
		}
	}
	return count == 1
}

func serverGatewaySystemdExecStartBound(body string) bool {
	if len(body) > 64<<10 {
		return false
	}
	canonical := strings.TrimSpace(body)
	if len(canonical) < 2 || canonical[0] != '{' || canonical[len(canonical)-1] != '}' || strings.Count(canonical, "{") != 1 || strings.Count(canonical, "}") != 1 || strings.ContainsAny(canonical, "\r\n\x00") {
		return false
	}
	fields := map[string]string{}
	seen := map[string]bool{}
	for _, field := range strings.Split(canonical[1:len(canonical)-1], ";") {
		name, value, found := strings.Cut(strings.TrimSpace(field), "=")
		if !found || name == "" || seen[name] {
			return false
		}
		seen[name] = true
		fields[name] = strings.TrimSpace(value)
	}
	const executable = "/usr/local/bin/punaro-telegram"
	return fields["path"] == executable && fields["argv[]"] == executable
}

func inspectUpdateState(parent context.Context, installation operator.Installation) (knownDoctorBool, knownDoctorBool, knownDoctorBool) {
	admin, err := openServerDoctorAdministration(parent, installation.OwnerDSNFile)
	if err != nil {
		return knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}
	}
	defer func() { _ = admin.Close() }()
	transaction, err := admin.LatestUpdate(parent)
	if errors.Is(err, punaropostgres.ErrNotFound) {
		return known(true, true), serverDoctorRecoveryReceiptCheck(parent, serverDoctorRecoveryReceiptRequest{Directory: installation.Directory, ExpectAbsent: true}), known(true, true)
	}
	if err != nil {
		return knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}
	}
	terminal := transaction.Phase == punaropostgres.UpdateCommitted || transaction.Phase == punaropostgres.UpdateRecovered || transaction.Phase == punaropostgres.UpdateAborted
	if transaction.Phase == punaropostgres.UpdateCommitted && serverBuildRelease != "" {
		terminal = transaction.TargetRelease == serverBuildRelease && transaction.TargetImage == installation.Image && transaction.ComposeSHA256 == serverBuildComposeSHA256 && transaction.MigrationManifestSHA256 == serverBuildMigrationSHA256
	}
	if terminal {
		return known(true, true), serverDoctorRecoveryReceiptCheck(parent, serverDoctorRecoveryReceiptRequest{Directory: installation.Directory, ExpectAbsent: true}), known(true, true)
	}
	if !updatePhaseRequiresRecoveryReceipt(transaction.Phase) {
		return known(true, false), serverDoctorRecoveryReceiptCheck(parent, serverDoctorRecoveryReceiptRequest{Directory: installation.Directory, ExpectAbsent: true}), known(true, false)
	}
	receipt := serverDoctorRecoveryReceiptRequest{Directory: installation.Directory, UpdateID: transaction.UpdateID, BackupID: transaction.BackupID, TargetRelease: transaction.TargetRelease, ManifestSHA256: transaction.BackupManifestSHA256}
	return known(true, false), serverDoctorRecoveryReceiptCheck(parent, receipt), known(true, false)
}

func updatePhaseRequiresRecoveryReceipt(phase punaropostgres.UpdatePhase) bool {
	switch phase {
	case punaropostgres.UpdateBackupVerified, punaropostgres.UpdateMigrationStarted, punaropostgres.UpdateMigrated,
		punaropostgres.UpdateCandidateReady, punaropostgres.UpdateDoctorPassed, punaropostgres.UpdateConfigPublished,
		punaropostgres.UpdateRecoveryRequired, punaropostgres.UpdateRecoveryReady, punaropostgres.UpdateRecoveryDoctor, punaropostgres.UpdateRecoveryConfig:
		return true
	default:
		return false
	}
}

func boundedCommand(parent context.Context, executable string, arguments ...string) (string, bool) {
	return boundedCommandLimit(parent, serverDoctorOutputLimit, executable, arguments...)
}

func boundedCommandLimit(parent context.Context, maximum int, executable string, arguments ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(parent, serverDoctorCommandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable, arguments...) // #nosec G204 -- fixed audited executable and structured arguments.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedServerDoctorOutput{maximum: maximum}
	command.Stdout = &output
	if err := command.Run(); err != nil || ctx.Err() != nil || output.overflow {
		return "", false
	}
	return output.buffer.String(), true
}
