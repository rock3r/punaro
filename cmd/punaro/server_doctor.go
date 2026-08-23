package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
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

func inspectServerDoctorState(parent context.Context, installation operator.Installation, machineID string, gatewayColocated bool, relayProfile string) serverDoctorState {
	ctx, cancel := context.WithTimeout(parent, serverDoctorTimeout)
	defer cancel()

	state := serverDoctorState{MachineID: validServerMachineID(machineID), Release: serverBuildRelease, Protocol: relay.ProtocolVersion, ExpectedPostgresMajor: punarorelease.ProductionPostgreSQLMajor}
	state.ReleaseSequence, _ = strconv.ParseInt(serverBuildSequence, 10, 64)
	state.CatalogSequence, _ = strconv.ParseInt(serverBuildCatalogSequence, 10, 64)
	state.InstalledRelease = known(serverBuildRelease != "" && serverBuildImage != "", serverBuildRelease != "" && serverBuildImage == installation.Image)
	state.ComposeBinding = fileDigestMatches(operator.OverrideFile(installation.Directory), serverBuildComposeSHA256)
	state.MigrationBinding = known(serverBuildMigrationSHA256 != "", serverBuildMigrationSHA256 == punaropostgres.MigrationManifestSHA256())
	state.RunningImage = inspectRunningImage(ctx, installation)
	state.Storage = inspectServerStorage(installation.DataDir, serverDoctorMinimumFree)
	state.BackupAvailable, state.BackupFresh = inspectServerBackups(installation.BackupDir, time.Now().UTC())
	state.DatabasePrivate = known(true, serverComposeTopologyPrivate(installation))
	state.HealthPrivate = known(true, listener.IsLoopback(installation.HealthListenAddr))
	state.AdminPrivate = state.DatabasePrivate
	state.BlobPrivate = known(true, serverBlobTopologyPrivate(installation))
	state.TunnelRoute, state.TunnelOrigin, state.AccessAdmission, state.RelayEnrollment, state.RelayProtocol = inspectServerRelay(ctx, installation, relayProfile)
	if gatewayColocated {
		state.GatewayInstalled, state.GatewayEnabled, state.GatewayRunning, state.GatewayExecutable, state.GatewayExitStatus, state.GatewayRestartState, state.GatewayRelease = inspectGatewayService(ctx, serverBuildRelease)
	}

	database, err := punaropostgres.OpenApplication(ctx, punaropostgres.Config{DSNFile: installation.AppDSNFile})
	if err == nil {
		state.PostgresMajor, err = database.PostgreSQLMajor(ctx)
		state.PostgresKnown = err == nil
		_ = database.Close()
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

func fileDigestMatches(path, expected string) knownDoctorBool {
	if len(expected) != 64 {
		return knownDoctorBool{}
	}
	file, err := os.Open(path) // #nosec G304 -- fixed generated file below the validated installation root.
	if err != nil {
		return known(true, false)
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.CopyN(hash, file, (1<<20)+1); err != nil && !errors.Is(err, io.EOF) {
		return knownDoctorBool{}
	}
	return known(true, hex.EncodeToString(hash.Sum(nil)) == expected)
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

func inspectServerBackups(root string, now time.Time) (knownDoctorBool, knownDoctorBool) {
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 128 {
		return knownDoctorBool{}, knownDoctorBool{}
	}
	backups, err := punarobackup.List(root)
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

func serverComposeTopologyPrivate(installation operator.Installation) bool {
	for _, failure := range operator.CheckPaths(installation) {
		if strings.Contains(failure, "Compose override") || strings.Contains(failure, "daemon environment") {
			return false
		}
	}
	return true
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
		return passed, passed, passed, passed, passed
	}
	profile, err := loadServerDoctorProfile(relayProfile)
	if err != nil {
		return knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}
	}
	client, err := adapter.NewHTTPRelayClient(profile.RelayURL, profile.MachineID, profile.PrivateKey, &http.Client{Timeout: 5 * time.Second}, profile.AccessToken)
	if err != nil {
		return knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}
	}
	result, _ := client.Doctor(parent)
	return known(true, result.Transport), known(result.Transport, result.Origin), known(result.Transport, result.Access), known(result.Origin, result.Enrolled), known(result.Enrolled, result.Protocol)
}

type serverDoctorProfile struct {
	RelayURL    string
	MachineID   string
	PrivateKey  ed25519.PrivateKey
	AccessToken adapter.AccessServiceToken
}

func loadServerDoctorProfile(path string) (serverDoctorProfile, error) {
	body, err := readProtectedServerDoctorFile(path, 8<<10)
	if err != nil {
		return serverDoctorProfile{}, errors.New("server doctor profile unavailable")
	}
	return parseServerDoctorProfile(body)
}

func parseServerDoctorProfile(body []byte) (serverDoctorProfile, error) {
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
	keyBody, err := readProtectedServerDoctorFile(values["PUNARO_SERVER_DOCTOR_PRIVATE_KEY_FILE"], 4<<10)
	if err != nil {
		return serverDoctorProfile{}, errors.New("server doctor credential unavailable")
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(keyBody)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return serverDoctorProfile{}, errors.New("server doctor credential invalid")
	}
	accessBody, err := readProtectedServerDoctorFile(values["PUNARO_SERVER_DOCTOR_ACCESS_TOKEN_FILE"], 4<<10)
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
	if _, err := parseServerDoctorProfile(body); err != nil {
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

func readProtectedServerDoctorFile(path string, maximum int64) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("protected doctor file invalid")
	}
	info, err := os.Lstat(path) // #nosec G703 -- explicit local protected diagnostic file.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maximum || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("protected doctor file invalid")
	}
	file, err := os.Open(path) // #nosec G304,G703 -- validated explicit protected file.
	if err != nil {
		return nil, errors.New("protected doctor file invalid")
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(body) == 0 || int64(len(body)) > maximum {
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
	executable := known(true, serverGatewayServiceFileBound("/etc/systemd/system/punaro-telegram.service"))
	release, releaseKnown := boundedCommand(parent, "/usr/local/bin/punaro-telegram", "version")
	return known(true, installed), known(true, enabled), known(activeKnown, running), executable,
		known(exitKnown, strings.TrimSpace(exitStatus) == "0"), known(resultKnown, strings.TrimSpace(serviceResult) == "success"),
		known(releaseKnown && expectedRelease != "", strings.TrimSpace(release) == expectedRelease)
}

func serverGatewayServiceFileBound(path string) bool {
	info, err := os.Lstat(path) // #nosec G703 -- fixed system service definition.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	body, err := os.ReadFile(path) // #nosec G304 -- fixed system service definition.
	if err != nil || len(body) > 64<<10 {
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

func inspectUpdateState(parent context.Context, installation operator.Installation) (knownDoctorBool, knownDoctorBool, knownDoctorBool) {
	admin, err := punaropostgres.OpenAdministration(parent, punaropostgres.Config{DSNFile: installation.OwnerDSNFile})
	if err != nil {
		return knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}
	}
	defer func() { _ = admin.Close() }()
	transaction, err := admin.LatestUpdate(parent)
	if errors.Is(err, punaropostgres.ErrNotFound) {
		return known(true, true), inspectRecoveryReceiptAbsent(installation), known(true, true)
	}
	if err != nil {
		return knownDoctorBool{}, knownDoctorBool{}, knownDoctorBool{}
	}
	terminal := transaction.Phase == punaropostgres.UpdateCommitted || transaction.Phase == punaropostgres.UpdateRecovered || transaction.Phase == punaropostgres.UpdateAborted
	if transaction.Phase == punaropostgres.UpdateCommitted && serverBuildRelease != "" {
		terminal = transaction.TargetRelease == serverBuildRelease && transaction.TargetImage == installation.Image && transaction.ComposeSHA256 == serverBuildComposeSHA256 && transaction.MigrationManifestSHA256 == serverBuildMigrationSHA256
	}
	if terminal {
		return known(true, true), inspectRecoveryReceiptAbsent(installation), known(true, true)
	}
	if !updatePhaseRequiresRecoveryReceipt(transaction.Phase) {
		return known(true, false), inspectRecoveryReceiptAbsent(installation), known(true, false)
	}
	receipt, _, receiptErr := operator.LoadUpdateRecoveryReceipt(operator.UpdateRecoveryReceiptFile(installation.Directory))
	receiptOK := receiptErr == nil && receipt.UpdateID == transaction.UpdateID && receipt.BackupID == transaction.BackupID && receipt.TargetRelease == transaction.TargetRelease && receipt.ManifestSHA256 == transaction.BackupManifestSHA256
	return known(true, false), known(true, receiptOK), known(true, false)
}

func inspectRecoveryReceiptAbsent(installation operator.Installation) knownDoctorBool {
	_, err := os.Lstat(operator.UpdateRecoveryReceiptFile(installation.Directory)) // #nosec G703 -- fixed update-stage child.
	return known(true, errors.Is(err, os.ErrNotExist))
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
	ctx, cancel := context.WithTimeout(parent, serverDoctorCommandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable, arguments...) // #nosec G204 -- fixed audited executable and structured arguments.
	command.Stdin = nil
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil || ctx.Err() != nil || len(output) > serverDoctorOutputLimit {
		return "", false
	}
	return string(output), true
}
