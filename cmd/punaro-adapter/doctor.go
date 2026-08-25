package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/adapter"
	"github.com/rock3r/punaro/internal/bootstrap"
	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
	"github.com/rock3r/punaro/internal/incrementalfs"
	"github.com/rock3r/punaro/internal/relay"
	_ "modernc.org/sqlite" // SQLite snapshot driver for non-mutating mailbox diagnostics.
)

const (
	defaultAdapterDoctorTimeout         = 15 * time.Second
	maximumAdapterDoctorTimeout         = 30 * time.Second
	maximumMailboxDoctorOutput          = 64 << 10
	maximumMailboxDoctorBytes           = 64 << 20
	maximumMailboxDoctorEndpoints       = 256
	maximumBootstrapVersionOutput       = 256
	maximumBootstrapReleaseDoctorOutput = 512
	maximumAdapterServiceDoctorOutput   = 4 << 10
)

type serviceDoctorResult struct {
	Installed    bool `json:"installed"`
	Enabled      bool `json:"enabled"`
	Running      bool `json:"running"`
	Executable   bool `json:"executable"`
	ExitStatus   bool `json:"exit_status"`
	RestartState bool `json:"restart_state"`
}

type bootstrapReleaseDoctorResult struct {
	Release string `json:"release"`
}

type pluginDoctorResult struct {
	Portable    bool
	Codex       bool
	Claude      bool
	Launcher    bool
	Version     string
	SkillDigest string
}

type mailboxDoctorResult struct {
	Attached      []string `json:"attached"`
	Configuration bool     `json:"configuration"`
	DataDirectory bool     `json:"data_directory"`
	DistinctPaths bool     `json:"distinct_paths"`
	Healthy       bool     `json:"healthy"`
}

type mailboxDoctorRequest struct {
	Binary         string `json:"binary"`
	State          string `json:"state"`
	Group          string `json:"group"`
	DataDir        string `json:"data_dir"`
	ProfileFile    string `json:"profile_file"`
	PrivateKeyFile string `json:"private_key_file"`
	IdentityFile   string `json:"identity_file"`
}

type boundedDoctorOutput struct {
	buffer   strings.Builder
	maximum  int
	overflow bool
}

func (output *boundedDoctorOutput) Write(value []byte) (int, error) {
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

var adapterBuildRelease string

var (
	adapterDoctorConfigLoad = loadConfig
	adapterDoctorRelayProbe = func(ctx context.Context, config adapterConfig) (adapter.DoctorProbeResult, error) {
		client, err := newAdapterRelayClient(config)
		if err != nil {
			return adapter.DoctorProbeResult{}, errors.New("relay doctor client is invalid")
		}
		return client.Doctor(ctx)
	}
	adapterDoctorNotificationProbe = func(ctx context.Context, config adapterConfig) (adapter.DoctorProbeResult, error) {
		client, err := newAdapterRelayClient(config)
		if err != nil {
			return adapter.DoctorProbeResult{}, errors.New("relay notification doctor client is invalid")
		}
		return client.DoctorNotifications(ctx)
	}
	adapterDoctorEndpointProbe = func(ctx context.Context, config adapterConfig, endpoint string) (adapter.DoctorProbeResult, error) {
		client, err := newAdapterRelayClient(config)
		if err != nil {
			return adapter.DoctorProbeResult{}, errors.New("relay endpoint doctor client is invalid")
		}
		return client.DoctorEndpoint(ctx, endpoint)
	}
	adapterDoctorMailboxProbe          = inspectAdapterMailboxIsolated
	adapterDoctorMailboxExecutable     = os.Executable
	adapterDoctorServiceProbe          = inspectAdapterServiceIsolated
	adapterDoctorServiceExecutable     = os.Executable
	adapterDoctorBootstrapReleaseProbe = func(ctx context.Context) string {
		return inspectAdapterBootstrapReleaseIsolated(ctx, defaultAdapterBootstrapExecutable())
	}
	adapterDoctorBootstrapReleaseExecutable = os.Executable
	adapterDoctorBootstrapProbe             = func(ctx context.Context, directory, bootstrapRelease string) (punarodiagnostic.Report, error) {
		return bootstrap.IsolatedDoctor(ctx, bootstrap.DoctorRequest{Directory: directory, BootstrapRelease: bootstrapRelease})
	}
	adapterDoctorPluginProbe     = inspectAdapterPluginIsolated
	mailboxDoctorSnapshotProtect = protectMailboxDoctorSnapshot
)

func runAdapterDoctor(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("punaro-adapter doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", defaultAdapterDoctorTimeout, "total diagnostic deadline")
	bootstrapDirectory := flags.String("bootstrap-directory", defaultAdapterBootstrapDirectory(), "private bootstrap state directory")
	pluginRoot := flags.String("plugin-root", strings.TrimSpace(os.Getenv("PUNARO_PLUGIN_ROOT")), "installed Punaro plugin root")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *timeout < time.Second || *timeout > maximumAdapterDoctorTimeout || *bootstrapDirectory == "" {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	config, err := loadAdapterDoctorConfig(ctx)
	if err != nil {
		checks := []punarodiagnostic.Check{
			punarodiagnostic.Fail("adapter_configuration", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("adapter_data_directory", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("machine_credential_file", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("mailbox_executable", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("mailbox_state_directory", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("mailbox_mcp", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("adapter_service_installed", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("adapter_service_enabled", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("adapter_service_running", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("adapter_service_executable", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("adapter_service_last_exit", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("adapter_service_restart_state", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("adapter_profile_file", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("client_identity_file", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("installer_path_aliases", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("endpoint_attachment", "repair_adapter_configuration"),
			punarodiagnostic.OptionalUnavailable("expired_endpoint_bindings", "inspect_retired_endpoint_bindings"),
			punarodiagnostic.OptionalUnavailable("expired_role_bindings", "inspect_retired_role_bindings"),
			punarodiagnostic.Unavailable("bootstrap_selected_artifact", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("bootstrap_running_artifact", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("bootstrap_supervisor", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("installed_release", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("portable_plugin_registration", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("codex_plugin_registration", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("claude_plugin_registration", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("plugin_launcher", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("plugin_version", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("skill_set_parity", "repair_adapter_configuration"),
		}
		checks = append(checks, unavailableRelayDoctorChecks("relay")...)
		checks = append(checks, unavailableRelayDoctorChecks("notification")...)
		report, reportErr := punarodiagnostic.NewComponentReport(punarodiagnostic.ComponentAdapter, punarodiagnostic.Identity{Platform: runtime.GOOS + "-" + runtime.GOARCH}, checks)
		return writeAdapterDoctorReport(stdout, stderr, report, reportErr)
	}

	checks := []punarodiagnostic.Check{
		punarodiagnostic.Pass("adapter_configuration"),
		punarodiagnostic.Pass("machine_credential_file"),
		boolDoctorCheck(config.profileFile != "", "adapter_profile_file", "install_adapter_profile"),
		boolDoctorCheck(config.identityFile != "", "client_identity_file", "install_client_identity"),
	}
	mailbox, mailboxErr := adapterDoctorMailboxProbe(ctx, config)
	if mailboxErr != nil {
		checks = append(checks,
			punarodiagnostic.Unavailable("adapter_data_directory", "repair_adapter_configuration"),
			punarodiagnostic.Unavailable("installer_path_aliases", "repair_adapter_configuration"),
		)
	} else {
		checks = append(checks,
			boolDoctorCheck(mailbox.DataDirectory, "adapter_data_directory", "repair_adapter_data_directory"),
			boolDoctorCheck(mailbox.DistinctPaths, "installer_path_aliases", "repair_installer_paths"),
		)
	}

	relayResult, _ := adapterDoctorRelayProbe(ctx, config)
	checks = append(checks, relayDoctorChecks("relay", relayResult)...)
	switch {
	case mailboxErr != nil || !mailbox.Healthy:
		checks = append(checks, punarodiagnostic.Unavailable("endpoint_attachment", "repair_mailbox_mcp"))
	default:
		checks = append(checks, boolDoctorCheck(adapterEndpointsAttached(ctx, config, mailbox.Attached), "endpoint_attachment", "restart_endpoint_attachment"))
	}
	if relayResult.AttachmentsKnown {
		checks = append(checks,
			retiredBindingDoctorCheck(relayResult.ExpiredEndpoints, "expired_endpoint_bindings", "inspect_retired_endpoint_bindings"),
			retiredBindingDoctorCheck(relayResult.ExpiredRoles, "expired_role_bindings", "inspect_retired_role_bindings"),
		)
	} else {
		checks = append(checks,
			punarodiagnostic.OptionalUnavailable("expired_endpoint_bindings", "install_compatible_release"),
			punarodiagnostic.OptionalUnavailable("expired_role_bindings", "install_compatible_release"),
		)
	}
	notificationResult, _ := adapterDoctorNotificationProbe(ctx, config)
	checks = append(checks, relayDoctorChecks("notification", notificationResult)...)

	switch {
	case mailboxErr != nil:
		checks = append(checks,
			punarodiagnostic.Unavailable("mailbox_executable", "repair_mailbox_configuration"),
			punarodiagnostic.Unavailable("mailbox_state_directory", "repair_mailbox_configuration"),
			punarodiagnostic.Unavailable("mailbox_mcp", "repair_mailbox_configuration"),
		)
	case !mailbox.Configuration:
		checks = append(checks,
			punarodiagnostic.Fail("mailbox_executable", "repair_mailbox_executable"),
			punarodiagnostic.Fail("mailbox_state_directory", "repair_mailbox_state_directory"),
			punarodiagnostic.Unavailable("mailbox_mcp", "repair_mailbox_configuration"),
		)
	case !mailbox.Healthy:
		checks = append(checks, punarodiagnostic.Pass("mailbox_executable"), punarodiagnostic.Pass("mailbox_state_directory"), punarodiagnostic.Fail("mailbox_mcp", "repair_mailbox_mcp"))
	default:
		checks = append(checks, punarodiagnostic.Pass("mailbox_executable"), punarodiagnostic.Pass("mailbox_state_directory"), punarodiagnostic.Pass("mailbox_mcp"))
	}

	service, serviceErr := adapterDoctorServiceProbe(ctx, config)
	checks = append(checks, adapterServiceDoctorChecks(service, serviceErr)...)

	bootstrapRelease := adapterDoctorBootstrapReleaseProbe(ctx)
	bootstrapReport, bootstrapErr := adapterDoctorBootstrapProbe(ctx, *bootstrapDirectory, bootstrapRelease)
	if bootstrapErr != nil {
		checks = append(checks,
			punarodiagnostic.Unavailable("bootstrap_selected_artifact", "repair_bootstrap_state"),
			punarodiagnostic.Unavailable("bootstrap_running_artifact", "repair_bootstrap_state"),
			punarodiagnostic.Unavailable("bootstrap_supervisor", "repair_bootstrap_state"),
			punarodiagnostic.Unavailable("installed_release", "repair_bootstrap_state"),
		)
	} else {
		checks = append(checks,
			boolDoctorCheck(adapterReportCheckPass(bootstrapReport, "current_artifact_integrity"), "bootstrap_selected_artifact", "reinstall_signed_release"),
			boolDoctorCheck(adapterReportCheckPass(bootstrapReport, "running_artifact"), "bootstrap_running_artifact", "restart_adapter_service"),
			boolDoctorCheck(adapterReportCheckPass(bootstrapReport, "supervisor_process"), "bootstrap_supervisor", "restart_adapter_service"),
			boolDoctorCheck(adapterBuildRelease != "" && adapterBuildRelease == bootstrapReport.Identity.Release, "installed_release", "install_matching_release"),
		)
	}

	plugin := adapterDoctorPluginProbe(ctx, *pluginRoot)
	checks = append(checks,
		boolDoctorCheck(plugin.Portable, "portable_plugin_registration", "repair_plugin_registration"),
		boolDoctorCheck(plugin.Codex, "codex_plugin_registration", "repair_codex_plugin_registration"),
		boolDoctorCheck(plugin.Claude, "claude_plugin_registration", "repair_claude_plugin_registration"),
		boolDoctorCheck(plugin.Launcher, "plugin_launcher", "repair_plugin_launcher"),
		boolDoctorCheck(plugin.Version != "", "plugin_version", "install_matching_plugin"),
		boolDoctorCheck(plugin.SkillDigest != "", "skill_set_parity", "install_matching_skill_set"),
	)

	identity := punarodiagnostic.Identity{MachineID: config.machineID, Protocol: relay.ProtocolVersion, Platform: runtime.GOOS + "-" + runtime.GOARCH, PluginVersion: plugin.Version, SkillSetDigest: plugin.SkillDigest}
	if bootstrapErr == nil {
		identity.Release = bootstrapReport.Identity.Release
		identity.ReleaseSequence = bootstrapReport.Identity.ReleaseSequence
		identity.CatalogSequence = bootstrapReport.Identity.CatalogSequence
		identity.ArtifactDigest = bootstrapReport.Identity.ArtifactDigest
	}
	report, reportErr := punarodiagnostic.NewComponentReport(punarodiagnostic.ComponentAdapter, identity, checks)
	return writeAdapterDoctorReport(stdout, stderr, report, reportErr)
}

func loadAdapterDoctorConfig(ctx context.Context) (adapterConfig, error) {
	type result struct {
		config adapterConfig
		err    error
	}
	loaded := make(chan result, 1)
	go func() {
		config, err := adapterDoctorConfigLoad()
		loaded <- result{config: config, err: err}
	}()
	select {
	case value := <-loaded:
		return value.config, value.err
	case <-ctx.Done():
		return adapterConfig{}, fmt.Errorf("adapter configuration diagnostic deadline exceeded: %w", ctx.Err())
	}
}

func retiredBindingDoctorCheck(count int, code, remediation string) punarodiagnostic.Check {
	if count == 0 {
		return punarodiagnostic.Check{Code: code, Status: punarodiagnostic.StatusPass}
	}
	return punarodiagnostic.OptionalFail(code, remediation)
}

func writeAdapterDoctorReport(stdout, stderr io.Writer, report punarodiagnostic.Report, err error) int {
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-adapter doctor failed: diagnostic report unavailable")
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-adapter doctor failed: diagnostic report unavailable")
		return 2
	}
	return punarodiagnostic.ExitCode(report)
}

func relayDoctorChecks(prefix string, result adapter.DoctorProbeResult) []punarodiagnostic.Check {
	checks := make([]punarodiagnostic.Check, 0, 5)
	checks = append(checks, boolDoctorCheck(result.Transport, prefix+"_transport", "repair_"+prefix+"_transport"))
	if !result.Transport {
		return append(checks,
			punarodiagnostic.Unavailable(prefix+"_origin", "repair_"+prefix+"_transport"),
			punarodiagnostic.Unavailable(prefix+"_access", "repair_"+prefix+"_transport"),
			punarodiagnostic.Unavailable(prefix+"_enrollment", "repair_"+prefix+"_transport"),
			punarodiagnostic.Unavailable(prefix+"_protocol", "repair_"+prefix+"_transport"),
		)
	}
	checks = append(checks, boolDoctorCheck(result.Origin, prefix+"_origin", "repair_"+prefix+"_route"))
	if !result.Origin {
		return append(checks,
			punarodiagnostic.Fail(prefix+"_access", "repair_"+prefix+"_access"),
			punarodiagnostic.Unavailable(prefix+"_enrollment", "repair_"+prefix+"_access"),
			punarodiagnostic.Unavailable(prefix+"_protocol", "repair_"+prefix+"_access"),
		)
	}
	checks = append(checks, boolDoctorCheck(result.Access, prefix+"_access", "repair_"+prefix+"_access"))
	if !result.Access {
		return append(checks,
			punarodiagnostic.Unavailable(prefix+"_enrollment", "repair_"+prefix+"_access"),
			punarodiagnostic.Unavailable(prefix+"_protocol", "repair_"+prefix+"_access"),
		)
	}
	checks = append(checks, boolDoctorCheck(result.Enrolled, prefix+"_enrollment", "repair_"+prefix+"_enrollment"))
	if !result.Enrolled {
		return append(checks, punarodiagnostic.Unavailable(prefix+"_protocol", "repair_"+prefix+"_enrollment"))
	}
	return append(checks, boolDoctorCheck(result.Protocol, prefix+"_protocol", "install_compatible_release"))
}

func unavailableRelayDoctorChecks(prefix string) []punarodiagnostic.Check {
	return []punarodiagnostic.Check{
		punarodiagnostic.Unavailable(prefix+"_transport", "repair_adapter_configuration"),
		punarodiagnostic.Unavailable(prefix+"_origin", "repair_adapter_configuration"),
		punarodiagnostic.Unavailable(prefix+"_access", "repair_adapter_configuration"),
		punarodiagnostic.Unavailable(prefix+"_enrollment", "repair_adapter_configuration"),
		punarodiagnostic.Unavailable(prefix+"_protocol", "repair_adapter_configuration"),
	}
}

func boolDoctorCheck(ok bool, code, remediation string) punarodiagnostic.Check {
	if ok {
		return punarodiagnostic.Pass(code)
	}
	return punarodiagnostic.Fail(code, remediation)
}

func adapterServiceDoctorChecks(result serviceDoctorResult, err error) []punarodiagnostic.Check {
	if err != nil {
		return []punarodiagnostic.Check{
			punarodiagnostic.Unavailable("adapter_service_installed", "install_adapter_service"),
			punarodiagnostic.Unavailable("adapter_service_enabled", "enable_adapter_service"),
			punarodiagnostic.Unavailable("adapter_service_running", "start_adapter_service"),
			punarodiagnostic.Unavailable("adapter_service_executable", "repair_adapter_service_binding"),
			punarodiagnostic.Unavailable("adapter_service_last_exit", "inspect_adapter_service_exit"),
			punarodiagnostic.Unavailable("adapter_service_restart_state", "repair_adapter_service_restart"),
		}
	}
	return []punarodiagnostic.Check{
		boolDoctorCheck(result.Installed, "adapter_service_installed", "install_adapter_service"),
		boolDoctorCheck(result.Enabled, "adapter_service_enabled", "enable_adapter_service"),
		boolDoctorCheck(result.Running, "adapter_service_running", "start_adapter_service"),
		boolDoctorCheck(result.Executable, "adapter_service_executable", "repair_adapter_service_binding"),
		boolDoctorCheck(result.ExitStatus, "adapter_service_last_exit", "inspect_adapter_service_exit"),
		boolDoctorCheck(result.RestartState, "adapter_service_restart_state", "repair_adapter_service_restart"),
	}
}

func privateDoctorDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path) // #nosec G703 -- local installer-selected diagnostic path.
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return privateDoctorDirectoryPlatform(path, info)
}

func distinctDoctorPaths(config adapterConfig) bool {
	paths := []string{config.profileFile, config.machineCredentialFile(), config.identityFile, config.dataDir, config.mailboxState}
	seen := map[string]struct{}{}
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return false
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return false
		}
		key := filepath.Clean(resolved)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

func probeAdapterMailbox(ctx context.Context, config adapterConfig) (mailboxDoctorResult, error) {
	snapshot, err := mailboxDoctorSnapshot(ctx, config.mailboxState)
	if err != nil {
		return mailboxDoctorResult{}, errors.New("mailbox state cannot be snapshotted safely")
	}
	defer func() { _ = os.RemoveAll(snapshot) }()
	config.mailboxState = snapshot
	if err := probeMailboxMCP(ctx, config); err != nil {
		return mailboxDoctorResult{}, err
	}
	attached, err := probeMailboxAttachments(ctx, config)
	if err != nil {
		return mailboxDoctorResult{}, err
	}
	return mailboxDoctorResult{Attached: attached, Configuration: true, Healthy: true}, nil
}

func inspectAdapterMailboxIsolated(ctx context.Context, config adapterConfig) (mailboxDoctorResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return mailboxDoctorResult{}, errors.New("mailbox diagnostic is unavailable")
	}
	executable, err := adapterDoctorMailboxExecutable()
	if err != nil {
		return mailboxDoctorResult{}, errors.New("mailbox diagnostic is unavailable")
	}
	body, err := json.Marshal(mailboxDoctorRequest{Binary: config.mailboxBinary, State: config.mailboxState, Group: config.attachedGroup, DataDir: config.dataDir, ProfileFile: config.profileFile, PrivateKeyFile: config.machineCredentialFile(), IdentityFile: config.identityFile})
	if err != nil || len(body) == 0 || len(body) > maximumMailboxDoctorOutput {
		return mailboxDoctorResult{}, errors.New("mailbox diagnostic is unavailable")
	}
	command := exec.CommandContext(ctx, executable, "doctor-mailbox-inspect", "--request", base64.RawURLEncoding.EncodeToString(body)) // #nosec G204,G702 -- os.Executable self helper with one bounded encoded request.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedDoctorOutput{maximum: maximumMailboxDoctorOutput}
	command.Stdout = &output
	if command.Run() != nil || ctx.Err() != nil || output.overflow {
		return mailboxDoctorResult{}, errors.New("mailbox diagnostic is unavailable")
	}
	decoder := json.NewDecoder(strings.NewReader(output.buffer.String()))
	var result mailboxDoctorResult
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF || result.Healthy && !result.Configuration || len(result.Attached) > maximumMailboxDoctorEndpoints {
		return mailboxDoctorResult{}, errors.New("mailbox diagnostic is unavailable")
	}
	return result, nil
}

func runAdapterMailboxInspect(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro-adapter doctor-mailbox-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	raw := flags.String("request", "", "bounded encoded mailbox diagnostic request")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *raw == "" || len(*raw) > base64.RawURLEncoding.EncodedLen(maximumMailboxDoctorOutput) {
		return 2
	}
	body, err := base64.RawURLEncoding.DecodeString(*raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != *raw || len(body) == 0 || len(body) > maximumMailboxDoctorOutput {
		return 2
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var request mailboxDoctorRequest
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return 2
	}
	config := adapterConfig{mailboxBinary: request.Binary, mailboxState: request.State, attachedGroup: request.Group, dataDir: request.DataDir, profileFile: request.ProfileFile, privateKeyFile: request.PrivateKeyFile, identityFile: request.IdentityFile}
	result := mailboxDoctorResult{DataDirectory: privateDoctorDirectory(config.dataDir), DistinctPaths: distinctDoctorPaths(config)}
	if _, err := validateMailboxDoctorConfiguration(config); err == nil {
		result.Configuration = true
		if inspected, inspectErr := probeAdapterMailbox(context.Background(), config); inspectErr == nil {
			result.Attached = inspected.Attached
			result.Configuration = inspected.Configuration
			result.Healthy = inspected.Healthy
		}
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return 1
	}
	return 0
}

func mailboxDoctorSnapshot(ctx context.Context, root string) (string, error) {
	if ctx == nil || !privateDoctorDirectory(root) {
		return "", errors.New("mailbox state is unavailable")
	}
	var source string
	for _, name := range []string{"waypost.db", "mailbox.db"} {
		candidate := filepath.Join(root, name)
		info, err := os.Lstat(candidate) // #nosec G703 -- installer-selected private mailbox database.
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || source != "" || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maximumMailboxDoctorBytes {
			return "", errors.New("mailbox database is unsafe")
		}
		source = candidate
	}
	if source == "" {
		return "", errors.New("mailbox database is unsafe")
	}
	snapshot, err := os.MkdirTemp("", "punaro-mailbox-doctor-*")
	if err != nil {
		return "", errors.New("mailbox snapshot is unavailable")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(snapshot)
		}
	}()
	if err := mailboxDoctorSnapshotProtect(snapshot); err != nil {
		return "", fmt.Errorf("mailbox snapshot directory protection failed: %w", err)
	}
	if !privateDoctorDirectory(snapshot) {
		return "", errors.New("mailbox snapshot directory is unsafe")
	}
	destination := filepath.Join(snapshot, filepath.Base(source))
	uri := mailboxDoctorReadOnlyURI(source)
	database, err := sql.Open("sqlite", uri)
	if err != nil {
		return "", fmt.Errorf("mailbox snapshot database open failed: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return "", fmt.Errorf("mailbox snapshot database ping failed: %w", err)
	}
	_, snapshotErr := database.ExecContext(ctx, `VACUUM INTO ?`, destination)
	closeErr := database.Close()
	if snapshotErr != nil {
		return "", fmt.Errorf("mailbox snapshot copy failed: %w", snapshotErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("mailbox snapshot database close failed: %w", closeErr)
	}
	copyInfo, err := os.Lstat(destination) // #nosec G703 -- fresh private snapshot destination.
	if err != nil || !copyInfo.Mode().IsRegular() || copyInfo.Mode()&os.ModeSymlink != 0 || copyInfo.Size() < 0 || copyInfo.Size() > maximumMailboxDoctorBytes {
		return "", errors.New("mailbox snapshot is unsafe")
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return "", fmt.Errorf("mailbox snapshot file protection failed: %w", err)
	}
	cleanup = false
	return snapshot, nil
}

func probeMailboxAttachments(ctx context.Context, config adapterConfig) ([]string, error) {
	binary, err := validateMailboxDoctorConfiguration(config)
	if err != nil {
		return nil, err
	}
	type membership struct {
		Person string `json:"person"`
		Active bool   `json:"active"`
	}
	attached := make([]string, 0, maximumMailboxDoctorEndpoints)
	seen := make(map[string]struct{}, maximumMailboxDoctorEndpoints)
	cursor := ""
	count := 0
	for range 8 {
		args := []string{"--state-dir", config.mailboxState, "group", "members", "--group", config.attachedGroup, "--json"}
		if cursor != "" {
			args = append(args, "--cursor", cursor)
		}
		command := exec.CommandContext(ctx, binary, args...) // #nosec G204,G702 -- fixed read-only mailbox command using installer configuration.
		output := &boundedDoctorOutput{maximum: maximumMailboxDoctorOutput}
		command.Stdout = output
		command.Stderr = io.Discard
		if err := command.Run(); err != nil || output.overflow {
			return nil, errors.New("mailbox attachments are unavailable")
		}
		body := []byte(output.buffer.String())
		var memberships []membership
		nextCursor := ""
		if err := json.Unmarshal(body, &memberships); err != nil {
			var page struct {
				Items      []membership `json:"items"`
				NextCursor string       `json:"next_cursor"`
			}
			if json.Unmarshal(body, &page) != nil || page.Items == nil {
				return nil, errors.New("mailbox attachments are invalid")
			}
			memberships, nextCursor = page.Items, page.NextCursor
		}
		count += len(memberships)
		if count > maximumMailboxDoctorEndpoints {
			return nil, errors.New("mailbox attachments are invalid")
		}
		for _, membership := range memberships {
			if !membership.Active {
				continue
			}
			if !relay.ValidEndpoint(membership.Person) {
				return nil, errors.New("mailbox attachments are invalid")
			}
			if _, duplicate := seen[membership.Person]; duplicate {
				return nil, errors.New("mailbox attachments are invalid")
			}
			seen[membership.Person] = struct{}{}
			attached = append(attached, membership.Person)
		}
		if nextCursor == "" {
			sort.Strings(attached)
			return attached, nil
		}
		if nextCursor == cursor || len(nextCursor) > maximumMailboxDoctorOutput || strings.ContainsAny(nextCursor, "\r\n\x00") {
			return nil, errors.New("mailbox attachments are invalid")
		}
		cursor = nextCursor
	}
	return nil, errors.New("mailbox attachments are invalid")
}

func adapterEndpointsAttached(ctx context.Context, config adapterConfig, endpoints []string) bool {
	if len(endpoints) == 0 || len(endpoints) > maximumMailboxDoctorEndpoints {
		return false
	}
	for _, endpoint := range endpoints {
		if ctx.Err() != nil || !relay.ValidEndpoint(endpoint) {
			return false
		}
		result, err := adapterDoctorEndpointProbe(ctx, config, endpoint)
		if err != nil || !result.Transport || !result.Origin || !result.Access || !result.Enrolled || !result.Protocol || !result.Attached {
			return false
		}
	}
	return true
}

func probeMailboxMCP(ctx context.Context, config adapterConfig) error {
	binary, err := validateMailboxDoctorConfiguration(config)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, binary, "--state-dir", config.mailboxState, "mcp") // #nosec G204,G702 -- fixed MCP handshake using installer configuration.
	stdin, err := command.StdinPipe()
	if err != nil {
		return errors.New("mailbox MCP is unavailable")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return errors.New("mailbox MCP is unavailable")
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return errors.New("mailbox MCP is unavailable")
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		if !waited {
			_ = command.Wait()
		}
	}()
	writer := bufio.NewWriter(stdin)
	decoder := json.NewDecoder(io.LimitReader(stdout, maximumMailboxDoctorOutput+1))
	if err := writeMCPDoctorRequest(writer, 1, "initialize", map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "punaro-doctor", "version": "1"}}); err != nil || !readMCPDoctorResponse(decoder, 1, false) {
		return errors.New("mailbox MCP initialize failed")
	}
	if err := writeMCPDoctorNotification(writer, "notifications/initialized"); err != nil || writeMCPDoctorRequest(writer, 2, "tools/list", map[string]any{}) != nil || !readMCPDoctorResponse(decoder, 2, true) {
		return errors.New("mailbox MCP tools handshake failed")
	}
	_ = stdin.Close()
	if command.Process != nil {
		_ = command.Process.Kill()
	}
	_ = command.Wait()
	waited = true
	return nil
}

func validateMailboxDoctorConfiguration(config adapterConfig) (string, error) {
	if config.mailboxState == "" || !privateDoctorDirectory(config.mailboxState) {
		return "", errors.New("mailbox state is unavailable")
	}
	binary, err := exec.LookPath(config.mailboxBinary)
	if err != nil || !filepath.IsAbs(binary) {
		return "", errors.New("mailbox executable is unavailable")
	}
	info, err := os.Lstat(binary) // #nosec G703 -- installer-selected local executable.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0) {
		return "", errors.New("mailbox executable is unsafe")
	}
	return binary, nil
}

func adapterReportCheckPass(report punarodiagnostic.Report, code string) bool {
	for _, check := range report.Checks {
		if check.Code == code {
			return check.Status == punarodiagnostic.StatusPass
		}
	}
	return false
}

func defaultAdapterBootstrapDirectory() string {
	if runtime.GOOS == "windows" {
		root := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
		if root == "" {
			return ""
		}
		return filepath.Join(root, "Punaro", "bootstrap")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "state", "punaro-bootstrap")
}

func defaultAdapterBootstrapExecutable() string {
	if runtime.GOOS == "windows" {
		root := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
		if root == "" {
			return ""
		}
		return filepath.Join(root, "Punaro", "bin", "punaro-bootstrap.exe")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "bin", "punaro-bootstrap")
}

func inspectAdapterBootstrapRelease(ctx context.Context, executable string) string {
	if executable == "" || !filepath.IsAbs(executable) || ctx.Err() != nil {
		return ""
	}
	info, err := os.Lstat(executable) // #nosec G703 -- fixed installer-owned bootstrap path for the local platform.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return ""
	}
	command := exec.CommandContext(ctx, executable, "version") // #nosec G204 -- validated fixed installer-owned executable, without a shell.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedDoctorOutput{maximum: maximumBootstrapVersionOutput}
	command.Stdout = &output
	if err := command.Run(); err != nil || output.overflow {
		return ""
	}
	release := strings.TrimSpace(output.buffer.String())
	if release == "" || strings.ContainsAny(release, "\r\n\t ") {
		return ""
	}
	return release
}

func inspectAdapterBootstrapReleaseIsolated(ctx context.Context, bootstrapExecutable string) string {
	if ctx == nil || ctx.Err() != nil || bootstrapExecutable == "" || !filepath.IsAbs(bootstrapExecutable) {
		return ""
	}
	executable, err := adapterDoctorBootstrapReleaseExecutable()
	if err != nil {
		return ""
	}
	command := exec.CommandContext(ctx, executable, "doctor-bootstrap-release-inspect", "--executable", bootstrapExecutable) // #nosec G204,G702 -- os.Executable self helper with one fixed-path data argument.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedDoctorOutput{maximum: maximumBootstrapReleaseDoctorOutput}
	command.Stdout = &output
	if command.Run() != nil || ctx.Err() != nil || output.overflow {
		return ""
	}
	decoder := json.NewDecoder(strings.NewReader(output.buffer.String()))
	decoder.DisallowUnknownFields()
	var result bootstrapReleaseDoctorResult
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ""
	}
	return result.Release
}

func runAdapterBootstrapReleaseInspect(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro-adapter doctor-bootstrap-release-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	executable := flags.String("executable", "", "fixed installer-owned bootstrap executable")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *executable == "" || !filepath.IsAbs(*executable) || filepath.Clean(*executable) != *executable {
		return 2
	}
	if json.NewEncoder(stdout).Encode(bootstrapReleaseDoctorResult{Release: inspectAdapterBootstrapRelease(context.Background(), *executable)}) != nil {
		return 1
	}
	return 0
}

func writeMCPDoctorRequest(writer *bufio.Writer, id int, method string, params any) error {
	if err := json.NewEncoder(writer).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return err
	}
	return writer.Flush()
}

func writeMCPDoctorNotification(writer *bufio.Writer, method string) error {
	if err := json.NewEncoder(writer).Encode(map[string]any{"jsonrpc": "2.0", "method": method}); err != nil {
		return err
	}
	return writer.Flush()
}

func readMCPDoctorResponse(decoder *json.Decoder, id int, requireTools bool) bool {
	for range 8 {
		var response struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   json.RawMessage `json:"error"`
		}
		if decoder.Decode(&response) != nil {
			return false
		}
		if response.JSONRPC != "2.0" || strings.TrimSpace(string(response.ID)) != strconv.Itoa(id) {
			continue
		}
		if len(response.Error) != 0 && string(response.Error) != "null" || len(response.Result) == 0 {
			return false
		}
		if !requireTools {
			return true
		}
		var result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		return json.Unmarshal(response.Result, &result) == nil && mailboxToolSurfaceSupported(result.Tools)
	}
	return false
}

func mailboxToolSurfaceSupported(tools []struct {
	Name string `json:"name"`
}) bool {
	present := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		present[tool.Name] = struct{}{}
	}
	for _, surface := range []struct {
		prefix     string
		operations []string
	}{
		{prefix: "waypost_", operations: []string{"status", "recv", "ack"}},
		{prefix: "mailbox_", operations: []string{"status", "recv", "ack", "wait"}},
	} {
		supported := true
		for _, operation := range surface.operations {
			if _, ok := present[surface.prefix+operation]; !ok {
				supported = false
				break
			}
		}
		if supported {
			return true
		}
	}
	return false
}

func inspectAdapterServiceIsolated(ctx context.Context, _ adapterConfig) (serviceDoctorResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return serviceDoctorResult{}, errors.New("adapter service diagnostic is unavailable")
	}
	executable, err := adapterDoctorServiceExecutable()
	if err != nil {
		return serviceDoctorResult{}, errors.New("adapter service diagnostic is unavailable")
	}
	command := exec.CommandContext(ctx, executable, "doctor-service-inspect") // #nosec G204,G702 -- os.Executable self helper without untrusted arguments.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedDoctorOutput{maximum: maximumAdapterServiceDoctorOutput}
	command.Stdout = &output
	if command.Run() != nil || ctx.Err() != nil || output.overflow {
		return serviceDoctorResult{}, errors.New("adapter service diagnostic is unavailable")
	}
	decoder := json.NewDecoder(strings.NewReader(output.buffer.String()))
	decoder.DisallowUnknownFields()
	var result serviceDoctorResult
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return serviceDoctorResult{}, errors.New("adapter service diagnostic is unavailable")
	}
	return result, nil
}

func runAdapterServiceInspect(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro-adapter doctor-service-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	if json.NewEncoder(stdout).Encode(inspectAdapterService(context.Background())) != nil {
		return 1
	}
	return 0
}

func inspectAdapterService(ctx context.Context) serviceDoctorResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return serviceDoctorResult{}
	}
	result := serviceDoctorResult{}
	var installedPath string
	switch runtime.GOOS {
	case "darwin":
		installedPath = filepath.Join(home, "Library", "LaunchAgents", "org.punaro.adapter.plist")
	case "linux":
		installedPath = filepath.Join(home, ".config", "systemd", "user", "punaro-adapter.service")
	case "windows":
		installedPath = filepath.Join(strings.TrimSpace(os.Getenv("LOCALAPPDATA")), "Punaro", "Run-PunaroAdapter.ps1")
	default:
		return result
	}
	if info, statErr := os.Lstat(installedPath); statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 { // #nosec G703 -- fixed installer-owned path selected only by the local platform.
		result.Installed = true
		if body, readErr := incrementalfs.ReadFile(ctx, installedPath, 64<<10); readErr == nil {
			result.Executable = adapterServiceFileBound(runtime.GOOS, string(body))
		}
	}
	if runtime.GOOS == "linux" && result.Executable {
		effective, ok := adapterServiceCommand(ctx, "systemctl", "--user", "show", "--property=ExecStart", "--value", "punaro-adapter.service")
		result.Executable = ok && adapterSystemdExecStartBound(effective, home)
	}
	if runtime.GOOS == "darwin" && result.Executable {
		effective, ok := adapterServiceCommand(ctx, "launchctl", "print", "gui/"+currentUserID()+"/org.punaro.adapter")
		result.Executable = ok && adapterLaunchdEffectiveBound(effective)
	}
	result.Enabled, result.Running, result.ExitStatus, result.RestartState = inspectAdapterServiceManager(ctx, runtime.GOOS)
	if runtime.GOOS == "windows" && result.Executable {
		task, ok := adapterServiceCommand(ctx, "schtasks.exe", "/Query", "/TN", "Punaro Adapter", "/XML")
		powershell := filepath.Join(strings.TrimSpace(os.Getenv("SystemRoot")), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		result.Executable = ok && adapterWindowsTaskBound(task, powershell, installedPath)
	}
	return result
}

func inspectAdapterServiceManager(ctx context.Context, goos string) (bool, bool, bool, bool) {
	switch goos {
	case "linux":
		_, enabled := adapterServiceCommand(ctx, "systemctl", "--user", "is-enabled", "--quiet", "punaro-adapter.service")
		_, running := adapterServiceCommand(ctx, "systemctl", "--user", "is-active", "--quiet", "punaro-adapter.service")
		exit, exitOK := adapterServiceCommand(ctx, "systemctl", "--user", "show", "--property=ExecMainStatus", "--value", "punaro-adapter.service")
		result, resultOK := adapterServiceCommand(ctx, "systemctl", "--user", "show", "--property=Result", "--value", "punaro-adapter.service")
		return enabled, running, exitOK && strings.TrimSpace(exit) == "0", resultOK && strings.TrimSpace(result) == "success"
	case "darwin":
		output, ok := adapterServiceCommand(ctx, "launchctl", "print", "gui/"+currentUserID()+"/org.punaro.adapter")
		running := ok && strings.Contains(output, "state = running")
		exitOK := running || strings.Contains(output, "last exit code = 0")
		return ok, running, exitOK, ok && strings.Contains(output, "runs =")
	case "windows":
		state, stateOK := adapterServiceCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-ScheduledTask -TaskName 'Punaro Adapter').State")
		last, lastOK := adapterServiceCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-ScheduledTaskInfo -TaskName 'Punaro Adapter').LastTaskResult")
		restarts, restartOK := adapterServiceCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-ScheduledTask -TaskName 'Punaro Adapter').Settings.RestartCount")
		canonicalState := strings.TrimSpace(state)
		enabled := stateOK && canonicalState != "Disabled"
		running := stateOK && canonicalState == "Running"
		exitOK := running || lastOK && strings.TrimSpace(last) == "0"
		restartCount, err := strconv.Atoi(strings.TrimSpace(restarts))
		return enabled, running, exitOK, restartOK && err == nil && restartCount > 0
	default:
		return false, false, false, false
	}
}

func adapterServiceCommand(ctx context.Context, executable string, arguments ...string) (string, bool) {
	command := exec.CommandContext(ctx, executable, arguments...) // #nosec G204 -- fixed read-only service-manager inspection.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedDoctorOutput{maximum: 64 << 10}
	command.Stdout = &output
	if err := command.Run(); err != nil || output.overflow {
		return "", false
	}
	return output.buffer.String(), true
}

func adapterWindowsTaskBound(body, powershell, runner string) bool {
	if len(body) > 64<<10 || powershell == "" || runner == "" {
		return false
	}
	// schtasks.exe /Query /XML writes UTF-8/ASCII bytes when stdout is captured
	// while retaining an encoding="UTF-16" declaration. encoding/xml correctly
	// rejects that contradictory declaration before it can inspect the task.
	// Remove only the exact schtasks prolog; genuine UTF-16 output contains NUL
	// bytes and cannot match this UTF-8 prefix.
	body = strings.TrimPrefix(body, `<?xml version="1.0" encoding="UTF-16"?>`)
	var task struct {
		Actions []struct {
			Exec []struct {
				Command   []string `xml:"Command"`
				Arguments []string `xml:"Arguments"`
			} `xml:"Exec"`
		} `xml:"Actions"`
	}
	decoder := xml.NewDecoder(strings.NewReader(body))
	if decoder.Decode(&task) != nil || len(task.Actions) != 1 || len(task.Actions[0].Exec) != 1 {
		return false
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		text, whitespace := token.(xml.CharData)
		if err != nil || !whitespace || strings.TrimSpace(string(text)) != "" {
			return false
		}
	}
	action := task.Actions[0].Exec[0]
	if len(action.Command) != 1 || len(action.Arguments) != 1 || !strings.EqualFold(strings.TrimSpace(action.Command[0]), powershell) {
		return false
	}
	wantArguments := `-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "` + runner + `"`
	return strings.TrimSpace(action.Arguments[0]) == wantArguments
}

func adapterSystemdExecStartBound(body, home string) bool {
	if home == "" || !filepath.IsAbs(home) || filepath.Clean(home) != home || len(body) > 64<<10 {
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
	executable := filepath.Join(home, ".local", "bin", "punaro-bootstrap")
	directory := filepath.Join(home, ".local", "state", "punaro-bootstrap")
	return fields["path"] == executable && fields["argv[]"] == executable+" run --directory "+directory
}

func adapterServiceFileBound(goos, body string) bool {
	switch goos {
	case "linux":
		line := "ExecStart=%h/.local/bin/punaro-bootstrap run --directory %h/.local/state/punaro-bootstrap"
		return exactAdapterServiceLine(body, line)
	case "darwin":
		return adapterLaunchdPlistBound(body)
	case "windows":
		return adapterWindowsRunnerBound(body)
	default:
		return false
	}
}

const adapterWindowsRunnerBody = "Set-StrictMode -Version Latest\n" +
	"$ErrorActionPreference = 'Stop'\n\n" +
	"$root = $PSScriptRoot\n" +
	"$bootstrap = Join-Path $root 'bootstrap'\n" +
	"$bin = Join-Path $root 'bin\\punaro-bootstrap.exe'\n" +
	"& $bin run --directory $bootstrap\n" +
	"exit $LASTEXITCODE\n"

func adapterWindowsRunnerBound(body string) bool {
	if len(body) > 64<<10 {
		return false
	}
	normalized := strings.ReplaceAll(body, "\r\n", "\n")
	return !strings.Contains(normalized, "\r") && normalized == adapterWindowsRunnerBody
}

func adapterLaunchdPlistBound(body string) bool {
	if len(body) > 64<<10 {
		return false
	}
	decoder := xml.NewDecoder(strings.NewReader(body))
	next := func() (xml.Token, error) {
		for {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch value := token.(type) {
			case xml.CharData:
				if strings.TrimSpace(string(value)) == "" {
					continue
				}
			case xml.ProcInst, xml.Directive, xml.Comment:
				continue
			}
			return token, nil
		}
	}
	token, err := next()
	root, ok := token.(xml.StartElement)
	if err != nil || !ok || root.Name.Local != "plist" {
		return false
	}
	token, err = next()
	dictionary, ok := token.(xml.StartElement)
	if err != nil || !ok || dictionary.Name.Local != "dict" {
		return false
	}
	seen := map[string]bool{}
	labelOK, argumentsOK := false, false
	for {
		token, err = next()
		if err != nil {
			return false
		}
		if end, ok := token.(xml.EndElement); ok {
			if end.Name.Local != "dict" {
				return false
			}
			break
		}
		keyStart, ok := token.(xml.StartElement)
		if !ok || keyStart.Name.Local != "key" {
			return false
		}
		key, ok := decodeAdapterXMLString(decoder, keyStart)
		if !ok || key == "" || seen[key] {
			return false
		}
		seen[key] = true
		token, err = next()
		valueStart, ok := token.(xml.StartElement)
		if err != nil || !ok {
			return false
		}
		switch key {
		case "Label":
			value, valid := decodeAdapterXMLString(decoder, valueStart)
			labelOK = valid && valueStart.Name.Local == "string" && value == "org.punaro.adapter"
		case "ProgramArguments":
			arguments, valid := decodeAdapterXMLStringArray(decoder, valueStart)
			argumentsOK = valid && slices.Equal(arguments, adapterLaunchdArguments())
		default:
			if decoder.Skip() != nil {
				return false
			}
		}
	}
	token, err = next()
	endRoot, ok := token.(xml.EndElement)
	if err != nil || !ok || endRoot.Name.Local != "plist" {
		return false
	}
	_, err = next()
	return errors.Is(err, io.EOF) && labelOK && argumentsOK
}

func decodeAdapterXMLString(decoder *xml.Decoder, start xml.StartElement) (string, bool) {
	if start.Name.Local != "key" && start.Name.Local != "string" {
		return "", false
	}
	var value strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", false
		}
		switch token := token.(type) {
		case xml.CharData:
			_, _ = value.Write(token)
		case xml.EndElement:
			return value.String(), token.Name == start.Name
		default:
			return "", false
		}
	}
}

func decodeAdapterXMLStringArray(decoder *xml.Decoder, start xml.StartElement) ([]string, bool) {
	if start.Name.Local != "array" {
		return nil, false
	}
	var values []string
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		switch token := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(token)) != "" {
				return nil, false
			}
		case xml.StartElement:
			value, ok := decodeAdapterXMLString(decoder, token)
			if !ok || token.Name.Local != "string" {
				return nil, false
			}
			values = append(values, value)
		case xml.EndElement:
			return values, token.Name == start.Name
		default:
			return nil, false
		}
	}
}

func adapterLaunchdArguments() []string {
	return []string{"/bin/sh", "-c", `exec "$HOME/.local/bin/punaro-bootstrap" run --directory "$HOME/.local/state/punaro-bootstrap"`}
}

func adapterLaunchdEffectiveBound(body string) bool {
	if len(body) > 64<<10 {
		return false
	}
	lines := strings.Split(body, "\n")
	var arguments []string
	inArguments, complete, programCount, argumentsCount := false, false, 0, 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "program = /bin/sh" {
			programCount++
		}
		if line == "arguments = {" {
			argumentsCount++
			if inArguments || complete {
				return false
			}
			inArguments = true
			continue
		}
		if inArguments {
			if line == "}" {
				inArguments, complete = false, true
				continue
			}
			if line == "" {
				return false
			}
			arguments = append(arguments, line)
		}
	}
	return programCount == 1 && argumentsCount == 1 && complete && !inArguments && slices.Equal(arguments, adapterLaunchdArguments())
}

func exactAdapterServiceLine(body, expected string) bool {
	count := 0
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == expected {
			count++
		}
	}
	return count == 1
}
