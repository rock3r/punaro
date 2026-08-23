package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/adapter"
	"github.com/rock3r/punaro/internal/bootstrap"
	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
	"github.com/rock3r/punaro/internal/relay"
)

const (
	defaultAdapterDoctorTimeout = 15 * time.Second
	maximumAdapterDoctorTimeout = 30 * time.Second
	maximumMailboxDoctorOutput  = 64 << 10
	maximumMailboxDoctorEntries = 4096
	maximumMailboxDoctorBytes   = 64 << 20
)

type serviceDoctorResult struct {
	Installed    bool
	Enabled      bool
	Running      bool
	Executable   bool
	ExitStatus   bool
	RestartState bool
}

type pluginDoctorResult struct {
	Portable    bool
	Codex       bool
	Claude      bool
	Launcher    bool
	Version     string
	SkillDigest string
}

var adapterBuildRelease string

var (
	adapterDoctorRelayProbe = func(ctx context.Context, config adapterConfig) (adapter.DoctorProbeResult, error) {
		client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
		if err != nil {
			return adapter.DoctorProbeResult{}, errors.New("relay doctor client is invalid")
		}
		return client.Doctor(ctx)
	}
	adapterDoctorNotificationProbe = func(ctx context.Context, config adapterConfig) (adapter.DoctorProbeResult, error) {
		client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
		if err != nil {
			return adapter.DoctorProbeResult{}, errors.New("relay notification doctor client is invalid")
		}
		return client.DoctorNotifications(ctx)
	}
	adapterDoctorMailboxProbe   = probeMailboxMCP
	adapterDoctorServiceProbe   = inspectAdapterService
	adapterDoctorBootstrapProbe = func(ctx context.Context, directory string) (punarodiagnostic.Report, error) {
		return bootstrap.Doctor(ctx, bootstrap.DoctorRequest{Directory: directory, BootstrapRelease: adapterBuildRelease})
	}
	adapterDoctorPluginProbe = inspectAdapterPlugin
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

	config, err := loadConfig()
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
		report, reportErr := punarodiagnostic.New(punarodiagnostic.ComponentAdapter, punarodiagnostic.Identity{Platform: runtime.GOOS + "-" + runtime.GOARCH}, checks)
		return writeAdapterDoctorReport(stdout, stderr, report, reportErr)
	}

	checks := []punarodiagnostic.Check{
		punarodiagnostic.Pass("adapter_configuration"),
		punarodiagnostic.Pass("machine_credential_file"),
		boolDoctorCheck(config.profileFile != "", "adapter_profile_file", "install_adapter_profile"),
		boolDoctorCheck(config.identityFile != "", "client_identity_file", "install_client_identity"),
		boolDoctorCheck(distinctDoctorPaths(config), "installer_path_aliases", "repair_installer_paths"),
	}
	if privateDoctorDirectory(config.dataDir) {
		checks = append(checks, punarodiagnostic.Pass("adapter_data_directory"))
	} else {
		checks = append(checks, punarodiagnostic.Fail("adapter_data_directory", "repair_adapter_data_directory"))
	}

	relayResult, _ := adapterDoctorRelayProbe(ctx, config)
	checks = append(checks, relayDoctorChecks("relay", relayResult)...)
	if relayResult.AttachmentsKnown {
		checks = append(checks,
			boolDoctorCheck(relayResult.ActiveEndpoints > 0, "endpoint_attachment", "restart_endpoint_attachment"),
			retiredBindingDoctorCheck(relayResult.ExpiredEndpoints, "expired_endpoint_bindings", "inspect_retired_endpoint_bindings"),
			retiredBindingDoctorCheck(relayResult.ExpiredRoles, "expired_role_bindings", "inspect_retired_role_bindings"),
		)
	} else {
		checks = append(checks,
			punarodiagnostic.Unavailable("endpoint_attachment", "install_compatible_release"),
			punarodiagnostic.OptionalUnavailable("expired_endpoint_bindings", "install_compatible_release"),
			punarodiagnostic.OptionalUnavailable("expired_role_bindings", "install_compatible_release"),
		)
	}
	notificationResult, _ := adapterDoctorNotificationProbe(ctx, config)
	checks = append(checks, relayDoctorChecks("notification", notificationResult)...)

	if _, err := validateMailboxDoctorConfiguration(config); err != nil {
		checks = append(checks,
			punarodiagnostic.Fail("mailbox_executable", "repair_mailbox_executable"),
			punarodiagnostic.Fail("mailbox_state_directory", "repair_mailbox_state_directory"),
			punarodiagnostic.Unavailable("mailbox_mcp", "repair_mailbox_configuration"),
		)
	} else if err := adapterDoctorMailboxProbe(ctx, config); err != nil {
		checks = append(checks, punarodiagnostic.Pass("mailbox_executable"), punarodiagnostic.Pass("mailbox_state_directory"), punarodiagnostic.Fail("mailbox_mcp", "repair_mailbox_mcp"))
	} else {
		checks = append(checks, punarodiagnostic.Pass("mailbox_executable"), punarodiagnostic.Pass("mailbox_state_directory"), punarodiagnostic.Pass("mailbox_mcp"))
	}

	service := adapterDoctorServiceProbe(ctx, config)
	checks = append(checks,
		boolDoctorCheck(service.Installed, "adapter_service_installed", "install_adapter_service"),
		boolDoctorCheck(service.Enabled, "adapter_service_enabled", "enable_adapter_service"),
		boolDoctorCheck(service.Running, "adapter_service_running", "start_adapter_service"),
		boolDoctorCheck(service.Executable, "adapter_service_executable", "repair_adapter_service_binding"),
		boolDoctorCheck(service.ExitStatus, "adapter_service_last_exit", "inspect_adapter_service_exit"),
		boolDoctorCheck(service.RestartState, "adapter_service_restart_state", "repair_adapter_service_restart"),
	)

	bootstrapReport, bootstrapErr := adapterDoctorBootstrapProbe(ctx, *bootstrapDirectory)
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

	plugin := adapterDoctorPluginProbe(*pluginRoot)
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
	report, reportErr := punarodiagnostic.New(punarodiagnostic.ComponentAdapter, identity, checks)
	return writeAdapterDoctorReport(stdout, stderr, report, reportErr)
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
	paths := []string{config.profileFile, config.privateKeyFile, config.identityFile, config.dataDir, config.mailboxState}
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

func probeMailboxMCP(ctx context.Context, config adapterConfig) (resultErr error) {
	binary, err := validateMailboxDoctorConfiguration(config)
	if err != nil {
		return err
	}
	before, err := mailboxDoctorTreeDigest(ctx, config.mailboxState)
	if err != nil {
		return errors.New("mailbox state cannot be inspected safely")
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
		after, err := mailboxDoctorTreeDigest(ctx, config.mailboxState)
		if err != nil || before != after {
			resultErr = errors.New("mailbox MCP changed state during doctor")
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

func mailboxDoctorTreeDigest(ctx context.Context, root string) ([sha256.Size]byte, error) {
	hash := sha256.New()
	entries := 0
	var totalBytes int64
	writeField := func(value []byte) error {
		if err := binary.Write(hash, binary.BigEndian, uint64(len(value))); err != nil {
			return err
		}
		_, err := hash.Write(value)
		return err
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > maximumMailboxDoctorEntries {
			return errors.New("mailbox state has too many entries")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("mailbox state path is invalid")
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("mailbox state entry is unsafe")
		}
		if err := writeField([]byte(filepath.ToSlash(relative))); err != nil {
			return err
		}
		if info.IsDir() {
			return writeField([]byte("directory"))
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || totalBytes > maximumMailboxDoctorBytes-info.Size() {
			return errors.New("mailbox state entry is unsafe")
		}
		totalBytes += info.Size()
		if err := writeField([]byte("file")); err != nil {
			return err
		}
		file, err := openMailboxDoctorSnapshotFile(path, info)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(hash, mailboxDoctorContextReader{ctx: ctx, reader: file}, info.Size())
		var extra [1]byte
		extraCount, extraErr := 0, ctx.Err()
		if extraErr == nil {
			extraCount, extraErr = file.Read(extra[:])
		}
		closeErr := file.Close()
		if copyErr != nil || extraCount != 0 || !errors.Is(extraErr, io.EOF) || closeErr != nil {
			return errors.New("mailbox state changed during inspection")
		}
		return nil
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

type mailboxDoctorContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader mailboxDoctorContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
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
			Tools []json.RawMessage `json:"tools"`
		}
		return json.Unmarshal(response.Result, &result) == nil && result.Tools != nil
	}
	return false
}

func inspectAdapterService(ctx context.Context, _ adapterConfig) serviceDoctorResult {
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
		// #nosec G304,G703 -- fixed installer-owned path selected only by the local platform.
		if body, readErr := os.ReadFile(installedPath); readErr == nil && len(body) <= 64<<10 {
			result.Executable = adapterServiceFileBound(runtime.GOOS, string(body))
		}
	}
	result.Enabled, result.Running, result.ExitStatus, result.RestartState = inspectAdapterServiceManager(ctx, runtime.GOOS)
	if runtime.GOOS == "windows" && result.Executable {
		task, ok := adapterServiceCommand(ctx, "schtasks.exe", "/Query", "/TN", "Punaro Adapter", "/XML")
		result.Executable = ok && adapterWindowsTaskBound(task)
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
	output, err := command.Output()
	if err != nil || len(output) > 64<<10 {
		return "", false
	}
	return string(output), true
}

func adapterWindowsTaskBound(xml string) bool {
	return len(xml) <= 64<<10 && strings.Count(strings.ToLower(xml), "powershell.exe") == 1 && strings.Count(xml, "Run-PunaroAdapter.ps1") == 1 && strings.Contains(xml, "-NoProfile") && strings.Contains(xml, "-NonInteractive")
}

func adapterServiceFileBound(goos, body string) bool {
	switch goos {
	case "linux":
		line := "ExecStart=%h/.local/bin/punaro-bootstrap run --directory %h/.local/state/punaro-bootstrap"
		return exactAdapterServiceLine(body, line)
	case "darwin":
		command := `<string>exec "$HOME/.local/bin/punaro-bootstrap" run --directory "$HOME/.local/state/punaro-bootstrap"</string>`
		return strings.Count(body, command) == 1
	case "windows":
		return strings.Count(body, "$bin = Join-Path $root 'bin\\punaro-bootstrap.exe'") == 1 && strings.Count(body, "& $bin run --directory $bootstrap") == 1
	default:
		return false
	}
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
