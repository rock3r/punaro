package main

import (
	"context"
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
	"strconv"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/adapter"
	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
	"github.com/rock3r/punaro/internal/incrementalfs"
	"github.com/rock3r/punaro/internal/relay"
	"github.com/rock3r/punaro/internal/telegram"
)

const (
	defaultTelegramDoctorTimeout = 15 * time.Second
	maximumTelegramDoctorTimeout = 30 * time.Second
	maximumHealthyCycleAge       = 2 * time.Minute
	maximumServiceVersionOutput  = 256
	maximumTelegramStateOutput   = 16 << 10
)

// Telegram release identity is set from a verified release build with -X.
// Empty development builds fail release-provenance readiness without inventing
// an identity.
var (
	telegramBuildRelease         string
	telegramBuildSequence        string
	telegramBuildCatalogSequence string
)

type telegramServiceDoctorResult struct {
	Installed    bool
	Enabled      bool
	Running      bool
	Executable   bool
	Release      bool
	ExitStatus   bool
	RestartState bool
}

type telegramStateDoctorRequest struct {
	Database string `json:"database"`
	Now      string `json:"now"`
}

type telegramStateDoctorResponse struct {
	Snapshot  telegram.GatewayStateSnapshot `json:"snapshot"`
	Available bool                          `json:"available"`
}

type boundedTelegramOutput struct {
	buffer   strings.Builder
	maximum  int
	overflow bool
}

func (output *boundedTelegramOutput) Write(value []byte) (int, error) {
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

var (
	telegramDoctorConfigLoad = loadConfig
	telegramDoctorNow        = time.Now
	telegramDoctorRelayProbe = func(ctx context.Context, cfg config) (adapter.DoctorProbeResult, error) {
		client, err := newTelegramRelayClient(cfg)
		if err != nil {
			return adapter.DoctorProbeResult{}, errors.New("relay doctor unavailable")
		}
		return client.DoctorEndpoint(ctx, cfg.endpoint)
	}
	telegramDoctorNotificationProbe = func(ctx context.Context, cfg config) (adapter.DoctorProbeResult, error) {
		client, err := newTelegramRelayClient(cfg)
		if err != nil {
			return adapter.DoctorProbeResult{}, errors.New("relay notification doctor unavailable")
		}
		return client.DoctorNotifications(ctx)
	}
	telegramDoctorBotProbe = func(ctx context.Context, cfg config) error {
		client, err := telegram.NewClient(cfg.apiURL, cfg.botToken, nil)
		if err != nil {
			return errors.New("telegram doctor unavailable")
		}
		return client.Doctor(ctx)
	}
	telegramDoctorServiceProbe      = inspectTelegramServiceIsolated
	telegramDoctorServiceExecutable = os.Executable
	telegramDoctorStateProbe        = inspectTelegramStateIsolated
	telegramDoctorStateExecutable   = os.Executable
)

func runTelegramDoctor(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("punaro-telegram doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", defaultTelegramDoctorTimeout, "total diagnostic deadline")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *timeout < time.Second || *timeout > maximumTelegramDoctorTimeout {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	cfg, err := loadTelegramDoctorConfig(ctx)
	if err != nil {
		report, reportErr := punarodiagnostic.NewComponentReport(punarodiagnostic.ComponentTelegram, punarodiagnostic.Identity{Platform: runtime.GOOS + "-" + runtime.GOARCH}, telegramUnavailableChecks())
		return writeTelegramDoctorReport(stdout, stderr, report, reportErr)
	}

	checks := []punarodiagnostic.Check{
		punarodiagnostic.Pass("telegram_configuration"),
		punarodiagnostic.Pass("machine_credential_file"),
		telegramBoolCheck(cfg.botTokenFile != "", "bot_credential_file", "install_bot_credential_file"),
		telegramBoolCheck(cfg.accessTokenFile != "" || cfg.accessToken.ClientID == "", "access_credential_file", "install_access_credential_file"),
		punarodiagnostic.Pass("single_user_policy"),
		punarodiagnostic.Pass("gateway_endpoint_identity"),
		telegramBoolCheck(telegramBuildRelease != "", "installed_release", "install_signed_release"),
	}

	service := telegramDoctorServiceProbe(ctx)
	checks = append(checks,
		telegramBoolCheck(service.Installed, "gateway_service_installed", "install_gateway_service"),
		telegramBoolCheck(service.Enabled, "gateway_service_enabled", "enable_gateway_service"),
		telegramBoolCheck(service.Running, "gateway_service_running", "start_gateway_service"),
		telegramBoolCheck(service.Executable, "gateway_service_executable", "repair_gateway_service_binding"),
		telegramBoolCheck(service.ExitStatus, "gateway_service_last_exit", "inspect_gateway_service_exit"),
		telegramBoolCheck(service.RestartState, "gateway_service_restart_state", "repair_gateway_service_restart"),
		telegramBoolCheck(service.Release, "running_release", "restart_gateway_release"),
	)

	relayResult, _ := telegramDoctorRelayProbe(ctx, cfg)
	checks = append(checks, telegramRelayChecks("relay", relayResult)...)
	checks = append(checks, telegramBoolCheck(relayResult.Attached, "gateway_endpoint_attachment", "restart_gateway_attachment"))
	notificationResult, _ := telegramDoctorNotificationProbe(ctx, cfg)
	checks = append(checks, telegramRelayChecks("notification", notificationResult)...)
	if telegramDoctorBotProbe(ctx, cfg) != nil {
		checks = append(checks, punarodiagnostic.Fail("bot_api", "repair_bot_api_access"))
	} else {
		checks = append(checks, punarodiagnostic.Pass("bot_api"))
	}

	snapshot, stateErr := telegramDoctorStateProbe(ctx, filepath.Join(cfg.stateDir, "telegram.db"), telegramDoctorNow().UTC())
	if stateErr != nil {
		checks = append(checks, telegramStateUnavailableChecks()...)
	} else {
		checks = append(checks,
			telegramBoolCheck(snapshot.Integrity, "state_integrity", "restore_gateway_state"),
			telegramBoolCheck(snapshot.RoutesConsistent, "conversation_route_integrity", "repair_conversation_routes"),
			telegramBoolCheck(snapshot.HasHealth && snapshot.LastCycleAge <= maximumHealthyCycleAge, "cycle_liveness", "restart_gateway_service"),
			telegramBoolCheck(snapshot.HasSuccess && snapshot.LastSuccessAge <= maximumHealthyCycleAge, "successful_cycle_liveness", "repair_gateway_retry_state"),
			telegramBoolCheck(snapshot.HasPoll && snapshot.LastPollAge <= maximumHealthyCycleAge, "polling_liveness", "repair_telegram_polling"),
			telegramBoolCheck(snapshot.HasRelay && snapshot.LastRelayAge <= maximumHealthyCycleAge, "relay_cycle_liveness", "repair_relay_access"),
			telegramBoolCheck(snapshot.HasTelegram && snapshot.LastTelegramAge <= maximumHealthyCycleAge, "telegram_cycle_liveness", "repair_bot_api_access"),
			telegramBoolCheck(snapshot.ConsecutiveFailures < 3, "retry_state", "inspect_gateway_retry_state"),
			telegramBoolCheck(snapshot.TerminalInbound == 0, "terminal_inbound_rejection", "repair_inbound_relay_authorization"),
			telegramBoolCheck(snapshot.TerminalOutbound == 0, "terminal_outbound_rejection", "repair_outbound_telegram_target"),
			telegramBoolCheck(!snapshot.StuckHead, "stuck_head_delivery", "repair_stuck_gateway_delivery"),
			telegramBoolCheck(snapshot.LastFailure != telegram.GatewayFailureMessageLessPoll || snapshot.ConsecutiveFailures < 3, "message_less_update_stall", "repair_message_less_polling"),
			telegramBoolCheck(snapshot.DeletedTopicTargets == 0, "deleted_topic_target", "repair_deleted_topic_route"),
			telegramBoolCheck(snapshot.LastFailure != telegram.GatewayFailureTransient || snapshot.ConsecutiveFailures < 3, "transient_retry_stall", "repair_transient_gateway_dependency"),
		)
		if snapshot.IncompleteClaims > 0 {
			checks = append(checks, punarodiagnostic.Fail("claim_backlog", "resume_gateway_claims"))
			checks = append(checks, telegramBoolCheck(snapshot.HasSuccess && snapshot.LastSuccessAge <= maximumHealthyCycleAge, "claim_backlog_age", "repair_stale_gateway_claims"))
		} else {
			checks = append(checks, punarodiagnostic.Pass("claim_backlog"))
			checks = append(checks, punarodiagnostic.Pass("claim_backlog_age"))
		}
	}

	releaseSequence, _ := strconv.ParseInt(telegramBuildSequence, 10, 64)
	catalogSequence, _ := strconv.ParseInt(telegramBuildCatalogSequence, 10, 64)
	identity := punarodiagnostic.Identity{MachineID: cfg.machineID, Release: telegramBuildRelease, ReleaseSequence: releaseSequence, CatalogSequence: catalogSequence, Protocol: relay.ProtocolVersion, Platform: runtime.GOOS + "-" + runtime.GOARCH}
	report, reportErr := punarodiagnostic.NewComponentReport(punarodiagnostic.ComponentTelegram, identity, checks)
	return writeTelegramDoctorReport(stdout, stderr, report, reportErr)
}

func inspectTelegramStateIsolated(ctx context.Context, database string, now time.Time) (telegram.GatewayStateSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(database) || now.IsZero() {
		return telegram.GatewayStateSnapshot{}, errors.New("telegram state diagnostic is unavailable")
	}
	executable, err := telegramDoctorStateExecutable()
	if err != nil {
		return telegram.GatewayStateSnapshot{}, errors.New("telegram state diagnostic is unavailable")
	}
	body, err := json.Marshal(telegramStateDoctorRequest{Database: database, Now: now.UTC().Format(time.RFC3339Nano)})
	if err != nil || len(body) == 0 || len(body) > maximumTelegramStateOutput {
		return telegram.GatewayStateSnapshot{}, errors.New("telegram state diagnostic is unavailable")
	}
	command := exec.CommandContext(ctx, executable, "doctor-state-inspect", "--request", base64.RawURLEncoding.EncodeToString(body)) // #nosec G204,G702 -- os.Executable self helper with one bounded encoded request.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedTelegramOutput{maximum: maximumTelegramStateOutput}
	command.Stdout = &output
	if command.Run() != nil || ctx.Err() != nil || output.overflow {
		return telegram.GatewayStateSnapshot{}, errors.New("telegram state diagnostic is unavailable")
	}
	decoder := json.NewDecoder(strings.NewReader(output.buffer.String()))
	decoder.DisallowUnknownFields()
	var response telegramStateDoctorResponse
	if decoder.Decode(&response) != nil || decoder.Decode(&struct{}{}) != io.EOF || !response.Available {
		return telegram.GatewayStateSnapshot{}, errors.New("telegram state diagnostic is unavailable")
	}
	return response.Snapshot, nil
}

func runTelegramStateInspect(args []string, stdout io.Writer) int {
	flags := flag.NewFlagSet("punaro-telegram doctor-state-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	raw := flags.String("request", "", "bounded encoded state diagnostic request")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *raw == "" || len(*raw) > base64.RawURLEncoding.EncodedLen(maximumTelegramStateOutput) {
		return 2
	}
	body, err := base64.RawURLEncoding.DecodeString(*raw)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != *raw || len(body) == 0 || len(body) > maximumTelegramStateOutput {
		return 2
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var request telegramStateDoctorRequest
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || !filepath.IsAbs(request.Database) || filepath.Clean(request.Database) != request.Database {
		return 2
	}
	now, err := time.Parse(time.RFC3339Nano, request.Now)
	if err != nil || now.Location() != time.UTC || now.Format(time.RFC3339Nano) != request.Now {
		return 2
	}
	response := telegramStateDoctorResponse{}
	if snapshot, inspectErr := telegram.InspectGatewayState(context.Background(), request.Database, now); inspectErr == nil {
		response.Snapshot = snapshot
		response.Available = true
	}
	if json.NewEncoder(stdout).Encode(response) != nil {
		return 1
	}
	return 0
}

func loadTelegramDoctorConfig(ctx context.Context) (config, error) {
	type result struct {
		config config
		err    error
	}
	loaded := make(chan result, 1)
	go func() {
		cfg, err := telegramDoctorConfigLoad()
		loaded <- result{config: cfg, err: err}
	}()
	select {
	case value := <-loaded:
		return value.config, value.err
	case <-ctx.Done():
		return config{}, fmt.Errorf("telegram configuration diagnostic deadline exceeded: %w", ctx.Err())
	}
}

func telegramUnavailableChecks() []punarodiagnostic.Check {
	codes := []string{"access_credential_file", "bot_api", "bot_credential_file", "claim_backlog", "claim_backlog_age", "conversation_route_integrity", "cycle_liveness", "deleted_topic_target", "gateway_endpoint_attachment", "gateway_endpoint_identity", "gateway_service_enabled", "gateway_service_executable", "gateway_service_installed", "gateway_service_last_exit", "gateway_service_restart_state", "gateway_service_running", "installed_release", "machine_credential_file", "message_less_update_stall", "notification_access", "notification_enrollment", "notification_origin", "notification_protocol", "notification_transport", "polling_liveness", "relay_access", "relay_cycle_liveness", "relay_enrollment", "relay_origin", "relay_protocol", "relay_transport", "retry_state", "running_release", "single_user_policy", "state_integrity", "stuck_head_delivery", "successful_cycle_liveness", "telegram_cycle_liveness", "terminal_inbound_rejection", "terminal_outbound_rejection", "transient_retry_stall"}
	checks := []punarodiagnostic.Check{punarodiagnostic.Fail("telegram_configuration", "repair_telegram_configuration")}
	for _, code := range codes {
		checks = append(checks, punarodiagnostic.Unavailable(code, "repair_telegram_configuration"))
	}
	return checks
}

func telegramStateUnavailableChecks() []punarodiagnostic.Check {
	codes := []string{"claim_backlog", "claim_backlog_age", "conversation_route_integrity", "cycle_liveness", "deleted_topic_target", "message_less_update_stall", "polling_liveness", "relay_cycle_liveness", "retry_state", "state_integrity", "stuck_head_delivery", "successful_cycle_liveness", "telegram_cycle_liveness", "terminal_inbound_rejection", "terminal_outbound_rejection", "transient_retry_stall"}
	checks := make([]punarodiagnostic.Check, 0, len(codes))
	for _, code := range codes {
		checks = append(checks, punarodiagnostic.Unavailable(code, "restore_gateway_state"))
	}
	return checks
}

func telegramRelayChecks(prefix string, result adapter.DoctorProbeResult) []punarodiagnostic.Check {
	checks := []punarodiagnostic.Check{telegramBoolCheck(result.Transport, prefix+"_transport", "repair_"+prefix+"_transport")}
	if !result.Transport {
		return append(checks, punarodiagnostic.Unavailable(prefix+"_origin", "repair_"+prefix+"_transport"), punarodiagnostic.Unavailable(prefix+"_access", "repair_"+prefix+"_transport"), punarodiagnostic.Unavailable(prefix+"_enrollment", "repair_"+prefix+"_transport"), punarodiagnostic.Unavailable(prefix+"_protocol", "repair_"+prefix+"_transport"))
	}
	checks = append(checks, telegramBoolCheck(result.Origin, prefix+"_origin", "repair_"+prefix+"_route"))
	if !result.Origin {
		return append(checks, punarodiagnostic.Fail(prefix+"_access", "repair_"+prefix+"_access"), punarodiagnostic.Unavailable(prefix+"_enrollment", "repair_"+prefix+"_access"), punarodiagnostic.Unavailable(prefix+"_protocol", "repair_"+prefix+"_access"))
	}
	checks = append(checks, telegramBoolCheck(result.Access, prefix+"_access", "repair_"+prefix+"_access"))
	if !result.Access {
		return append(checks, punarodiagnostic.Unavailable(prefix+"_enrollment", "repair_"+prefix+"_access"), punarodiagnostic.Unavailable(prefix+"_protocol", "repair_"+prefix+"_access"))
	}
	checks = append(checks, telegramBoolCheck(result.Enrolled, prefix+"_enrollment", "repair_"+prefix+"_enrollment"))
	if !result.Enrolled {
		return append(checks, punarodiagnostic.Unavailable(prefix+"_protocol", "repair_"+prefix+"_enrollment"))
	}
	return append(checks, telegramBoolCheck(result.Protocol, prefix+"_protocol", "install_compatible_release"))
}

func telegramBoolCheck(ok bool, code, remediation string) punarodiagnostic.Check {
	if ok {
		return punarodiagnostic.Pass(code)
	}
	return punarodiagnostic.Fail(code, remediation)
}

func writeTelegramDoctorReport(stdout, stderr io.Writer, report punarodiagnostic.Report, err error) int {
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-telegram doctor failed: diagnostic report unavailable")
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if encoder.Encode(report) != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-telegram doctor failed: diagnostic report unavailable")
		return 2
	}
	return punarodiagnostic.ExitCode(report)
}

func inspectTelegramService(ctx context.Context) telegramServiceDoctorResult {
	result := telegramServiceDoctorResult{}
	executable := telegramServiceExecutable(runtime.GOOS, strings.TrimSpace(os.Getenv("LOCALAPPDATA")))
	if executable == "" {
		return result
	}
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return result
		}
		installedPath := filepath.Join(home, "Library", "LaunchAgents", "org.punaro.telegram.plist")
		result.Installed, result.Executable = inspectTelegramServiceDefinition(ctx, installedPath, executable, "darwin")
		effective, loaded := telegramServiceCommand(ctx, "launchctl", "print", "gui/"+strconv.Itoa(os.Getuid())+"/org.punaro.telegram")
		result.Executable = result.Executable && loaded && telegramLaunchdEffectiveBound(effective)
		result.Enabled, result.Running, result.ExitStatus, result.RestartState = inspectTelegramLaunchdServiceManager(effective, loaded)
	case "linux":
		result.Installed, result.Executable = inspectTelegramServiceDefinition(ctx, "/etc/systemd/system/punaro-telegram.service", executable, "linux")
		effectiveExecStart, effectiveKnown := telegramServiceCommand(ctx, "systemctl", "show", "--property=ExecStart", "--value", "punaro-telegram.service")
		result.Executable = result.Executable && effectiveKnown && telegramSystemdExecStartBound(effectiveExecStart, executable)
		_, result.Enabled = telegramServiceCommand(ctx, "systemctl", "is-enabled", "--quiet", "punaro-telegram.service")
		_, result.Running = telegramServiceCommand(ctx, "systemctl", "is-active", "--quiet", "punaro-telegram.service")
		exit, exitOK := telegramServiceCommand(ctx, "systemctl", "show", "--property=ExecMainStatus", "--value", "punaro-telegram.service")
		serviceResult, resultOK := telegramServiceCommand(ctx, "systemctl", "show", "--property=Result", "--value", "punaro-telegram.service")
		result.ExitStatus = exitOK && strings.TrimSpace(exit) == "0"
		result.RestartState = resultOK && strings.TrimSpace(serviceResult) == "success"
	case "windows":
		task, taskOK := telegramServiceCommand(ctx, "schtasks.exe", "/Query", "/TN", "Punaro Telegram", "/XML")
		result.Installed = taskOK
		result.Executable = taskOK && telegramServiceExecutableSafe(ctx, executable, "windows") && telegramWindowsTaskBound(task, executable)
		state, stateOK := telegramServiceCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-ScheduledTask -TaskName 'Punaro Telegram').State")
		last, lastOK := telegramServiceCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-ScheduledTaskInfo -TaskName 'Punaro Telegram').LastTaskResult")
		restarts, restartOK := telegramServiceCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-ScheduledTask -TaskName 'Punaro Telegram').Settings.RestartCount")
		canonicalState := strings.TrimSpace(state)
		result.Enabled = stateOK && canonicalState != "Disabled"
		result.Running = stateOK && canonicalState == "Running"
		result.ExitStatus = result.Running || lastOK && strings.TrimSpace(last) == "0"
		restartCount, restartErr := strconv.Atoi(strings.TrimSpace(restarts))
		result.RestartState = restartOK && restartErr == nil && restartCount > 0
	default:
		return result
	}
	if result.Executable {
		release, ok := telegramExecutableVersion(ctx, executable)
		result.Release = result.Running && telegramBuildRelease != "" && release == telegramBuildRelease
		if !ok {
			result.Release = false
		}
	}
	return result
}

func inspectTelegramLaunchdServiceManager(output string, loaded bool) (bool, bool, bool, bool) {
	running := loaded && strings.Contains(output, "state = running")
	exitOK := running || loaded && strings.Contains(output, "last exit code = 0")
	restartOK := loaded && strings.Contains(output, "runs =")
	return loaded, running, exitOK, restartOK
}

func inspectTelegramServiceIsolated(ctx context.Context) telegramServiceDoctorResult {
	if ctx == nil || ctx.Err() != nil {
		return telegramServiceDoctorResult{}
	}
	executable, err := telegramDoctorServiceExecutable()
	if err != nil {
		return telegramServiceDoctorResult{}
	}
	command := exec.CommandContext(ctx, executable, "doctor-service-inspect") // #nosec G204,G702 -- os.Executable self helper with no caller-controlled arguments.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedTelegramOutput{maximum: maximumTelegramStateOutput}
	command.Stdout = &output
	if command.Run() != nil || ctx.Err() != nil || output.overflow {
		return telegramServiceDoctorResult{}
	}
	decoder := json.NewDecoder(strings.NewReader(output.buffer.String()))
	decoder.DisallowUnknownFields()
	var result telegramServiceDoctorResult
	if decoder.Decode(&result) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return telegramServiceDoctorResult{}
	}
	return result
}

func runTelegramServiceInspect(args []string, stdout io.Writer) int {
	if len(args) != 0 {
		return 2
	}
	if json.NewEncoder(stdout).Encode(inspectTelegramService(context.Background())) != nil {
		return 1
	}
	return 0
}

func telegramServiceExecutable(goos, localAppData string) string {
	switch goos {
	case "darwin", "linux":
		return "/usr/local/bin/punaro-telegram"
	case "windows":
		if localAppData == "" || !filepath.IsAbs(localAppData) || filepath.Clean(localAppData) != localAppData {
			return ""
		}
		return filepath.Join(localAppData, "Punaro", "bin", "punaro-telegram.exe")
	default:
		return ""
	}
}

func inspectTelegramServiceDefinition(ctx context.Context, definition, executable, goos string) (bool, bool) {
	info, err := os.Lstat(definition) // #nosec G703 -- fixed platform service definition.
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, false
	}
	body, err := incrementalfs.ReadFile(ctx, definition, 64<<10)
	return true, err == nil && telegramServiceFileBound(goos, string(body)) && telegramServiceExecutableSafe(ctx, executable, goos)
}

func telegramServiceExecutableSafe(ctx context.Context, executable, goos string) bool {
	if ctx.Err() != nil || executable == "" || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return false
	}
	info, err := os.Lstat(executable) // #nosec G703 -- fixed platform-installed gateway executable.
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && (goos == "windows" || info.Mode().Perm()&0o111 != 0)
}

func telegramWindowsTaskBound(body, executable string) bool {
	if len(body) > 64<<10 || executable == "" {
		return false
	}
	var task struct {
		Actions struct {
			Exec []struct {
				Command   string `xml:"Command"`
				Arguments string `xml:"Arguments"`
			} `xml:"Exec"`
		} `xml:"Actions"`
	}
	decoder := xml.NewDecoder(strings.NewReader(body))
	if decoder.Decode(&task) != nil || len(task.Actions.Exec) != 1 {
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
	action := task.Actions.Exec[0]
	return strings.EqualFold(filepath.Clean(strings.TrimSpace(action.Command)), filepath.Clean(executable)) && strings.TrimSpace(action.Arguments) == ""
}

func telegramServiceCommand(ctx context.Context, executable string, arguments ...string) (string, bool) {
	command := exec.CommandContext(ctx, executable, arguments...) // #nosec G204 -- fixed read-only service inspection.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedTelegramOutput{maximum: 64 << 10}
	command.Stdout = &output
	if err := command.Run(); err != nil || output.overflow {
		return "", false
	}
	return output.buffer.String(), true
}

func telegramServiceFileBound(goos, body string) bool {
	switch goos {
	case "linux":
		count := 0
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) == "ExecStart=/usr/local/bin/punaro-telegram" {
				count++
			}
		}
		return count == 1
	case "darwin":
		return telegramLaunchdPlistBound(body)
	case "windows":
		return strings.Count(body, "punaro-telegram.exe") == 1
	default:
		return false
	}
}

func telegramLaunchdPlistBound(body string) bool {
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
		key, ok := decodeTelegramXMLString(decoder, keyStart)
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
			value, valid := decodeTelegramXMLString(decoder, valueStart)
			labelOK = valid && valueStart.Name.Local == "string" && value == "org.punaro.telegram"
		case "ProgramArguments":
			arguments, valid := decodeTelegramXMLStringArray(decoder, valueStart)
			argumentsOK = valid && slices.Equal(arguments, telegramLaunchdArguments())
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

func decodeTelegramXMLString(decoder *xml.Decoder, start xml.StartElement) (string, bool) {
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

func decodeTelegramXMLStringArray(decoder *xml.Decoder, start xml.StartElement) ([]string, bool) {
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
			value, ok := decodeTelegramXMLString(decoder, token)
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

func telegramLaunchdArguments() []string {
	return []string{"/usr/local/bin/punaro-telegram"}
}

func telegramLaunchdEffectiveBound(body string) bool {
	if len(body) > 64<<10 {
		return false
	}
	lines := strings.Split(body, "\n")
	var arguments []string
	inArguments, complete, programCount, argumentsCount := false, false, 0, 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "program = /usr/local/bin/punaro-telegram" {
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
	return programCount == 1 && argumentsCount == 1 && complete && !inArguments && slices.Equal(arguments, telegramLaunchdArguments())
}

func telegramSystemdExecStartBound(body, executable string) bool {
	if executable == "" || len(body) > 64<<10 {
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
	return fields["path"] == executable && fields["argv[]"] == executable
}

func telegramExecutableVersion(ctx context.Context, executable string) (string, bool) {
	command := exec.CommandContext(ctx, executable, "version") // #nosec G204 -- caller supplies the fixed installed gateway executable or a test fixture.
	command.Stdin = nil
	command.Stderr = io.Discard
	output := boundedTelegramOutput{maximum: maximumServiceVersionOutput}
	command.Stdout = &output
	if err := command.Run(); err != nil || output.overflow {
		return "", false
	}
	release := strings.TrimSpace(output.buffer.String())
	if release == "" || strings.ContainsAny(release, "\r\n\t ") {
		return "", false
	}
	return release, true
}
