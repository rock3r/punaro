package main

import (
	"context"
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
	punarodiagnostic "github.com/rock3r/punaro/internal/diagnostic"
	"github.com/rock3r/punaro/internal/relay"
	"github.com/rock3r/punaro/internal/telegram"
)

const (
	defaultTelegramDoctorTimeout = 15 * time.Second
	maximumTelegramDoctorTimeout = 30 * time.Second
	maximumHealthyCycleAge       = 2 * time.Minute
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

var (
	telegramDoctorNow        = time.Now
	telegramDoctorRelayProbe = func(ctx context.Context, cfg config) (adapter.DoctorProbeResult, error) {
		client, err := adapter.NewHTTPRelayClientWithPolicy(cfg.relayURL, cfg.machineID, cfg.privateKey, nil, cfg.accessToken, cfg.transportPolicy)
		if err != nil {
			return adapter.DoctorProbeResult{}, errors.New("relay doctor unavailable")
		}
		return client.DoctorEndpoint(ctx, cfg.endpoint)
	}
	telegramDoctorNotificationProbe = func(ctx context.Context, cfg config) (adapter.DoctorProbeResult, error) {
		client, err := adapter.NewHTTPRelayClientWithPolicy(cfg.relayURL, cfg.machineID, cfg.privateKey, nil, cfg.accessToken, cfg.transportPolicy)
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
	telegramDoctorServiceProbe = inspectTelegramService
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
	cfg, err := loadConfig()
	if err != nil {
		report, reportErr := punarodiagnostic.New(punarodiagnostic.ComponentTelegram, punarodiagnostic.Identity{Platform: runtime.GOOS + "-" + runtime.GOARCH}, telegramUnavailableChecks())
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

	snapshot, stateErr := telegram.InspectGatewayState(filepath.Join(cfg.stateDir, "telegram.db"), telegramDoctorNow().UTC())
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
			telegramBoolCheck(snapshot.LastFailure != telegram.GatewayFailureDeletedTopic, "deleted_topic_target", "repair_deleted_topic_route"),
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
	report, reportErr := punarodiagnostic.New(punarodiagnostic.ComponentTelegram, identity, checks)
	return writeTelegramDoctorReport(stdout, stderr, report, reportErr)
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
	home, err := os.UserHomeDir()
	if err != nil {
		return telegramServiceDoctorResult{}
	}
	result := telegramServiceDoctorResult{}
	var installedPath string
	var commands [][]string
	switch runtime.GOOS {
	case "darwin":
		installedPath = filepath.Join(home, "Library", "LaunchAgents", "org.punaro.telegram.plist")
		commands = [][]string{{"launchctl", "print", "gui/" + strconv.Itoa(os.Getuid()) + "/org.punaro.telegram"}}
	case "linux":
		installedPath = "/etc/systemd/system/punaro-telegram.service"
		commands = [][]string{{"systemctl", "is-enabled", "--quiet", "punaro-telegram.service"}, {"systemctl", "is-active", "--quiet", "punaro-telegram.service"}}
	case "windows":
		commands = [][]string{{"schtasks.exe", "/Query", "/TN", "Punaro Telegram"}}
	default:
		return result
	}
	if installedPath == "" {
		result.Installed = true
	} else if info, statErr := os.Lstat(installedPath); statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		result.Installed = true
		// #nosec G304 -- fixed service definition selected only by the local platform.
		if body, readErr := os.ReadFile(installedPath); readErr == nil && len(body) <= 64<<10 {
			result.Executable = telegramServiceFileBound(runtime.GOOS, string(body))
		}
	}
	succeeded := make([]bool, len(commands))
	for index, arguments := range commands {
		command := exec.CommandContext(ctx, arguments[0], arguments[1:]...) // #nosec G204 -- fixed read-only service inspection.
		command.Stdout, command.Stderr = io.Discard, io.Discard
		succeeded[index] = command.Run() == nil
	}
	if runtime.GOOS == "linux" {
		result.Enabled = len(succeeded) == 2 && succeeded[0]
		result.Running = len(succeeded) == 2 && succeeded[1]
	} else {
		result.Enabled = result.Installed
		result.Running = len(succeeded) == 1 && succeeded[0]
	}
	if runtime.GOOS == "linux" {
		exit, exitOK := telegramServiceCommand(ctx, "systemctl", "show", "--property=ExecMainStatus", "--value", "punaro-telegram.service")
		serviceResult, resultOK := telegramServiceCommand(ctx, "systemctl", "show", "--property=Result", "--value", "punaro-telegram.service")
		result.ExitStatus = exitOK && strings.TrimSpace(exit) == "0"
		result.RestartState = resultOK && strings.TrimSpace(serviceResult) == "success"
	} else {
		result.ExitStatus = result.Running
		result.RestartState = result.Running
	}
	if release, ok := telegramServiceVersion(ctx); ok {
		result.Release = result.Running && telegramBuildRelease != "" && release == telegramBuildRelease
	}
	return result
}

func telegramServiceCommand(ctx context.Context, executable string, arguments ...string) (string, bool) {
	command := exec.CommandContext(ctx, executable, arguments...) // #nosec G204 -- fixed read-only service inspection.
	command.Stdin = nil
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil || len(output) > 64<<10 {
		return "", false
	}
	return string(output), true
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
		return strings.Count(body, "/usr/local/bin/punaro-telegram") == 1
	case "windows":
		return strings.Count(body, "punaro-telegram.exe") == 1
	default:
		return false
	}
}

func telegramServiceVersion(ctx context.Context) (string, bool) {
	command := exec.CommandContext(ctx, "/usr/local/bin/punaro-telegram", "version") // #nosec G204 -- fixed installed gateway executable.
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil || len(output) > 256 || strings.Contains(strings.TrimSpace(string(output)), "\n") {
		return "", false
	}
	return strings.TrimSpace(string(output)), true
}
