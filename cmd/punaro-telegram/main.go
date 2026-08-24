// punaro-telegram bridges one enrolled relay endpoint to one restricted
// Telegram bot identity and its explicitly mapped topics.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rock3r/punaro/internal/adapter"
	"github.com/rock3r/punaro/internal/clienttransport"
	"github.com/rock3r/punaro/internal/relay"
	"github.com/rock3r/punaro/internal/telegram"
)

const defaultTelegramAPIURL = "https://api.telegram.org"

type config struct {
	relayURL        string
	machineID       string
	privateKey      ed25519.PrivateKey
	botToken        string
	allowedUserID   int64
	endpoint        string
	stateDir        string
	apiURL          string
	accessToken     adapter.AccessServiceToken
	transportPolicy clienttransport.Policy
	privateKeyFile  string
	botTokenFile    string
	accessTokenFile string
}

type routeRequest struct {
	chatID       int64
	threadID     int64
	conversation string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		if len(os.Args) != 2 || telegramBuildRelease == "" {
			os.Exit(1)
		}
		fmt.Println(telegramBuildRelease)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "doctor" {
		os.Exit(runTelegramDoctor(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "doctor-state-inspect" {
		os.Exit(runTelegramStateInspect(os.Args[2:], os.Stdout))
	}
	if len(os.Args) > 1 && os.Args[1] == "route" {
		if err := runRoute(os.Args[2:]); err != nil {
			log.Printf("punaro-telegram stopped: %v", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "adopt" {
		if err := runAdopt(os.Args[2:]); err != nil {
			log.Printf("punaro-telegram stopped: %v", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 {
		log.Print("punaro-telegram stopped: unknown command (supported: doctor, route, adopt, version)")
		os.Exit(1)
	}
	if err := run(); err != nil {
		log.Printf("punaro-telegram stopped: %v", err)
		os.Exit(1)
	}
}

func registerOperatorCommands(ctx context.Context, register func(context.Context, []telegram.BotCommand) error) {
	if err := register(ctx, telegram.DefaultBotCommands()); err != nil {
		// Menu registration is operator UX, not a prerequisite for poll/lease.
		log.Printf("telegram event class=telegram_command cmd=setMyCommands err=register_failed")
	}
}

func parseRoute(args []string) (routeRequest, error) {
	flags := flag.NewFlagSet("punaro-telegram route", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request routeRequest
	flags.Int64Var(&request.chatID, "chat-id", 0, "Telegram chat ID")
	flags.Int64Var(&request.threadID, "thread-id", 0, "Telegram message thread ID")
	flags.StringVar(&request.conversation, "conversation", "", "Punaro conversation ID")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || request.chatID == 0 || request.threadID <= 0 || strings.TrimSpace(request.conversation) == "" {
		return routeRequest{}, fmt.Errorf("--chat-id, --thread-id, and --conversation are required")
	}
	return request, nil
}

func parseAdopt(args []string) (string, error) {
	flags := flag.NewFlagSet("punaro-telegram adopt", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var conversation string
	flags.StringVar(&conversation, "conversation", "", "Punaro conversation ID")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || strings.TrimSpace(conversation) == "" {
		return "", fmt.Errorf("--conversation is required")
	}
	return conversation, nil
}

func runRoute(args []string) error {
	request, err := parseRoute(args)
	if err != nil {
		return err
	}
	stateDir := strings.TrimSpace(os.Getenv("PUNARO_TELEGRAM_STATE_DIR"))
	if stateDir == "" {
		return fmt.Errorf("PUNARO_TELEGRAM_STATE_DIR is required")
	}
	state, err := telegram.Open(filepath.Join(stateDir, "telegram.db"))
	if err != nil {
		return err
	}
	defer func() { _ = state.Close() }()
	return state.SetRoute(request.chatID, request.threadID, request.conversation)
}

func runAdopt(args []string) error {
	conversation, err := parseAdopt(args)
	if err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	state, err := telegram.Open(filepath.Join(cfg.stateDir, "telegram.db"))
	if err != nil {
		return err
	}
	defer func() { _ = state.Close() }()
	relayClient, err := adapter.NewHTTPRelayClientWithPolicy(cfg.relayURL, cfg.machineID, cfg.privateKey, nil, cfg.accessToken, cfg.transportPolicy)
	if err != nil {
		return err
	}
	return telegram.Adopt(context.Background(), state, relayClient, conversation, cfg.allowedUserID, nil)
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	state, err := telegram.Open(filepath.Join(cfg.stateDir, "telegram.db"))
	if err != nil {
		return err
	}
	defer func() { _ = state.Close() }()
	relayClient, err := adapter.NewHTTPRelayClientWithPolicy(cfg.relayURL, cfg.machineID, cfg.privateKey, nil, cfg.accessToken, cfg.transportPolicy)
	if err != nil {
		return err
	}
	botClient, err := telegram.NewClient(cfg.apiURL, cfg.botToken, nil)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	registerOperatorCommands(ctx, botClient.SetMyCommands)
	claims := &telegram.ClaimExecutor{
		State:         state,
		Relay:         relayClient,
		Topics:        botClient,
		AllowedUserID: cfg.allowedUserID,
	}
	bridge := telegram.Bridge{
		Relay:    relayClient,
		Endpoint: cfg.endpoint,
		State:    state,
		Poller:   botClient,
		Gateway: telegram.Gateway{
			AllowedUserID: cfg.allowedUserID,
			State:         state,
			Submit:        telegram.SubmitToRelay(relayClient, cfg.endpoint, state, nil),
			ListUnclaimed: relayClient.ListUnclaimed,
			Notify:        botClient,
			Claims:        claims,
		},
		Sender: botClient,
		Claims: claims,
	}
	var offset int64
	for ctx.Err() == nil {
		next, err := bridge.SyncOnce(ctx, offset)
		if err == nil {
			if recordErr := state.RecordGatewayCycle(telegram.GatewayCycleRecord{At: time.Now().UTC(), Offset: next, PollOK: true, RelayOK: true, TelegramOK: true}); recordErr != nil {
				err = recordErr
			} else {
				offset = next
				continue
			}
		} else {
			record := failedGatewayCycleRecord(time.Now().UTC(), next, err)
			if recordErr := state.RecordGatewayCycle(record); recordErr != nil {
				log.Print("telegram event class=gateway_health err=state_unavailable")
			}
		}
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return nil
		}
		// Errors omit Telegram bodies, tokens, Access headers, and relay URL.
		log.Printf("telegram bridge cycle failed: %v", err)
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

func failedGatewayCycleRecord(at time.Time, offset int64, err error) telegram.GatewayCycleRecord {
	record := telegram.GatewayCycleRecord{At: at, Offset: offset, Failure: telegram.ClassifyGatewayCycleFailure(err)}
	var cycleErr *telegram.GatewayCycleError
	if errors.As(err, &cycleErr) {
		record.OutboundBlocked = cycleErr.OutboundBlocked
		record.OutboundProgress = cycleErr.OutboundProgress
		switch cycleErr.Phase {
		case telegram.GatewayPhaseInbound, telegram.GatewayPhaseLease:
			record.PollOK = true
		case telegram.GatewayPhaseSend:
			record.PollOK, record.RelayOK = true, true
		case telegram.GatewayPhaseAck:
			record.PollOK, record.RelayOK, record.TelegramOK = true, true, true
		}
	}
	return record
}

func loadConfig() (config, error) {
	cfg := config{
		relayURL:  strings.TrimSpace(os.Getenv("PUNARO_ADAPTER_RELAY_URL")),
		machineID: strings.TrimSpace(os.Getenv("PUNARO_MACHINE_ID")),
		botToken:  strings.TrimSpace(os.Getenv("PUNARO_TELEGRAM_BOT_TOKEN")),
		endpoint:  strings.TrimSpace(os.Getenv("PUNARO_TELEGRAM_GATEWAY_ENDPOINT")),
		stateDir:  strings.TrimSpace(os.Getenv("PUNARO_TELEGRAM_STATE_DIR")),
		apiURL:    strings.TrimSpace(os.Getenv("PUNARO_TELEGRAM_API_URL")),
		accessToken: adapter.AccessServiceToken{
			ClientID:     strings.TrimSpace(os.Getenv("PUNARO_CF_ACCESS_CLIENT_ID")),
			ClientSecret: strings.TrimSpace(os.Getenv("PUNARO_CF_ACCESS_CLIENT_SECRET")),
		},
	}
	if cfg.apiURL == "" {
		cfg.apiURL = defaultTelegramAPIURL
	}
	botTokenFile := strings.TrimSpace(os.Getenv("PUNARO_TELEGRAM_BOT_TOKEN_FILE"))
	cfg.botTokenFile = botTokenFile
	if (cfg.botToken == "") == (botTokenFile == "") {
		return config{}, fmt.Errorf("exactly one of PUNARO_TELEGRAM_BOT_TOKEN or PUNARO_TELEGRAM_BOT_TOKEN_FILE is required")
	}
	if botTokenFile != "" {
		botToken, err := readPrivateFile(botTokenFile, "Telegram bot token", 4<<10)
		if err != nil {
			return config{}, err
		}
		cfg.botToken = strings.TrimSpace(string(botToken))
		if cfg.botToken == "" {
			return config{}, fmt.Errorf("telegram bot token file is empty")
		}
	}
	if cfg.relayURL == "" || cfg.machineID == "" || cfg.botToken == "" || cfg.endpoint == "" || cfg.stateDir == "" {
		return config{}, fmt.Errorf("PUNARO_ADAPTER_RELAY_URL, PUNARO_MACHINE_ID, Telegram bot token source, PUNARO_TELEGRAM_GATEWAY_ENDPOINT, and PUNARO_TELEGRAM_STATE_DIR are required")
	}
	if cfg.endpoint != relay.TelegramGatewayEndpoint {
		return config{}, fmt.Errorf("PUNARO_TELEGRAM_GATEWAY_ENDPOINT must be %s", relay.TelegramGatewayEndpoint)
	}
	accessTokenFile := strings.TrimSpace(os.Getenv("PUNARO_TELEGRAM_ACCESS_TOKEN_FILE"))
	cfg.accessTokenFile = accessTokenFile
	if accessTokenFile != "" {
		if cfg.accessToken.ClientID != "" || cfg.accessToken.ClientSecret != "" {
			return config{}, fmt.Errorf("PUNARO_TELEGRAM_ACCESS_TOKEN_FILE cannot be combined with Access environment credentials")
		}
		accessToken, err := loadAccessTokenFile(accessTokenFile)
		if err != nil {
			return config{}, err
		}
		cfg.accessToken = accessToken
	}
	if (cfg.accessToken.ClientID == "") != (cfg.accessToken.ClientSecret == "") {
		return config{}, fmt.Errorf("both PUNARO_CF_ACCESS_CLIENT_ID and PUNARO_CF_ACCESS_CLIENT_SECRET are required together")
	}
	allowLANHTTP, err := parseLANHTTP(strings.TrimSpace(os.Getenv("PUNARO_ADAPTER_ALLOW_LAN_HTTP")))
	if err != nil {
		return config{}, err
	}
	cfg.transportPolicy = clienttransport.Policy{AllowLANHTTP: allowLANHTTP, TrustedLANCIDR: strings.TrimSpace(os.Getenv("PUNARO_ADAPTER_TRUSTED_LAN_CIDR"))}
	if _, err := clienttransport.ValidateOrigin(cfg.relayURL, cfg.transportPolicy); err != nil {
		return config{}, fmt.Errorf("telegram relay transport policy is invalid")
	}
	allowedUserID, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("PUNARO_TELEGRAM_ALLOWED_USER_ID")), 10, 64)
	if err != nil || allowedUserID == 0 {
		return config{}, fmt.Errorf("PUNARO_TELEGRAM_ALLOWED_USER_ID must be a non-zero integer")
	}
	cfg.allowedUserID = allowedUserID
	keyFile := strings.TrimSpace(os.Getenv("PUNARO_MACHINE_PRIVATE_KEY_FILE"))
	if keyFile == "" {
		return config{}, fmt.Errorf("PUNARO_MACHINE_PRIVATE_KEY_FILE is required")
	}
	cfg.privateKeyFile = keyFile
	privateKey, err := loadPrivateKey(keyFile)
	if err != nil {
		return config{}, err
	}
	cfg.privateKey = privateKey
	absolute, err := filepath.Abs(cfg.stateDir)
	if err != nil {
		return config{}, fmt.Errorf("resolve telegram state directory: %w", err)
	}
	cfg.stateDir = absolute
	return cfg, nil
}

func parseLANHTTP(raw string) (bool, error) {
	switch raw {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("PUNARO_ADAPTER_ALLOW_LAN_HTTP must be true or false")
	}
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	// #nosec G304,G703 -- the local operator explicitly selects this private
	// credential path through configuration; remote inputs never control it.
	raw, err := readPrivateFile(path, "machine private key", 4<<10)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("machine private key must be a base64url Ed25519 private key")
	}
	return ed25519.PrivateKey(decoded), nil
}

func loadAccessTokenFile(path string) (adapter.AccessServiceToken, error) {
	raw, err := readPrivateFile(path, "Access token", 4<<10)
	if err != nil {
		return adapter.AccessServiceToken{}, err
	}
	values := make(map[string]string, 2)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || value == "" || (key != "PUNARO_CF_ACCESS_CLIENT_ID" && key != "PUNARO_CF_ACCESS_CLIENT_SECRET") {
			return adapter.AccessServiceToken{}, fmt.Errorf("invalid Access token file")
		}
		if _, duplicate := values[key]; duplicate {
			return adapter.AccessServiceToken{}, fmt.Errorf("invalid Access token file")
		}
		values[key] = value
	}
	token := adapter.AccessServiceToken{ClientID: values["PUNARO_CF_ACCESS_CLIENT_ID"], ClientSecret: values["PUNARO_CF_ACCESS_CLIENT_SECRET"]}
	if token.ClientID == "" || token.ClientSecret == "" {
		return adapter.AccessServiceToken{}, fmt.Errorf("invalid Access token file")
	}
	return token, nil
}
