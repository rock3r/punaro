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
	"github.com/rock3r/punaro/internal/telegram"
)

const defaultTelegramAPIURL = "https://api.telegram.org"

type config struct {
	relayURL      string
	machineID     string
	privateKey    ed25519.PrivateKey
	botToken      string
	allowedUserID int64
	endpoint      string
	stateDir      string
	apiURL        string
	accessToken   adapter.AccessServiceToken
}

type routeRequest struct {
	chatID       int64
	threadID     int64
	conversation string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "route" {
		if err := runRoute(os.Args[2:]); err != nil {
			log.Printf("punaro-telegram stopped: %v", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 {
		log.Print("punaro-telegram stopped: unknown command (supported: route)")
		os.Exit(1)
	}
	if err := run(); err != nil {
		log.Printf("punaro-telegram stopped: %v", err)
		os.Exit(1)
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
	relayClient, err := adapter.NewHTTPRelayClient(cfg.relayURL, cfg.machineID, cfg.privateKey, nil, cfg.accessToken)
	if err != nil {
		return err
	}
	botClient, err := telegram.NewClient(cfg.apiURL, cfg.botToken, nil)
	if err != nil {
		return err
	}
	bridge := telegram.Bridge{
		Relay:    relayClient,
		Endpoint: cfg.endpoint,
		State:    state,
		Poller:   botClient,
		Gateway:  telegram.Gateway{AllowedUserID: cfg.allowedUserID, State: state, Submit: telegram.SubmitToRelay(relayClient, cfg.endpoint)},
		Sender:   botClient,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var offset int64
	for ctx.Err() == nil {
		next, err := bridge.SyncOnce(ctx, offset)
		if err == nil {
			offset = next
			continue
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
	if cfg.relayURL == "" || cfg.machineID == "" || cfg.botToken == "" || cfg.endpoint == "" || cfg.stateDir == "" {
		return config{}, fmt.Errorf("PUNARO_ADAPTER_RELAY_URL, PUNARO_MACHINE_ID, PUNARO_TELEGRAM_BOT_TOKEN, PUNARO_TELEGRAM_GATEWAY_ENDPOINT, and PUNARO_TELEGRAM_STATE_DIR are required")
	}
	if (cfg.accessToken.ClientID == "") != (cfg.accessToken.ClientSecret == "") {
		return config{}, fmt.Errorf("both PUNARO_CF_ACCESS_CLIENT_ID and PUNARO_CF_ACCESS_CLIENT_SECRET are required together")
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

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	// #nosec G304,G703 -- the local operator explicitly selects this private
	// credential path through configuration; remote inputs never control it.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read machine private key: %w", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("machine private key must be a base64url Ed25519 private key")
	}
	return ed25519.PrivateKey(decoded), nil
}
