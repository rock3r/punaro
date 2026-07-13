// punaro-adapter synchronizes one enrolled machine's local agent-mailbox
// attachment group with the central Punaro relay.
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
	"strings"
	"syscall"
	"time"

	"github.com/rock3r/punaro/internal/adapter"
	"github.com/rock3r/punaro/internal/relay"
)

type adapterConfig struct {
	relayURL      string
	machineID     string
	privateKey    ed25519.PrivateKey
	attachedGroup string
	mailboxBinary string
	mailboxState  string
	dataDir       string
	pollInterval  time.Duration
	accessToken   adapter.AccessServiceToken
}

func main() {
	var err error
	switch {
	case len(os.Args) == 1:
		err = run()
	case os.Args[1] == "send":
		err = runSend(os.Args[2:])
	case os.Args[1] == "create":
		err = runCreate(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q (supported: send, create)", os.Args[1])
	}
	if err != nil {
		log.Printf("punaro-adapter stopped: %v", err)
		os.Exit(1)
	}
}

type createRequest struct {
	creator        string
	members        []relay.Member
	idempotencyKey string
}
type memberFlags []string

func (m *memberFlags) String() string         { return strings.Join(*m, ",") }
func (m *memberFlags) Set(value string) error { *m = append(*m, value); return nil }

func parseCreateArgs(args []string) (createRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request createRequest
	var members memberFlags
	flags.StringVar(&request.creator, "creator", "", "attached creator endpoint")
	flags.Var(&members, "member", "endpoint:send,receive,admin (repeatable)")
	flags.StringVar(&request.idempotencyKey, "idempotency-key", "", "stable retry key")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || request.creator == "" || request.idempotencyKey == "" || len(members) == 0 {
		return createRequest{}, fmt.Errorf("--creator, at least one --member, and --idempotency-key are required")
	}
	for _, raw := range members {
		endpoint, permissions, found := strings.Cut(raw, ":")
		if !found || endpoint == "" || permissions == "" {
			return createRequest{}, fmt.Errorf("invalid --member")
		}
		var capability relay.Capability
		for _, item := range strings.Split(permissions, ",") {
			switch item {
			case "send":
				capability |= relay.CapSend
			case "receive":
				capability |= relay.CapReceive
			case "admin":
				capability |= relay.CapAdmin
			default:
				return createRequest{}, fmt.Errorf("invalid member capability")
			}
		}
		if capability == 0 {
			return createRequest{}, fmt.Errorf("invalid member capability")
		}
		request.members = append(request.members, relay.Member{Endpoint: endpoint, Capabilities: capability})
	}
	return request, nil
}

func runCreate(args []string) error {
	request, err := parseCreateArgs(args)
	if err != nil {
		return err
	}
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	client, err := adapter.NewHTTPRelayClient(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken)
	if err != nil {
		return err
	}
	conversation, err := client.CreateConversation(context.Background(), request.creator, request.members, request.idempotencyKey)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"id\":%q}\n", conversation.ID)
	return err
}

type sendRequest struct {
	conversationID string
	fromEndpoint   string
	bodyFile       string
	idempotencyKey string
}

func parseSendArgs(args []string) (sendRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter send", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request sendRequest
	flags.StringVar(&request.conversationID, "conversation", "", "conversation ID")
	flags.StringVar(&request.fromEndpoint, "from", "", "attached sender endpoint")
	flags.StringVar(&request.bodyFile, "body-file", "", "message body file or - for stdin")
	flags.StringVar(&request.idempotencyKey, "idempotency-key", "", "stable key for retries")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return sendRequest{}, fmt.Errorf("invalid send arguments")
	}
	if strings.TrimSpace(request.conversationID) == "" || strings.TrimSpace(request.fromEndpoint) == "" || request.bodyFile == "" || strings.TrimSpace(request.idempotencyKey) == "" {
		return sendRequest{}, fmt.Errorf("--conversation, --from, --body-file, and --idempotency-key are required")
	}
	return request, nil
}

func runSend(args []string) error {
	request, err := parseSendArgs(args)
	if err != nil {
		return err
	}
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	body, err := readMessageBody(request.bodyFile)
	if err != nil {
		return err
	}
	client, err := adapter.NewHTTPRelayClient(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken)
	if err != nil {
		return err
	}
	message, err := client.Send(context.Background(), request.conversationID, request.fromEndpoint, string(body), request.idempotencyKey)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"id\":%q,\"sequence\":%d}\n", message.ID, message.Sequence)
	return err
}

func readMessageBody(path string) ([]byte, error) {
	var reader io.Reader
	if path == "-" {
		reader = os.Stdin
	} else {
		// #nosec G304 -- the local caller explicitly names a message file; no
		// remote message or relay response controls this path.
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("read message body: %w", err)
		}
		defer func() { _ = file.Close() }()
		reader = file
	}
	body, err := io.ReadAll(io.LimitReader(reader, 32<<10+1))
	if err != nil || len(body) > 32<<10 {
		return nil, fmt.Errorf("message body exceeds 32768 bytes")
	}
	return body, nil
}

func run() error {
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	mailbox, err := adapter.NewCLIMailbox(config.mailboxBinary, config.mailboxState, config.attachedGroup)
	if err != nil {
		return err
	}
	relayClient, err := adapter.NewHTTPRelayClient(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken)
	if err != nil {
		return err
	}
	journal, err := adapter.OpenJournal(filepath.Join(config.dataDir, "adapter.db"))
	if err != nil {
		return err
	}
	defer func() { _ = journal.Close() }()
	syncer := adapter.Syncer{Mailbox: mailbox, Relay: relayClient, Journal: journal}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	wake := make(chan struct{}, 1)
	go runNotifications(ctx, relayClient, wake)
	for {
		if err := syncer.SyncOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			// Errors deliberately omit remote and mailbox output bodies.
			log.Printf("synchronization failed: %v", err)
		}
		timer := time.NewTimer(config.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
	}
}

func runNotifications(ctx context.Context, client *adapter.HTTPRelayClient, wake chan<- struct{}) {
	backoff := time.Second
	for ctx.Err() == nil {
		_ = client.ReadNotifications(ctx, func(_ relay.WakeEvent) {
			select {
			case wake <- struct{}{}:
			default:
			}
		})
		if ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func loadConfig() (adapterConfig, error) {
	relayURL := strings.TrimSpace(os.Getenv("PUNARO_ADAPTER_RELAY_URL"))
	machineID := strings.TrimSpace(os.Getenv("PUNARO_MACHINE_ID"))
	keyFile := strings.TrimSpace(os.Getenv("PUNARO_MACHINE_PRIVATE_KEY_FILE"))
	group := strings.TrimSpace(os.Getenv("PUNARO_ATTACHED_GROUP"))
	if relayURL == "" || machineID == "" || keyFile == "" || group == "" {
		return adapterConfig{}, fmt.Errorf("PUNARO_ADAPTER_RELAY_URL, PUNARO_MACHINE_ID, PUNARO_MACHINE_PRIVATE_KEY_FILE, and PUNARO_ATTACHED_GROUP are required")
	}
	key, err := loadPrivateKey(keyFile)
	if err != nil {
		return adapterConfig{}, err
	}
	dataDir := strings.TrimSpace(os.Getenv("PUNARO_ADAPTER_DATA_DIR"))
	if dataDir == "" {
		dataDir = "./data"
	}
	if !filepath.IsAbs(dataDir) {
		dataDir, err = filepath.Abs(dataDir)
		if err != nil {
			return adapterConfig{}, fmt.Errorf("resolve adapter data directory: %w", err)
		}
	}
	pollInterval := 30 * time.Second
	if raw := strings.TrimSpace(os.Getenv("PUNARO_ADAPTER_POLL_INTERVAL")); raw != "" {
		pollInterval, err = time.ParseDuration(raw)
		if err != nil || pollInterval < 5*time.Second || pollInterval > 5*time.Minute {
			return adapterConfig{}, fmt.Errorf("PUNARO_ADAPTER_POLL_INTERVAL must be between 5s and 5m")
		}
	}
	mailboxBinary := strings.TrimSpace(os.Getenv("PUNARO_AGENT_MAILBOX_BIN"))
	if mailboxBinary == "" {
		mailboxBinary = "agent-mailbox"
	}
	accessToken := adapter.AccessServiceToken{ClientID: strings.TrimSpace(os.Getenv("PUNARO_CF_ACCESS_CLIENT_ID")), ClientSecret: strings.TrimSpace(os.Getenv("PUNARO_CF_ACCESS_CLIENT_SECRET"))}
	if (accessToken.ClientID == "") != (accessToken.ClientSecret == "") {
		return adapterConfig{}, fmt.Errorf("both PUNARO_CF_ACCESS_CLIENT_ID and PUNARO_CF_ACCESS_CLIENT_SECRET are required together")
	}
	return adapterConfig{relayURL: relayURL, machineID: machineID, privateKey: key, attachedGroup: group, mailboxBinary: mailboxBinary, mailboxState: strings.TrimSpace(os.Getenv("PUNARO_MAILBOX_STATE_DIR")), dataDir: dataDir, pollInterval: pollInterval, accessToken: accessToken}, nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	// #nosec G304 -- the local operator explicitly selected this credential path
	// through configuration; remote inputs never control it.
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
