// punaro-adapter synchronizes one enrolled machine's local agent-mailbox
// attachment group with the central Punaro relay.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rock3r/punaro/internal/adapter"
	"github.com/rock3r/punaro/internal/clientidentity"
	"github.com/rock3r/punaro/internal/clienttransport"
	"github.com/rock3r/punaro/internal/relay"
)

type adapterConfig struct {
	relayURL        string
	machineID       string
	privateKey      ed25519.PrivateKey
	attachedGroup   string
	mailboxBinary   string
	mailboxState    string
	dataDir         string
	pollInterval    time.Duration
	accessToken     adapter.AccessServiceToken
	transportPolicy clienttransport.Policy
	invokerCommand  string
}

const (
	adapterProfileFileEnv = "PUNARO_ADAPTER_PROFILE_FILE"
	maxAdapterProfileSize = 16 << 10
)

var adapterProfileKeys = map[string]struct{}{
	"PUNARO_ADAPTER_RELAY_URL":        {},
	"PUNARO_MACHINE_ID":               {},
	"PUNARO_MACHINE_PRIVATE_KEY_FILE": {},
	"PUNARO_ATTACHED_GROUP":           {},
	"PUNARO_ADAPTER_DATA_DIR":         {},
	"PUNARO_MAILBOX_STATE_DIR":        {},
	"PUNARO_ADAPTER_POLL_INTERVAL":    {},
	"PUNARO_AGENT_MAILBOX_BIN":        {},
	"PUNARO_CF_ACCESS_CLIENT_ID":      {},
	"PUNARO_CF_ACCESS_CLIENT_SECRET":  {},
	"PUNARO_INVOKER_COMMAND":          {},
	"PUNARO_CLIENT_IDENTITY_FILE":     {},
	"PUNARO_CLIENT_BINDING":           {},
	"PUNARO_ADAPTER_ALLOW_LAN_HTTP":   {},
	"PUNARO_ADAPTER_TRUSTED_LAN_CIDR": {},
}

func main() {
	var err error
	switch {
	case len(os.Args) == 1:
		err = run()
	case os.Args[1] == "send":
		err = runSend(os.Args[2:])
	case os.Args[1] == "claim":
		err = runClaim(os.Args[2:])
	case os.Args[1] == "get":
		err = runGet(os.Args[2:])
	case os.Args[1] == "create":
		err = runCreate(os.Args[2:])
	case os.Args[1] == "rename":
		err = runRename(os.Args[2:])
	case os.Args[1] == "bind-role":
		err = runBindRole(os.Args[2:])
	case os.Args[1] == "register-role":
		err = runRegisterRole(os.Args[2:])
	case os.Args[1] == "contacts":
		err = runContacts(os.Args[2:])
	case os.Args[1] == "invoke":
		err = runInvoke(os.Args[2:])
	case os.Args[1] == "member" && len(os.Args) > 2 && os.Args[2] == "set":
		err = runMemberSet(os.Args[3:])
	case os.Args[1] == "member" && len(os.Args) > 2 && os.Args[2] == "remove":
		err = runMemberRemove(os.Args[3:])
	case os.Args[1] == "attachment-notify":
		err = runAttachmentNotify(os.Args[2:])
	case os.Args[1] == "mailbox-mcp":
		err = runMailboxMCP()
	case os.Args[1] == "validate-relay-transport":
		err = validateRelayTransport(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q (supported: send, claim, get, create, rename, bind-role, register-role, contacts list, contacts resolve, invoke, member set, member remove, attachment-notify, mailbox-mcp, validate-relay-transport)", os.Args[1])
	}
	if err != nil {
		if shouldLogAdapterStop(err) {
			log.Printf("punaro-adapter stopped: %v", err)
		}
		os.Exit(exitStatus(err))
	}
}

func shouldLogAdapterStop(err error) bool {
	var status *contactsStatusError
	return !errors.As(err, &status)
}

func exitStatus(err error) int {
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return 1
}

func mailboxMCPCommand() ([]string, error) {
	settings, err := loadAdapterProfile()
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"PUNARO_AGENT_MAILBOX_BIN", "PUNARO_MAILBOX_STATE_DIR"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			settings[key] = value
		}
	}
	mailboxBinary := settings["PUNARO_AGENT_MAILBOX_BIN"]
	mailboxState := settings["PUNARO_MAILBOX_STATE_DIR"]
	if mailboxBinary == "" || mailboxState == "" || !filepath.IsAbs(mailboxState) || filepath.Clean(mailboxState) != mailboxState {
		return nil, errors.New("mailbox MCP configuration is incomplete or invalid")
	}
	if !filepath.IsAbs(mailboxBinary) && filepath.Base(mailboxBinary) != mailboxBinary {
		return nil, errors.New("mailbox MCP configuration is incomplete or invalid")
	}
	return []string{mailboxBinary, "--state-dir", mailboxState, "mcp"}, nil
}

func runMailboxMCP() error {
	command, err := mailboxMCPCommand()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runMailboxMCPProcess(ctx, command, os.Stdin, os.Stdout, os.Stderr)
}

func runMailboxMCPProcess(ctx context.Context, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	process := exec.CommandContext(ctx, command[0], command[1:]...) // #nosec G204,G702 -- fixed operation using owner-controlled installer configuration.
	process.Stdout = stdout
	process.Stderr = stderr
	childInput, err := process.StdinPipe()
	if err != nil {
		return fmt.Errorf("prepare agent-mailbox MCP input: %w", err)
	}
	process.Cancel = func() error {
		_ = childInput.Close()
		return os.ErrProcessDone
	}
	process.WaitDelay = 2 * time.Second
	go func() {
		_, _ = io.Copy(childInput, stdin)
		_ = childInput.Close()
	}()
	if err := process.Run(); err != nil {
		return fmt.Errorf("agent-mailbox MCP server failed: %w", err)
	}
	return nil
}

func validateRelayTransport(args []string) error {
	flags := flag.NewFlagSet("punaro-adapter validate-relay-transport", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	relayURL := flags.String("relay-url", "", "fixed relay origin")
	allowLANHTTP := flags.Bool("allow-lan-http", false, "explicitly allow plaintext credentials on the pinned trusted LAN")
	trustedLANCIDR := flags.String("trusted-lan-cidr", "", "private or link-local CIDR containing the literal HTTP origin")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *relayURL == "" {
		return errors.New("relay transport policy is invalid")
	}
	policy := clienttransport.Policy{AllowLANHTTP: *allowLANHTTP, TrustedLANCIDR: strings.TrimSpace(*trustedLANCIDR)}
	if _, err := clienttransport.ValidateOrigin(*relayURL, policy); err != nil {
		return errors.New("relay transport policy is invalid")
	}
	return nil
}

type memberControlRequest struct {
	conversationID, actor, idempotencyKey string
	member                                relay.Member
	operation                             relay.ControlOperation
}

func parseMemberSetArgs(args []string) (memberControlRequest, error) {
	return parseMemberControlArgs(args, relay.ControlUpsertMember)
}
func parseMemberRemoveArgs(args []string) (memberControlRequest, error) {
	return parseMemberControlArgs(args, relay.ControlRemoveMember)
}
func parseMemberControlArgs(args []string, operation relay.ControlOperation) (memberControlRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter member", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request memberControlRequest
	var rawMember string
	request.operation = operation
	flags.StringVar(&request.conversationID, "conversation", "", "conversation ID")
	flags.StringVar(&request.actor, "actor", "", "attached admin endpoint")
	flags.StringVar(&rawMember, "member", "", "member endpoint, or endpoint:send,receive,admin for set")
	flags.StringVar(&request.idempotencyKey, "idempotency-key", "", "stable retry key")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || request.conversationID == "" || request.actor == "" || rawMember == "" || request.idempotencyKey == "" {
		return memberControlRequest{}, fmt.Errorf("--conversation, --actor, --member, and --idempotency-key are required")
	}
	if operation == relay.ControlRemoveMember {
		request.member.Endpoint = rawMember
		return request, nil
	}
	separator := strings.LastIndex(rawMember, ":")
	if separator <= 0 || separator == len(rawMember)-1 {
		return memberControlRequest{}, fmt.Errorf("member set requires endpoint:send,receive,admin")
	}
	endpoint, permissions := rawMember[:separator], rawMember[separator+1:]
	request.member.Endpoint = endpoint
	for _, item := range strings.Split(permissions, ",") {
		switch item {
		case "send":
			request.member.Capabilities |= relay.CapSend
		case "receive":
			request.member.Capabilities |= relay.CapReceive
		case "admin":
			request.member.Capabilities |= relay.CapAdmin
		default:
			return memberControlRequest{}, fmt.Errorf("invalid member capability")
		}
	}
	if request.member.Capabilities == 0 {
		return memberControlRequest{}, fmt.Errorf("invalid member capability")
	}
	return request, nil
}

func runMemberSet(args []string) error {
	request, err := parseMemberSetArgs(args)
	if err != nil {
		return err
	}
	return runMemberControl(request)
}
func runMemberRemove(args []string) error {
	request, err := parseMemberRemoveArgs(args)
	if err != nil {
		return err
	}
	return runMemberControl(request)
}
func runMemberControl(request memberControlRequest) error {
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	event, err := client.ControlMembership(context.Background(), request.conversationID, request.actor, request.operation, request.member, request.idempotencyKey)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"id\":%q,\"operation\":%q,\"member\":%q}\n", event.ID, event.Operation, event.Member.Endpoint)
	return err
}

type createRequest struct {
	creator        string
	displayName    string
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
	var roleMembers memberFlags
	flags.StringVar(&request.creator, "creator", "", "attached creator endpoint")
	flags.StringVar(&request.displayName, "name", "", "optional conversation display name")
	flags.Var(&members, "member", "endpoint:send,receive,admin (repeatable)")
	flags.Var(&roleMembers, "role-member", `JSON {"role":"...","machine_id":"...","capabilities":["send","receive","admin"]} (repeatable)`)
	flags.StringVar(&request.idempotencyKey, "idempotency-key", "", "stable retry key")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || request.creator == "" || request.idempotencyKey == "" || len(members)+len(roleMembers) == 0 {
		return createRequest{}, fmt.Errorf("--creator, at least one --member, and --idempotency-key are required")
	}
	for _, raw := range members {
		endpoint, permissions, found := strings.Cut(raw, ":")
		capability, err := parseMemberCapabilities(permissions, found)
		if err != nil || endpoint == "" {
			return createRequest{}, fmt.Errorf("invalid --member")
		}
		request.members = append(request.members, relay.Member{Endpoint: endpoint, Capabilities: capability})
	}
	for _, raw := range roleMembers {
		var member struct {
			Role         string   `json:"role"`
			MachineID    string   `json:"machine_id"`
			Capabilities []string `json:"capabilities"`
		}
		if err := json.Unmarshal([]byte(raw), &member); err != nil || !relay.ValidRole(member.Role) || !relay.ValidMachineID(member.MachineID) {
			return createRequest{}, fmt.Errorf("invalid --role-member")
		}
		capability, err := parseCapabilityNames(member.Capabilities)
		if err != nil {
			return createRequest{}, fmt.Errorf("invalid --role-member")
		}
		if capability&relay.CapInvoke != 0 {
			return createRequest{}, fmt.Errorf("invalid --role-member")
		}
		request.members = append(request.members, relay.Member{Role: member.Role, RoleMachineID: member.MachineID, Capabilities: capability})
	}
	return request, nil
}

func parseMemberCapabilities(permissions string, present bool) (relay.Capability, error) {
	if !present || permissions == "" {
		return 0, fmt.Errorf("missing member capability")
	}
	return parseCapabilityNames(strings.Split(permissions, ","))
}

func parseCapabilityNames(items []string) (relay.Capability, error) {
	var capability relay.Capability
	for _, item := range items {
		switch item {
		case "send":
			capability |= relay.CapSend
		case "receive":
			capability |= relay.CapReceive
		case "admin":
			capability |= relay.CapAdmin
		case "invoke":
			capability |= relay.CapInvoke
		default:
			return 0, fmt.Errorf("invalid member capability")
		}
	}
	if capability == 0 {
		return 0, fmt.Errorf("invalid member capability")
	}
	return capability, nil
}

type invokeRequest struct {
	conversationID string
	fromEndpoint   string
	targetEndpoint string
	idempotencyKey string
}

func parseInvokeArgs(args []string) (invokeRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter invoke", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request invokeRequest
	flags.StringVar(&request.conversationID, "conversation", "", "conversation ID")
	flags.StringVar(&request.fromEndpoint, "from", "", "attached invoking endpoint")
	flags.StringVar(&request.targetEndpoint, "target", "", "offline receiving endpoint")
	flags.StringVar(&request.idempotencyKey, "idempotency-key", "", "stable invocation retry key")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || strings.TrimSpace(request.conversationID) == "" || strings.TrimSpace(request.fromEndpoint) == "" || strings.TrimSpace(request.targetEndpoint) == "" || strings.TrimSpace(request.idempotencyKey) == "" {
		return invokeRequest{}, fmt.Errorf("--conversation, --from, --target, and --idempotency-key are required")
	}
	return request, nil
}

func runInvoke(args []string) error {
	request, err := parseInvokeArgs(args)
	if err != nil {
		return err
	}
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	invocation, err := client.Invoke(context.Background(), request.conversationID, request.fromEndpoint, request.targetEndpoint, request.idempotencyKey)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"id\":%q,\"status\":%q}\n", invocation.ID, invocation.Status)
	return err
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
	client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	conversation, err := client.CreateConversation(context.Background(), request.creator, request.members, request.displayName, request.idempotencyKey)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"id\":%q}\n", conversation.ID)
	return err
}

type renameRequest struct {
	conversationID string
	actor          string
	displayName    string
	idempotencyKey string
}

func parseRenameArgs(args []string) (renameRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter rename", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request renameRequest
	flags.StringVar(&request.conversationID, "conversation", "", "conversation ID")
	flags.StringVar(&request.actor, "actor", "", "attached admin endpoint")
	flags.StringVar(&request.displayName, "name", "", "conversation display name")
	flags.StringVar(&request.idempotencyKey, "idempotency-key", "", "stable retry key")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || request.conversationID == "" || request.actor == "" || request.displayName == "" || request.idempotencyKey == "" {
		return renameRequest{}, fmt.Errorf("--conversation, --actor, --name, and --idempotency-key are required")
	}
	return request, nil
}

func runRename(args []string) error {
	request, err := parseRenameArgs(args)
	if err != nil {
		return err
	}
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	conversation, err := client.SetConversationDisplayName(context.Background(), request.conversationID, request.actor, request.displayName, request.idempotencyKey)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"id\":%q,\"display_name\":%q}\n", conversation.ID, conversation.DisplayName)
	return err
}

type bindRoleRequest struct {
	role    string
	session string
}

func parseBindRoleArgs(args []string) (bindRoleRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter bind-role", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request bindRoleRequest
	flags.StringVar(&request.role, "role", "", "durable role identity")
	flags.StringVar(&request.session, "session", "", "currently attached session endpoint")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !relay.ValidRole(request.role) || !relay.ValidEndpoint(request.session) {
		return bindRoleRequest{}, fmt.Errorf("--role and --session are required")
	}
	return request, nil
}

func runBindRole(args []string) error {
	request, err := parseBindRoleArgs(args)
	if err != nil {
		return err
	}
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	return client.BindRole(context.Background(), request.role, request.session)
}

type registerRoleRequest struct {
	role              string
	displayName       string
	directAddressable bool
	idempotencyKey    string
}

func parseRegisterRoleArgs(args []string) (registerRoleRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter register-role", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request registerRoleRequest
	flags.StringVar(&request.role, "role", "", "canonical role handle role/<machine>/<slug>")
	flags.StringVar(&request.displayName, "display-name", "", "optional portable display name")
	flags.BoolVar(&request.directAddressable, "direct-addressable", false, "opt the role into later discovery")
	flags.StringVar(&request.idempotencyKey, "idempotency-key", "", "stable key for retries")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !relay.CanonicalRoleHandle(request.role) || !relay.ValidRequestToken(request.idempotencyKey) {
		return registerRoleRequest{}, fmt.Errorf("--role and --idempotency-key are required")
	}
	if request.displayName != "" {
		if _, ok := relay.NormalizeRoleDisplayName(request.displayName); !ok {
			return registerRoleRequest{}, fmt.Errorf("--display-name is invalid")
		}
	}
	return request, nil
}

func runRegisterRole(args []string) error {
	request, err := parseRegisterRoleArgs(args)
	if err != nil {
		return err
	}
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	if !relay.CanonicalRoleForMachine(request.role, config.machineID) {
		return fmt.Errorf("role must be owned by this machine")
	}
	client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	profile, err := client.RegisterRole(context.Background(), request.role, request.displayName, request.directAddressable, request.idempotencyKey)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "%s\n", encoded)
	return err
}

type contactsListRequest struct {
	cursor string
	limit  int
}

type contactsStatusError struct {
	message string
	code    int
}

func (e *contactsStatusError) Error() string { return e.message }
func (e *contactsStatusError) ExitCode() int { return e.code }

func parseContactsListArgs(args []string) (contactsListRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter contacts list", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request contactsListRequest
	flags.StringVar(&request.cursor, "cursor", "", "opaque directory cursor")
	flags.IntVar(&request.limit, "limit", relay.DefaultRoleListLimit, "page size from 1 to 100")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return contactsListRequest{}, fmt.Errorf("contacts list accepts optional --cursor and --limit")
	}
	if request.limit < 1 || request.limit > relay.MaxRoleListLimit {
		return contactsListRequest{}, fmt.Errorf("contacts list --limit must be between 1 and 100")
	}
	return request, nil
}

func parseContactsResolveArgs(args []string) (string, error) {
	flags := flag.NewFlagSet("punaro-adapter contacts resolve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 || strings.TrimSpace(flags.Arg(0)) == "" {
		return "", fmt.Errorf("contacts resolve requires NAME")
	}
	return flags.Arg(0), nil
}

func contactsResolveExit(result relay.RoleResolveResult) int {
	switch result.Status {
	case relay.RoleResolveResolved:
		return 0
	case relay.RoleResolveAmbiguous:
		return 2
	default:
		return 1
	}
}

func runContacts(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("contacts requires list or resolve")
	}
	switch args[0] {
	case "list":
		return runContactsList(args[1:])
	case "resolve":
		return runContactsResolve(args[1:])
	default:
		return fmt.Errorf("unknown contacts command %q", args[0])
	}
}

func newRelayClient() (*adapter.HTTPRelayClient, error) {
	config, err := loadConfig()
	if err != nil {
		return nil, fmt.Errorf("configuration: %w", err)
	}
	return adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
}

func writeJSONLine(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "%s\n", encoded)
	return err
}

func runContactsList(args []string) error {
	request, err := parseContactsListArgs(args)
	if err != nil {
		return err
	}
	client, err := newRelayClient()
	if err != nil {
		return err
	}
	page, err := client.ListRoles(context.Background(), request.cursor, request.limit)
	if err != nil {
		return err
	}
	return writeJSONLine(page)
}

func runContactsResolve(args []string) error {
	name, err := parseContactsResolveArgs(args)
	if err != nil {
		return err
	}
	client, err := newRelayClient()
	if err != nil {
		return err
	}
	result, err := client.ResolveRole(context.Background(), name)
	if err != nil {
		return err
	}
	if err := writeJSONLine(result); err != nil {
		return err
	}
	if code := contactsResolveExit(result); code != 0 {
		return &contactsStatusError{message: result.Status, code: code}
	}
	return nil
}

type sendRequest struct {
	conversationID string
	fromEndpoint   string
	targetRole     string
	to             string
	toRole         string
	fromRole       string
	bodyFile       string
	idempotencyKey string
}

type claimRequest struct {
	conversationID string
	fromEndpoint   string
	idempotencyKey string
}

type getRequest struct {
	fromEndpoint string
}

func parseClaimArgs(args []string) (claimRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter claim", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request claimRequest
	flags.StringVar(&request.conversationID, "conversation", "", "conversation ID")
	flags.StringVar(&request.fromEndpoint, "from", "", "attached member session")
	flags.StringVar(&request.idempotencyKey, "idempotency-key", "", "stable retry key")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || strings.TrimSpace(request.conversationID) == "" || strings.TrimSpace(request.fromEndpoint) == "" || strings.TrimSpace(request.idempotencyKey) == "" {
		return claimRequest{}, fmt.Errorf("--conversation, --from, and --idempotency-key are required")
	}
	return request, nil
}

func runClaim(args []string) error {
	request, err := parseClaimArgs(args)
	if err != nil {
		return err
	}
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	claim, err := client.ClaimConversation(context.Background(), request.conversationID, request.fromEndpoint, request.idempotencyKey)
	if err != nil {
		return mapClaimError(err)
	}
	if claim.Status != "pending" && claim.Status != "complete" {
		return fmt.Errorf("telegram claim was not accepted")
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"conversation_id\":%q,\"status\":%q}\n", claim.ConversationID, claim.Status)
	return err
}

func parseGetArgs(args []string) (getRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter get", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request getRequest
	flags.StringVar(&request.fromEndpoint, "from", "", "attached session endpoint")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || strings.TrimSpace(request.fromEndpoint) == "" {
		return getRequest{}, fmt.Errorf("--from is required")
	}
	return request, nil
}

func runGet(args []string) error {
	request, err := parseGetArgs(args)
	if err != nil {
		return err
	}
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	topic, err := client.GetSessionTopic(context.Background(), request.fromEndpoint)
	if err != nil {
		return mapSessionTopicError(err)
	}
	if !topic.Claimed {
		return errTopicNotClaimed
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"id\":%q,\"display_name\":%q,\"claimed\":true}\n", topic.ID, topic.DisplayName)
	return err
}

func parseSendArgs(args []string) (sendRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter send", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request sendRequest
	flags.StringVar(&request.conversationID, "conversation", "", "conversation ID")
	flags.StringVar(&request.fromEndpoint, "from", "", "attached sender endpoint")
	flags.StringVar(&request.targetRole, "target-role", "", "deliver only to this durable conversation role")
	flags.StringVar(&request.to, "to", "", "user-telegram or canonical destination role")
	flags.StringVar(&request.fromRole, "from-role", "", "canonical source role")
	flags.StringVar(&request.bodyFile, "body-file", "", "message body file or - for stdin")
	flags.StringVar(&request.idempotencyKey, "idempotency-key", "", "stable key for retries")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return sendRequest{}, fmt.Errorf("invalid send arguments")
	}
	to := strings.TrimSpace(request.to)
	fromRole := strings.TrimSpace(request.fromRole)
	if to == relay.TelegramUserParticipant {
		if fromRole != "" {
			return sendRequest{}, fmt.Errorf("--to user-telegram cannot be combined with --from-role")
		}
		if request.targetRole != "" && request.targetRole != relay.TelegramUserParticipant {
			return sendRequest{}, fmt.Errorf("--to and --target-role do not match")
		}
		request.to = to
		request.targetRole = relay.TelegramUserParticipant
		if strings.TrimSpace(request.fromEndpoint) == "" || request.bodyFile == "" || strings.TrimSpace(request.idempotencyKey) == "" {
			return sendRequest{}, fmt.Errorf("--from, --body-file, and --idempotency-key are required")
		}
		return request, nil
	}
	if to != "" || fromRole != "" {
		if strings.TrimSpace(request.conversationID) != "" || strings.TrimSpace(request.fromEndpoint) != "" || request.targetRole != "" {
			return sendRequest{}, fmt.Errorf("--to/--from-role cannot be combined with --conversation, --from, or --target-role")
		}
		if to == "" || fromRole == "" || request.bodyFile == "" || strings.TrimSpace(request.idempotencyKey) == "" {
			return sendRequest{}, fmt.Errorf("--to, --from-role, --body-file, and --idempotency-key are required")
		}
		if !relay.CanonicalRoleHandle(to) || !relay.CanonicalRoleHandle(fromRole) {
			return sendRequest{}, fmt.Errorf("--to and --from-role must be canonical role handles")
		}
		request.to = to
		request.toRole = to
		request.fromRole = fromRole
		return request, nil
	}
	if strings.TrimSpace(request.fromEndpoint) == "" || request.bodyFile == "" || strings.TrimSpace(request.idempotencyKey) == "" {
		if request.targetRole == relay.TelegramUserParticipant {
			return sendRequest{}, fmt.Errorf("--from, --body-file, and --idempotency-key are required")
		}
		return sendRequest{}, fmt.Errorf("--conversation, --from, --body-file, and --idempotency-key are required")
	}
	if request.targetRole != relay.TelegramUserParticipant && strings.TrimSpace(request.conversationID) == "" {
		return sendRequest{}, fmt.Errorf("--conversation, --from, --body-file, and --idempotency-key are required")
	}
	if request.targetRole != "" && !relay.ValidRole(request.targetRole) {
		return sendRequest{}, fmt.Errorf("--target-role is invalid")
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
	client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	conversationID := request.conversationID
	if request.targetRole == relay.TelegramUserParticipant {
		topic, err := client.GetSessionTopic(context.Background(), request.fromEndpoint)
		if err != nil {
			return mapSessionTopicError(err)
		}
		if !topic.Claimed {
			return errTopicNotClaimed
		}
		if conversationID != "" && conversationID != topic.ID {
			return errConversationMismatch
		}
		conversationID = topic.ID
	}
	var message relay.Message
	switch {
	case request.toRole != "":
		message, err = client.SendDirectMessage(context.Background(), request.fromRole, request.toRole, string(body), request.idempotencyKey)
	case request.targetRole == "":
		message, err = client.Send(context.Background(), conversationID, request.fromEndpoint, string(body), request.idempotencyKey)
	default:
		message, err = client.SendToRole(context.Background(), conversationID, request.fromEndpoint, request.targetRole, string(body), request.idempotencyKey)
	}
	if err != nil {
		return err
	}
	if request.toRole != "" {
		_, err = fmt.Fprintf(os.Stdout, "{\"id\":%q,\"conversation_id\":%q,\"sequence\":%d}\n", message.ID, message.ConversationID, message.Sequence)
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"id\":%q,\"sequence\":%d}\n", message.ID, message.Sequence)
	return err
}

var (
	errTopicNotClaimed        = errors.New("topic is not claimed")
	errSessionHasNoTopic      = errors.New("session has no topic")
	errConversationMismatch   = errors.New("conversation does not match session topic")
	errSessionTopicAmbiguous  = errors.New("session topic is ambiguous")
	errTelegramClaimForbidden = errors.New("telegram claim is not authorized")
	errTelegramClaimConflict  = errors.New("telegram claim conflicts")
)

func mapSessionTopicError(err error) error {
	switch adapter.RelayHTTPStatus(err) {
	case http.StatusForbidden:
		return errSessionHasNoTopic
	case http.StatusConflict:
		return errSessionTopicAmbiguous
	default:
		return err
	}
}

func mapClaimError(err error) error {
	switch adapter.RelayHTTPStatus(err) {
	case http.StatusForbidden:
		return errTelegramClaimForbidden
	case http.StatusConflict:
		return errTelegramClaimConflict
	default:
		return err
	}
}

// attachmentNotifyRequest is intentionally an explicit post-offer handoff:
// the offer bytes were generated by the v3 data-plane workflow and are first
// persisted in the local adapter outbox before any relay append is attempted.
type attachmentNotifyRequest struct {
	conversationID string
	fromEndpoint   string
	offerFile      string
	idempotencyKey string
}

func parseAttachmentNotifyArgs(args []string) (attachmentNotifyRequest, error) {
	flags := flag.NewFlagSet("punaro-adapter attachment-notify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var request attachmentNotifyRequest
	flags.StringVar(&request.conversationID, "conversation", "", "conversation ID")
	flags.StringVar(&request.fromEndpoint, "from", "", "attached sender endpoint")
	flags.StringVar(&request.offerFile, "offer-file", "", "canonical v3 offer CDE file or - for stdin")
	flags.StringVar(&request.idempotencyKey, "idempotency-key", "", "stable transfer-scoped retry key")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || strings.TrimSpace(request.conversationID) == "" || strings.TrimSpace(request.fromEndpoint) == "" || request.offerFile == "" || strings.TrimSpace(request.idempotencyKey) == "" {
		return attachmentNotifyRequest{}, fmt.Errorf("--conversation, --from, --offer-file, and --idempotency-key are required")
	}
	return request, nil
}

func runAttachmentNotify(args []string) error {
	request, err := parseAttachmentNotifyArgs(args)
	if err != nil {
		return err
	}
	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	offer, err := readMessageBody(request.offerFile)
	if err != nil {
		return err
	}
	outbox, err := adapter.OpenOfferNoticeOutbox(filepath.Join(config.dataDir, "attachment-offers.db"))
	if err != nil {
		return err
	}
	defer func() { _ = outbox.Close() }()
	if err := outbox.EnqueueV3OfferNotice(context.Background(), request.conversationID, request.fromEndpoint, offer, request.idempotencyKey); err != nil {
		return err
	}
	client, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	if err := outbox.Flush(context.Background(), client); err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, `{"status":"delivered"}`)
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
	relayClient, err := adapter.NewHTTPRelayClientWithPolicy(config.relayURL, config.machineID, config.privateKey, nil, config.accessToken, config.transportPolicy)
	if err != nil {
		return err
	}
	journal, err := adapter.OpenJournal(filepath.Join(config.dataDir, "adapter.db"))
	if err != nil {
		return err
	}
	defer func() { _ = journal.Close() }()
	offerOutbox, err := adapter.OpenOfferNoticeOutbox(filepath.Join(config.dataDir, "attachment-offers.db"))
	if err != nil {
		return err
	}
	defer func() { _ = offerOutbox.Close() }()
	var invoker adapter.Invoker
	if config.invokerCommand != "" {
		invoker, err = adapter.NewCommandInvoker(config.invokerCommand)
		if err != nil {
			return fmt.Errorf("invocation runtime: %w", err)
		}
	}
	syncer := adapter.Syncer{Mailbox: mailbox, Relay: relayClient, Journal: journal, Invoker: invoker}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	wake := make(chan struct{}, 1)
	go runNotifications(ctx, relayClient, wake)
	reportedReady := false
	for {
		if err := offerOutbox.Flush(ctx, relayClient); err != nil && !errors.Is(err, context.Canceled) {
			// Durable rows remain for the next poll; never log their offer body.
			log.Printf("attachment offer notice synchronization failed: %v", err)
		}
		if err := syncer.SyncOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			// Errors deliberately omit remote and mailbox output bodies.
			log.Printf("synchronization failed: %v", err)
		} else if err == nil && !reportedReady {
			if readyErr := writeBootstrapReady(); readyErr != nil {
				log.Printf("bootstrap ready file is invalid: %v", readyErr)
			} else {
				reportedReady = true
			}
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
	settings, err := loadAdapterProfile()
	if err != nil {
		return adapterConfig{}, err
	}
	for key := range adapterProfileKeys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			settings[key] = value
		}
	}
	relayURL := settings["PUNARO_ADAPTER_RELAY_URL"]
	machineID := settings["PUNARO_MACHINE_ID"]
	keyFile := settings["PUNARO_MACHINE_PRIVATE_KEY_FILE"]
	group := settings["PUNARO_ATTACHED_GROUP"]
	if relayURL == "" || machineID == "" || keyFile == "" || group == "" {
		return adapterConfig{}, errors.New("adapter configuration is incomplete")
	}
	allowLANHTTP, err := parseLANHTTPSetting(settings["PUNARO_ADAPTER_ALLOW_LAN_HTTP"])
	if err != nil {
		return adapterConfig{}, err
	}
	transportPolicy := clienttransport.Policy{AllowLANHTTP: allowLANHTTP, TrustedLANCIDR: settings["PUNARO_ADAPTER_TRUSTED_LAN_CIDR"]}
	if _, err := clienttransport.ValidateOrigin(relayURL, transportPolicy); err != nil {
		return adapterConfig{}, errors.New("adapter relay transport policy is invalid")
	}
	if err := loadClientIdentity(settings, relayURL, machineID, transportPolicy); err != nil {
		return adapterConfig{}, err
	}
	key, err := loadPrivateKey(keyFile)
	if err != nil {
		return adapterConfig{}, err
	}
	dataDir := settings["PUNARO_ADAPTER_DATA_DIR"]
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
	if raw := settings["PUNARO_ADAPTER_POLL_INTERVAL"]; raw != "" {
		pollInterval, err = time.ParseDuration(raw)
		if err != nil || pollInterval < 5*time.Second || pollInterval > 5*time.Minute {
			return adapterConfig{}, fmt.Errorf("PUNARO_ADAPTER_POLL_INTERVAL must be between 5s and 5m")
		}
	}
	mailboxBinary := settings["PUNARO_AGENT_MAILBOX_BIN"]
	if mailboxBinary == "" {
		mailboxBinary = "agent-mailbox"
	}
	accessToken := adapter.AccessServiceToken{ClientID: settings["PUNARO_CF_ACCESS_CLIENT_ID"], ClientSecret: settings["PUNARO_CF_ACCESS_CLIENT_SECRET"]}
	if (accessToken.ClientID == "") != (accessToken.ClientSecret == "") {
		return adapterConfig{}, fmt.Errorf("both PUNARO_CF_ACCESS_CLIENT_ID and PUNARO_CF_ACCESS_CLIENT_SECRET are required together")
	}
	return adapterConfig{relayURL: relayURL, machineID: machineID, privateKey: key, attachedGroup: group, mailboxBinary: mailboxBinary, mailboxState: settings["PUNARO_MAILBOX_STATE_DIR"], dataDir: dataDir, pollInterval: pollInterval, accessToken: accessToken, transportPolicy: transportPolicy, invokerCommand: settings["PUNARO_INVOKER_COMMAND"]}, nil
}

func parseLANHTTPSetting(raw string) (bool, error) {
	switch raw {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, errors.New("PUNARO_ADAPTER_ALLOW_LAN_HTTP must be true or false")
	}
}

func loadClientIdentity(settings map[string]string, relayURL, machineID string, policy clienttransport.Policy) error {
	path, binding := settings["PUNARO_CLIENT_IDENTITY_FILE"], settings["PUNARO_CLIENT_BINDING"]
	if path == "" && binding == "" {
		return nil
	}
	if path == "" || binding == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("client identity configuration is invalid")
	}
	raw, err := readPrivateFile(path, "client identity", maxAdapterProfileSize)
	if err != nil {
		return errors.New("client identity configuration is invalid")
	}
	state, err := clientidentity.Parse(raw)
	if err != nil || state.MatchLegacyAdapter(relayURL, binding, machineID) != nil || state.TransportPolicy() != policy {
		return errors.New("client identity configuration does not match this adapter")
	}
	return nil
}

// loadAdapterProfile reads the installer-managed profile as plain data rather
// than evaluating it as shell or service-manager syntax. A non-empty process
// environment setting intentionally overrides the corresponding profile entry.
func loadAdapterProfile() (map[string]string, error) {
	path := strings.TrimSpace(os.Getenv(adapterProfileFileEnv))
	explicitPath := path != ""
	if !explicitPath {
		path = installedAdapterProfilePath()
		if path == "" {
			// Preserve environment-only deployments when the optional default
			// profile root is unavailable. An explicitly selected profile still
			// fails closed below.
			return map[string]string{}, nil
		}
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("adapter profile is unsafe")
	}
	// #nosec G703 -- this is the fixed installer profile location or an explicit
	// local operator override; remote data never selects it.
	if _, err := os.Lstat(path); err != nil {
		if !explicitPath && errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, errors.New("adapter profile is unavailable")
	}
	raw, err := readPrivateFile(path, "adapter profile", maxAdapterProfileSize)
	if err != nil {
		return nil, errors.New("adapter profile is unsafe")
	}
	settings := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(name) != name || strings.ContainsRune(value, '\x00') {
			return nil, errors.New("adapter profile is invalid")
		}
		if _, allowed := adapterProfileKeys[name]; !allowed {
			return nil, errors.New("adapter profile is invalid")
		}
		if _, duplicate := settings[name]; duplicate {
			return nil, errors.New("adapter profile is invalid")
		}
		settings[name] = strings.TrimSpace(value)
	}
	return settings, nil
}

const (
	bootstrapReadyEnv  = "PUNARO_BOOTSTRAP_READY_FILE"
	bootstrapReadyBody = `{"schema":1,"status":"healthy"}`
)

func writeBootstrapReady() error {
	path := strings.TrimSpace(os.Getenv(bootstrapReadyEnv))
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("bootstrap ready file is invalid")
	}
	// #nosec G703 -- ready path is the absolute bootstrap-owned file passed by the local supervisor.
	info, err := os.Lstat(path)
	if err == nil && !info.Mode().IsRegular() {
		return errors.New("bootstrap ready file is invalid")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("bootstrap ready file is invalid")
	}
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".health-*.tmp")
	if err != nil {
		return errors.New("bootstrap ready file is invalid")
	}
	tmp := file.Name()
	if _, err := file.WriteString(bootstrapReadyBody); err != nil {
		_ = file.Close()
		removeReadyTemp(tmp)
		return errors.New("bootstrap ready file is invalid")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		removeReadyTemp(tmp)
		return errors.New("bootstrap ready file is invalid")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		removeReadyTemp(tmp)
		return errors.New("bootstrap ready file is invalid")
	}
	if err := file.Close(); err != nil {
		removeReadyTemp(tmp)
		return errors.New("bootstrap ready file is invalid")
	}
	// #nosec G703 -- ready path is the absolute bootstrap-owned file passed by the local supervisor.
	if err := os.Rename(tmp, path); err != nil {
		removeReadyTemp(tmp)
		return errors.New("bootstrap ready file is invalid")
	}
	return nil
}

func removeReadyTemp(tmp string) {
	// #nosec G703 -- tmp is the sibling CreateTemp file beside the supervisor-owned ready path.
	_ = os.Remove(tmp)
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	// #nosec G304,G703 -- the local operator explicitly selected this credential path
	// through configuration; remote inputs never control it.
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
