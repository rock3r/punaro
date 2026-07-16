// punaro-attachment is the narrow local control surface for v3 attachment
// discovery. It intentionally has no command that accepts arbitrary network
// URLs, permit bytes, device keys, or Access credentials.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/adapter"
	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/attachment/v3/controller"
)

// receiveConfig contains only locally provisioned identities and root trust.
// The command never accepts them as flags or mailbox-derived data.
type receiveConfig struct {
	relayURL                string
	machineID               string
	machinePrivate          ed25519.PrivateKey
	recipientSigningPrivate ed25519.PrivateKey
	recipientHPKEPrivate    *ecdh.PrivateKey
	directoryAudience       [32]byte
	directoryRootKeyID      [32]byte
	directoryRootPublic     ed25519.PublicKey
	checkpointPath          string
	accessToken             adapter.AccessServiceToken
}

// senderConfig contains the independently provisioned source identity and
// local durable state needed to create a v3 source. It deliberately does not
// reuse a recipient controller journal: a source machine must not gain a
// recipient identity merely by selecting a different command.
type senderConfig struct {
	relayURL             string
	machineID            string
	machinePrivate       ed25519.PrivateKey
	senderSigningPrivate ed25519.PrivateKey
	sender               controller.SenderIdentity
	directoryAudience    [32]byte
	directoryRootKeyID   [32]byte
	directoryRootPublic  ed25519.PublicKey
	checkpointPath       string
	journalPath          string
	artifactPath         string
	offerOutboxPath      string
	accessToken          adapter.AccessServiceToken
}

// loadReceiveConfig intentionally keeps local runtime credentials in explicit
// service-provisioned paths/environment, never in command arguments or the
// journal.
func loadReceiveConfig() (receiveConfig, error) {
	var cfg receiveConfig
	cfg.relayURL = strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_RELAY_URL"))
	cfg.machineID = strings.TrimSpace(os.Getenv("PUNARO_MACHINE_ID"))
	machineKey := strings.TrimSpace(os.Getenv("PUNARO_MACHINE_PRIVATE_KEY_FILE"))
	recipientKey := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_RECIPIENT_SIGNING_PRIVATE_KEY_FILE"))
	hpkeKey := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_RECIPIENT_HPKE_PRIVATE_KEY_FILE"))
	checkpoint := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_DIRECTORY_CHECKPOINT_FILE"))
	if cfg.relayURL == "" || cfg.machineID == "" || machineKey == "" || recipientKey == "" || hpkeKey == "" || checkpoint == "" {
		return receiveConfig{}, fmt.Errorf("PUNARO_ATTACHMENT_RELAY_URL, PUNARO_MACHINE_ID, PUNARO_MACHINE_PRIVATE_KEY_FILE, PUNARO_ATTACHMENT_RECIPIENT_SIGNING_PRIVATE_KEY_FILE, PUNARO_ATTACHMENT_RECIPIENT_HPKE_PRIVATE_KEY_FILE, and PUNARO_ATTACHMENT_DIRECTORY_CHECKPOINT_FILE are required")
	}
	if !filepath.IsAbs(checkpoint) {
		return receiveConfig{}, errors.New("PUNARO_ATTACHMENT_DIRECTORY_CHECKPOINT_FILE must be absolute")
	}
	var err error
	if cfg.machinePrivate, err = attachmentv2.LoadPrivateEd25519KeyFile(machineKey); err != nil {
		return receiveConfig{}, errors.New("machine private key is unavailable")
	}
	if cfg.recipientSigningPrivate, err = attachmentv2.LoadPrivateEd25519KeyFile(recipientKey); err != nil {
		return receiveConfig{}, errors.New("recipient signing key is unavailable")
	}
	if cfg.recipientHPKEPrivate, err = loadX25519PrivateKeyFile(hpkeKey); err != nil {
		return receiveConfig{}, errors.New("recipient HPKE key is unavailable")
	}
	if cfg.directoryAudience, err = id32(strings.TrimSpace(os.Getenv("PUNARO_DIRECTORY_AUDIENCE"))); err != nil {
		return receiveConfig{}, errors.New("PUNARO_DIRECTORY_AUDIENCE is required")
	}
	if cfg.directoryRootKeyID, err = id32(strings.TrimSpace(os.Getenv("PUNARO_DIRECTORY_ROOT_KEY_ID"))); err != nil {
		return receiveConfig{}, errors.New("PUNARO_DIRECTORY_ROOT_KEY_ID is required")
	}
	root, err := id32(strings.TrimSpace(os.Getenv("PUNARO_DIRECTORY_ROOT_PUBLIC_KEY")))
	if err != nil {
		return receiveConfig{}, errors.New("PUNARO_DIRECTORY_ROOT_PUBLIC_KEY is required")
	}
	cfg.directoryRootPublic = ed25519.PublicKey(append([]byte(nil), root[:]...))
	cfg.checkpointPath = checkpoint
	cfg.accessToken = adapter.AccessServiceToken{ClientID: strings.TrimSpace(os.Getenv("PUNARO_CF_ACCESS_CLIENT_ID")), ClientSecret: strings.TrimSpace(os.Getenv("PUNARO_CF_ACCESS_CLIENT_SECRET"))}
	if (cfg.accessToken.ClientID == "") != (cfg.accessToken.ClientSecret == "") {
		return receiveConfig{}, errors.New("both Cloudflare Access service-token variables are required together")
	}
	return cfg, nil
}

// loadSenderConfig accepts only service-provisioned local identity, trust and
// durable-state paths. A command line can select a locally mapped conversation
// and source file but cannot supply relay authority or attachment credentials.
func loadSenderConfig() (senderConfig, error) {
	var cfg senderConfig
	cfg.relayURL = strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_RELAY_URL"))
	cfg.machineID = strings.TrimSpace(os.Getenv("PUNARO_MACHINE_ID"))
	machineKey := strings.TrimSpace(os.Getenv("PUNARO_MACHINE_PRIVATE_KEY_FILE"))
	senderKey := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_SENDER_SIGNING_PRIVATE_KEY_FILE"))
	cfg.checkpointPath = strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_DIRECTORY_CHECKPOINT_FILE"))
	cfg.journalPath = strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_SENDER_JOURNAL"))
	cfg.artifactPath = strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_ARTIFACT_STORE"))
	cfg.offerOutboxPath = strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_OFFER_OUTBOX"))
	if cfg.relayURL == "" || cfg.machineID == "" || machineKey == "" || senderKey == "" || cfg.checkpointPath == "" || cfg.journalPath == "" || cfg.artifactPath == "" || cfg.offerOutboxPath == "" {
		return senderConfig{}, errors.New("sender relay, machine, signing key, checkpoint, journal, artifact store, and offer outbox configuration are required")
	}
	for _, path := range []string{cfg.checkpointPath, cfg.journalPath, cfg.artifactPath, cfg.offerOutboxPath} {
		if !filepath.IsAbs(path) {
			return senderConfig{}, errors.New("sender durable-state paths must be absolute")
		}
	}
	var err error
	if cfg.machinePrivate, err = attachmentv2.LoadPrivateEd25519KeyFile(machineKey); err != nil {
		return senderConfig{}, errors.New("machine private key is unavailable")
	}
	if cfg.senderSigningPrivate, err = attachmentv2.LoadPrivateEd25519KeyFile(senderKey); err != nil {
		return senderConfig{}, errors.New("sender signing key is unavailable")
	}
	if cfg.sender, err = senderIdentityFromConfig(); err != nil {
		return senderConfig{}, err
	}
	if cfg.directoryAudience, err = id32(strings.TrimSpace(os.Getenv("PUNARO_DIRECTORY_AUDIENCE"))); err != nil {
		return senderConfig{}, errors.New("PUNARO_DIRECTORY_AUDIENCE is required")
	}
	if cfg.directoryRootKeyID, err = id32(strings.TrimSpace(os.Getenv("PUNARO_DIRECTORY_ROOT_KEY_ID"))); err != nil {
		return senderConfig{}, errors.New("PUNARO_DIRECTORY_ROOT_KEY_ID is required")
	}
	root, err := id32(strings.TrimSpace(os.Getenv("PUNARO_DIRECTORY_ROOT_PUBLIC_KEY")))
	if err != nil {
		return senderConfig{}, errors.New("PUNARO_DIRECTORY_ROOT_PUBLIC_KEY is required")
	}
	cfg.directoryRootPublic = ed25519.PublicKey(append([]byte(nil), root[:]...))
	cfg.accessToken = adapter.AccessServiceToken{ClientID: strings.TrimSpace(os.Getenv("PUNARO_CF_ACCESS_CLIENT_ID")), ClientSecret: strings.TrimSpace(os.Getenv("PUNARO_CF_ACCESS_CLIENT_SECRET"))}
	if (cfg.accessToken.ClientID == "") != (cfg.accessToken.ClientSecret == "") {
		return senderConfig{}, errors.New("both Cloudflare Access service-token variables are required together")
	}
	return cfg, nil
}

func loadX25519PrivateKeyFile(path string) (*ecdh.PrivateKey, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("private key path must be absolute")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key parent is unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key is unavailable")
	}
	// #nosec G304 -- this absolute operator-provisioned credential path passed
	// private non-symlink checks above and is never influenced by relay input.
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("private key is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(base64.RawURLEncoding.EncodedLen(32)+1)))
	if err != nil || len(raw) != base64.RawURLEncoding.EncodedLen(32) {
		return nil, errors.New("private key is unavailable")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(raw))
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != string(raw) {
		return nil, errors.New("invalid private key encoding")
	}
	return ecdh.X25519().NewPrivateKey(decoded)
}

func main() {
	var err error
	switch {
	case len(os.Args) >= 2 && os.Args[1] == "map":
		err = runMap(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "map-sender":
		err = runMapSender(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "record":
		err = runRecord(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "approve":
		err = runApprove(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "receive":
		err = runReceive(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "send":
		err = runSend(os.Args[2:])
	default:
		err = fmt.Errorf("supported commands: map, map-sender, record, approve, receive, send")
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "punaro-attachment:", err)
		os.Exit(2)
	}
}

type receiveAuthorityProvider struct {
	authority *attachmentv3.DirectoryAuthorityAdapter
}

type senderAuthorityProvider struct {
	authority *attachmentv3.DirectoryAuthorityAdapter
}

func (p senderAuthorityProvider) ResolveSenderDeliveryAuthority(ctx context.Context, now time.Time) (controller.SenderDeliveryAuthority, error) {
	if p.authority == nil {
		return nil, errors.New("sender authority is unavailable")
	}
	authority, err := p.authority.ResolveAttachmentAuthority(ctx, now)
	if err != nil {
		return nil, err
	}
	resolved, ok := authority.(controller.SenderDeliveryAuthority)
	if !ok {
		return nil, errors.New("sender authority is unavailable")
	}
	return resolved, nil
}

func (p receiveAuthorityProvider) ResolveRecipientAcceptanceAuthority(ctx context.Context, now time.Time) (controller.RecipientAcceptanceAuthority, error) {
	if p.authority == nil {
		return nil, errors.New("recipient authority is unavailable")
	}
	authority, err := p.authority.ResolveAttachmentAuthority(ctx, now)
	if err != nil {
		return nil, err
	}
	resolved, ok := authority.(controller.RecipientAcceptanceAuthority)
	if !ok {
		return nil, errors.New("recipient authority is unavailable")
	}
	return resolved, nil
}

func runReceive(args []string) error {
	f := flag.NewFlagSet("receive", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var messageID, destination string
	f.StringVar(&messageID, "message-id", "", "approved Punaro offer message ID")
	f.StringVar(&destination, "output", "", "absolute new output file path")
	if f.Parse(args) != nil || f.NArg() != 0 || messageID == "" || !filepath.IsAbs(destination) {
		return fmt.Errorf("receive requires --message-id and absolute --output")
	}
	local, err := openJournal()
	if err != nil {
		return err
	}
	defer local.Close()
	inbound, err := local.ApprovedInboundOffer(messageID)
	if err != nil {
		return err
	}
	cfg, err := loadReceiveConfig()
	if err != nil {
		return err
	}
	client, err := adapter.NewHTTPRelayClient(cfg.relayURL, cfg.machineID, cfg.machinePrivate, nil, cfg.accessToken)
	if err != nil {
		return err
	}
	checkpoints, err := attachmentv2.OpenSQLiteCheckpointStore(cfg.checkpointPath)
	if err != nil {
		return err
	}
	defer checkpoints.Close()
	fresh, err := attachmentv2.NewFreshDirectoryAuthorityProvider(client, attachmentv2.DirectoryTrust{Audience: cfg.directoryAudience, RootKeyID: cfg.directoryRootKeyID, RootPublicKey: cfg.directoryRootPublic, Checkpoints: checkpoints})
	if err != nil {
		return err
	}
	authority, err := attachmentv3.NewDirectoryAuthorityAdapter(fresh)
	if err != nil {
		return err
	}
	recipient, err := recipientIdentityFromJournal(local)
	if err != nil {
		return err
	}
	signer := controller.NewLocalRecipientOperationSigner(recipient, cfg.recipientSigningPrivate)
	acceptance, err := controller.NewRecipientAcceptanceWorker(controller.RecipientAcceptanceWorkerOptions{Journal: local, AuthorityProvider: receiveAuthorityProvider{authority}, Signer: signer, Transport: client, NewID: newID, NewIdempotencyKey: newIdempotencyKey})
	if err != nil {
		return err
	}
	worker, err := controller.NewRecipientDownloadWorker(controller.RecipientDownloadWorkerOptions{Acceptance: acceptance, AuthorityProvider: receiveAuthorityProvider{authority}, Signer: signer, Transport: client, EnvelopeOpener: controller.NewLocalRecipientEnvelopeOpener(cfg.recipientHPKEPrivate), NewID: newID, NewIdempotencyKey: newIdempotencyKey})
	if err != nil {
		return err
	}
	result, err := worker.Receive(context.Background(), inbound, destination)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"transfer_id\":%q,\"state\":%d}\n", base64.RawURLEncoding.EncodeToString(result.TransferID[:]), result.State)
	return err
}

type sendRequest struct {
	inputPath           string
	relayConversationID string
	fromEndpoint        string
	stageID             [16]byte
}

func parseSendArgs(args []string) (sendRequest, error) {
	f := flag.NewFlagSet("send", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var request sendRequest
	var stage string
	f.StringVar(&request.inputPath, "input", "", "absolute local source file")
	f.StringVar(&request.relayConversationID, "relay-conversation", "", "locally mapped relay conversation")
	f.StringVar(&request.fromEndpoint, "from", "", "attached local sender endpoint")
	f.StringVar(&stage, "stage-id", "", "stable local source-stage ID")
	if f.Parse(args) != nil || f.NArg() != 0 || !filepath.IsAbs(request.inputPath) || strings.TrimSpace(request.relayConversationID) == "" || strings.TrimSpace(request.fromEndpoint) == "" {
		return sendRequest{}, errors.New("send requires --input, --relay-conversation, --from, and --stage-id")
	}
	var err error
	if request.stageID, err = id16(stage); err != nil || request.stageID == [16]byte{} {
		return sendRequest{}, errors.New("send requires a canonical non-zero --stage-id")
	}
	return request, nil
}

// runSend stages a bounded local plaintext file, uploads only its encrypted
// source, and persists the recipient offer to the adapter-owned outbox before
// it attempts normal relay delivery. A failed final Flush leaves that durable
// outbox row for the long-running adapter to retry.
func runSend(args []string) error {
	request, err := parseSendArgs(args)
	if err != nil {
		return err
	}
	cfg, err := loadSenderConfig()
	if err != nil {
		return err
	}
	plaintext, err := readPlaintextInput(request.inputPath)
	if err != nil {
		return err
	}
	journal, err := controller.OpenJournalForSender(cfg.journalPath, cfg.sender)
	if err != nil {
		return err
	}
	defer journal.Close()
	client, err := adapter.NewHTTPRelayClient(cfg.relayURL, cfg.machineID, cfg.machinePrivate, nil, cfg.accessToken)
	if err != nil {
		return err
	}
	checkpoints, err := attachmentv2.OpenSQLiteCheckpointStore(cfg.checkpointPath)
	if err != nil {
		return err
	}
	defer checkpoints.Close()
	fresh, err := attachmentv2.NewFreshDirectoryAuthorityProvider(client, attachmentv2.DirectoryTrust{Audience: cfg.directoryAudience, RootKeyID: cfg.directoryRootKeyID, RootPublicKey: cfg.directoryRootPublic, Checkpoints: checkpoints})
	if err != nil {
		return err
	}
	authority, err := attachmentv3.NewDirectoryAuthorityAdapter(fresh)
	if err != nil {
		return err
	}
	artifacts, err := attachmentv3.OpenArtifactStore(cfg.artifactPath)
	if err != nil {
		return err
	}
	defer artifacts.Close()
	protector, err := newSenderKeyProtector()
	if err != nil {
		return err
	}
	outbox, err := adapter.OpenOfferNoticeOutbox(cfg.offerOutboxPath)
	if err != nil {
		return err
	}
	defer outbox.Close()
	stager, err := controller.NewSenderStager(controller.SenderStageOptions{Journal: journal, ArtifactStore: artifacts, BindingResolver: authority, Sender: cfg.sender, SigningKey: cfg.senderSigningPrivate, FileKeyProtector: protector, NewID: newID, ChunkSize: 64 << 10})
	if err != nil {
		return err
	}
	signer := controller.NewLocalSenderOperationSigner(cfg.sender, cfg.senderSigningPrivate)
	source, err := controller.NewSenderSourceInitializer(controller.SenderSourceInitializerOptions{Journal: journal, AuthorityProvider: senderAuthorityProvider{authority}, Signer: signer, Transport: client, NewID: newID, NewIdempotencyKey: newIdempotencyKey})
	if err != nil {
		return err
	}
	offer, err := controller.NewSenderOfferWorker(controller.SenderOfferWorkerOptions{Source: source, FileKeyProtector: protector, NewAcceptanceNonce: newIdempotencyKey, RelaySenderEndpoint: request.fromEndpoint, OfferNoticeQueue: outbox})
	if err != nil {
		return err
	}
	if err := client.ValidateSender(context.Background(), request.relayConversationID, request.fromEndpoint); err != nil {
		return errors.New("configured sender endpoint is not currently authorized")
	}
	manifest, err := stager.Stage(context.Background(), request.stageID, request.relayConversationID, plaintext)
	if err != nil {
		return err
	}
	result, err := offer.Offer(context.Background(), manifest.TransferID)
	if err != nil {
		return err
	}
	if err := outbox.Flush(context.Background(), client); err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"transfer_id\":%q,\"state\":%d}\n", base64.RawURLEncoding.EncodeToString(result.TransferID[:]), result.State)
	return err
}

func readPlaintextInput(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("sender input path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("sender input is unavailable")
	}
	// #nosec G304 -- the local caller selects this absolute source path; relay
	// data never controls it. The opened descriptor is checked against Lstat.
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("sender input is unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() > 64<<20 {
		return nil, errors.New("sender input is unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(file, 64<<20+1))
	if err != nil || len(data) > 64<<20 {
		return nil, errors.New("sender input is unavailable")
	}
	return data, nil
}

func recipientIdentityFromJournal(j *controller.Journal) (controller.RecipientIdentity, error) {
	// The journal is opened with this exact identity by openJournal; retrieve it
	// through its own immutable configuration rather than allowing a receive
	// command to select a device from flags or an offer.
	id, err := id16(os.Getenv("PUNARO_ATTACHMENT_RECIPIENT_ID"))
	if err != nil {
		return controller.RecipientIdentity{}, errors.New("invalid local recipient identity")
	}
	generation, err := strconv.ParseUint(os.Getenv("PUNARO_ATTACHMENT_RECIPIENT_GENERATION"), 10, 64)
	if err != nil || generation == 0 {
		return controller.RecipientIdentity{}, errors.New("invalid local recipient identity")
	}
	if j == nil {
		return controller.RecipientIdentity{}, errors.New("local journal is unavailable")
	}
	return controller.RecipientIdentity{DeviceID: id, Generation: generation}, nil
}

func senderIdentityFromConfig() (controller.SenderIdentity, error) {
	id, err := id16(os.Getenv("PUNARO_ATTACHMENT_SENDER_ID"))
	if err != nil {
		return controller.SenderIdentity{}, errors.New("invalid local sender identity")
	}
	generation, err := strconv.ParseUint(os.Getenv("PUNARO_ATTACHMENT_SENDER_GENERATION"), 10, 64)
	if err != nil || generation == 0 {
		return controller.SenderIdentity{}, errors.New("invalid local sender identity")
	}
	return controller.SenderIdentity{DeviceID: id, Generation: generation}, nil
}

func newID() ([16]byte, error) { var id [16]byte; _, err := rand.Read(id[:]); return id, err }
func newIdempotencyKey() ([32]byte, error) {
	var key [32]byte
	_, err := rand.Read(key[:])
	return key, err
}

func openJournal() (*controller.Journal, error) {
	path := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_CONTROLLER_JOURNAL"))
	id, err := id16(os.Getenv("PUNARO_ATTACHMENT_RECIPIENT_ID"))
	if err != nil {
		return nil, errorsConfig()
	}
	generation, err := strconv.ParseUint(os.Getenv("PUNARO_ATTACHMENT_RECIPIENT_GENERATION"), 10, 64)
	if err != nil || generation == 0 {
		return nil, errorsConfig()
	}
	return controller.OpenJournalForRecipient(path, controller.RecipientIdentity{DeviceID: id, Generation: generation})
}

func errorsConfig() error {
	return fmt.Errorf("PUNARO_ATTACHMENT_CONTROLLER_JOURNAL, PUNARO_ATTACHMENT_RECIPIENT_ID, and PUNARO_ATTACHMENT_RECIPIENT_GENERATION are required")
}

func runMap(args []string) error {
	mapping, err := parseMappingArgs(args)
	if err != nil {
		return err
	}
	j, err := openJournal()
	if err != nil {
		return err
	}
	defer j.Close()
	return j.AddMapping(mapping)
}

// runMapSender pins one operator-provided sender relationship in the source
// journal. The local sender identity must match the source side exactly;
// accepting a map for another sender would make later key use ambiguous.
func runMapSender(args []string) error {
	mapping, err := parseMappingArgs(args)
	if err != nil {
		return err
	}
	sender, err := senderIdentityFromConfig()
	if err != nil || mapping.SenderDeviceID != sender.DeviceID || mapping.SenderGeneration != sender.Generation {
		return errors.New("sender mapping source is not local")
	}
	path := strings.TrimSpace(os.Getenv("PUNARO_ATTACHMENT_SENDER_JOURNAL"))
	j, err := controller.OpenJournalForSender(path, sender)
	if err != nil {
		return err
	}
	defer j.Close()
	return j.AddMapping(mapping)
}

func parseMappingArgs(args []string) (controller.Mapping, error) {
	f := flag.NewFlagSet("map", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var relay, conversation, sender, recipient, commitment string
	var senderGen, recipientGen uint64
	f.StringVar(&relay, "relay-conversation", "", "relay conversation ID")
	f.StringVar(&conversation, "conversation-id", "", "directory conversation ID")
	f.StringVar(&sender, "sender-id", "", "sender device ID")
	f.Uint64Var(&senderGen, "sender-generation", 0, "sender generation")
	f.StringVar(&recipient, "recipient-id", "", "recipient device ID")
	f.Uint64Var(&recipientGen, "recipient-generation", 0, "recipient generation")
	f.StringVar(&commitment, "membership-commitment", "", "directory membership commitment")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return controller.Mapping{}, fmt.Errorf("invalid map arguments")
	}
	conversationID, err := id16(conversation)
	if err != nil {
		return controller.Mapping{}, fmt.Errorf("invalid directory conversation ID")
	}
	senderID, err := id16(sender)
	if err != nil {
		return controller.Mapping{}, fmt.Errorf("invalid sender device ID")
	}
	recipientID, err := id16(recipient)
	if err != nil {
		return controller.Mapping{}, fmt.Errorf("invalid recipient device ID")
	}
	membership, err := id32(commitment)
	if err != nil {
		return controller.Mapping{}, fmt.Errorf("invalid membership commitment")
	}
	return controller.Mapping{RelayConversationID: relay, ConversationID: conversationID, SenderDeviceID: senderID, SenderGeneration: senderGen, RecipientDeviceID: recipientID, RecipientGeneration: recipientGen, MembershipCommitment: membership}, nil
}

func runRecord(args []string) error {
	f := flag.NewFlagSet("record", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var message, relay, bodyFile string
	f.StringVar(&message, "message-id", "", "Punaro message ID")
	f.StringVar(&relay, "relay-conversation", "", "relay conversation ID")
	f.StringVar(&bodyFile, "body-file", "", "offer notice file or -")
	if f.Parse(args) != nil || f.NArg() != 0 || bodyFile == "" {
		return fmt.Errorf("invalid record arguments")
	}
	body, err := readBounded(bodyFile)
	if err != nil {
		return err
	}
	j, err := openJournal()
	if err != nil {
		return err
	}
	defer j.Close()
	_, created, err := j.RecordInboundOffer(controller.InboundOffer{PunaroMessageID: message, RelayConversationID: relay, Body: string(body)})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"recorded\":%t}\n", created)
	return err
}

func runApprove(args []string) error {
	f := flag.NewFlagSet("approve", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var message string
	f.StringVar(&message, "message-id", "", "recorded Punaro message ID")
	if f.Parse(args) != nil || f.NArg() != 0 || message == "" {
		return fmt.Errorf("invalid approve arguments")
	}
	j, err := openJournal()
	if err != nil {
		return err
	}
	defer j.Close()
	approved, err := j.ApproveInboundOffer(message, time.Now().UTC())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stdout, "{\"approved\":%t}\n", approved)
	return err
}

func id16(raw string) ([16]byte, error) {
	var result [16]byte
	value, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(value) != len(result) || base64.RawURLEncoding.EncodeToString(value) != raw {
		return result, fmt.Errorf("invalid ID")
	}
	copy(result[:], value)
	return result, nil
}
func id32(raw string) ([32]byte, error) {
	var result [32]byte
	value, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(value) != len(result) || base64.RawURLEncoding.EncodeToString(value) != raw {
		return result, fmt.Errorf("invalid commitment")
	}
	copy(result[:], value)
	return result, nil
}
func readBounded(path string) ([]byte, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, 32<<10+1))
	if err != nil || len(data) > 32<<10 {
		return nil, fmt.Errorf("offer body exceeds 32768 bytes")
	}
	return data, nil
}
