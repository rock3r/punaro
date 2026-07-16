// punaro-attachment is the narrow local control surface for v3 attachment
// discovery. It intentionally has no command that accepts arbitrary network
// URLs, permit bytes, device keys, or Access credentials.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/attachment/v3/controller"
)

func main() {
	var err error
	switch {
	case len(os.Args) >= 2 && os.Args[1] == "map":
		err = runMap(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "record":
		err = runRecord(os.Args[2:])
	case len(os.Args) >= 2 && os.Args[1] == "approve":
		err = runApprove(os.Args[2:])
	default:
		err = fmt.Errorf("supported commands: map, record, approve")
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "punaro-attachment:", err)
		os.Exit(2)
	}
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
		return fmt.Errorf("invalid map arguments")
	}
	conversationID, err := id16(conversation)
	if err != nil {
		return fmt.Errorf("invalid directory conversation ID")
	}
	senderID, err := id16(sender)
	if err != nil {
		return fmt.Errorf("invalid sender device ID")
	}
	recipientID, err := id16(recipient)
	if err != nil {
		return fmt.Errorf("invalid recipient device ID")
	}
	membership, err := id32(commitment)
	if err != nil {
		return fmt.Errorf("invalid membership commitment")
	}
	j, err := openJournal()
	if err != nil {
		return err
	}
	defer j.Close()
	return j.AddMapping(controller.Mapping{RelayConversationID: relay, ConversationID: conversationID, SenderDeviceID: senderID, SenderGeneration: senderGen, RecipientDeviceID: recipientID, RecipientGeneration: recipientGen, MembershipCommitment: membership})
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
