package adapter

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

func TestSyncOnceAdvertisesAttachmentsForwardsThenAcknowledges(t *testing.T) {
	t.Parallel()
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mailbox := &fakeMailbox{attached: []string{"agent/reviewer"}}
	relayClient := &fakeRelay{deliveries: map[string][]relay.Delivery{"agent/reviewer": {{ID: "delivery-1", Message: relay.Message{ID: "message-1", ConversationID: "conversation-1", Sequence: 7, FromEndpoint: "agent/sender", Body: "ship it"}, LeaseToken: "lease", LeaseGeneration: 1}}}}
	sync := Syncer{Mailbox: mailbox, Relay: relayClient, Journal: journal, Now: func() time.Time { return time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC) }}
	if err := sync.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(relayClient.advertised) != 1 || relayClient.advertised[0] != "agent/reviewer" {
		t.Fatalf("advertised = %#v", relayClient.advertised)
	}
	if len(mailbox.sent) != 1 || mailbox.sent[0].PunaroMessageID != "message-1" || mailbox.sent[0].Body != "ship it" {
		t.Fatalf("mailbox sent = %#v", mailbox.sent)
	}
	if len(relayClient.acknowledged) != 1 || relayClient.acknowledged[0] != "delivery-1" {
		t.Fatalf("acks = %#v", relayClient.acknowledged)
	}
}

func TestSyncOnceRetriesAckWithoutSendingForwardedMessageAgain(t *testing.T) {
	t.Parallel()
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	if err := journal.MarkForwarded("delivery-1", "message-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	mailbox := &fakeMailbox{attached: []string{"agent/reviewer"}}
	relayClient := &fakeRelay{deliveries: map[string][]relay.Delivery{"agent/reviewer": {{ID: "delivery-1", Message: relay.Message{ID: "message-1", ConversationID: "conversation-1"}, LeaseToken: "lease", LeaseGeneration: 2}}}}
	sync := Syncer{Mailbox: mailbox, Relay: relayClient, Journal: journal}
	if err := sync.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(mailbox.sent) != 0 {
		t.Fatalf("forwarded delivery was sent again: %#v", mailbox.sent)
	}
	if len(relayClient.acknowledged) != 1 {
		t.Fatalf("acknowledged = %#v", relayClient.acknowledged)
	}
}

func TestSyncOnceDoesNotAcknowledgeWhenMailboxInjectionFails(t *testing.T) {
	t.Parallel()
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "adapter.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	mailbox := &fakeMailbox{attached: []string{"agent/reviewer"}, sendErr: errors.New("mailbox unavailable")}
	relayClient := &fakeRelay{deliveries: map[string][]relay.Delivery{"agent/reviewer": {{ID: "delivery-1", Message: relay.Message{ID: "message-1"}, LeaseToken: "lease", LeaseGeneration: 1}}}}
	sync := Syncer{Mailbox: mailbox, Relay: relayClient, Journal: journal}
	if err := sync.SyncOnce(context.Background()); err == nil {
		t.Fatal("mailbox failure reported success")
	}
	if len(relayClient.acknowledged) != 0 {
		t.Fatalf("acknowledged after failed injection: %#v", relayClient.acknowledged)
	}
}

type fakeMailbox struct {
	attached []string
	sent     []InboundMessage
	sendErr  error
}

func (m *fakeMailbox) Attached(context.Context) ([]string, error) { return m.attached, nil }
func (m *fakeMailbox) Send(_ context.Context, _ string, message InboundMessage) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, message)
	return nil
}

type fakeRelay struct {
	advertised   []string
	deliveries   map[string][]relay.Delivery
	acknowledged []string
}

func (r *fakeRelay) Advertise(_ context.Context, endpoints []string) error {
	r.advertised = append([]string(nil), endpoints...)
	return nil
}
func (r *fakeRelay) Lease(_ context.Context, endpoint string) ([]relay.Delivery, error) {
	return r.deliveries[endpoint], nil
}
func (r *fakeRelay) Ack(_ context.Context, delivery relay.Delivery) error {
	r.acknowledged = append(r.acknowledged, delivery.ID)
	return nil
}
