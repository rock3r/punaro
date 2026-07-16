package adapter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/rock3r/punaro/internal/relay"
)

func TestOfferNoticeOutboxPersistsExactNoticeUntilRelayAcceptsIt(t *testing.T) {
	path := filepath.Join(privateOutboxDir(t), "offer-notices.db")
	raw := testV3OfferNotice(t)
	outbox, err := OpenOfferNoticeOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.EnqueueV3OfferNotice(context.Background(), "conversation-1", "agent/a", raw, "offer-1"); err != nil {
		t.Fatal(err)
	}
	if err := outbox.EnqueueV3OfferNotice(context.Background(), "conversation-1", "agent/a", raw, "offer-1"); err != nil {
		t.Fatalf("exact queue retry failed: %v", err)
	}
	if err := outbox.EnqueueV3OfferNotice(context.Background(), "conversation-2", "agent/a", raw, "offer-1"); err == nil {
		t.Fatal("changed idempotency routing accepted")
	}
	failing := &offerNoticeSenderStub{err: errors.New("offline")}
	if err := outbox.Flush(context.Background(), failing); err == nil || failing.calls != 1 {
		t.Fatalf("failed flush err=%v calls=%d", err, failing.calls)
	}
	if err := outbox.Close(); err != nil {
		t.Fatal(err)
	}
	outbox, err = OpenOfferNoticeOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	sender := &offerNoticeSenderStub{}
	if err := outbox.Flush(context.Background(), sender); err != nil || sender.calls != 1 {
		t.Fatalf("flush err=%v calls=%d", err, sender.calls)
	}
	notice, err := attachmentv3.DecodeOfferNotice(sender.body)
	if err != nil || string(notice.Raw) != string(raw) || sender.conversation != "conversation-1" || sender.endpoint != "agent/a" || sender.key != "offer-1" {
		t.Fatalf("sent=%+v notice=%+v err=%v", sender, notice, err)
	}
	if err := outbox.Flush(context.Background(), sender); err != nil || sender.calls != 1 {
		t.Fatalf("delivered outbox retried err=%v calls=%d", err, sender.calls)
	}
}

func TestOfferNoticeOutboxTreatsConcurrentIdenticalDeliveryAsSuccess(t *testing.T) {
	path := filepath.Join(privateOutboxDir(t), "offer-notices.db")
	outbox, err := OpenOfferNoticeOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	if err := outbox.EnqueueV3OfferNotice(context.Background(), "conversation-1", "agent/a", testV3OfferNotice(t), "offer-1"); err != nil {
		t.Fatal(err)
	}
	sender := &offerNoticeSenderStub{beforeReturn: func() {
		if _, err := outbox.db.Exec(`DELETE FROM v3_offer_notice_outbox WHERE idempotency_key='offer-1'`); err != nil {
			t.Errorf("concurrent delivery delete: %v", err)
		}
	}}
	if err := outbox.Flush(context.Background(), sender); err != nil || sender.calls != 1 {
		t.Fatalf("flush err=%v calls=%d", err, sender.calls)
	}
}

func TestOfferNoticeOutboxClearsProvenPreAppendRejection(t *testing.T) {
	outbox, err := OpenOfferNoticeOutbox(filepath.Join(privateOutboxDir(t), "offer-notices.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	if err := outbox.EnqueueV3OfferNotice(context.Background(), "conversation-1", "agent/a", testV3OfferNotice(t), "offer-1"); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Flush(context.Background(), terminalOfferNoticeSender{}); err == nil {
		t.Fatal("terminal rejection accepted")
	}
	if err := outbox.EnqueueV3OfferNotice(context.Background(), "conversation-1", "agent/corrected", testV3OfferNotice(t), "offer-1"); err != nil {
		t.Fatalf("terminal rejected route remained pinned: %v", err)
	}
}

func TestOfferNoticeOutboxRejectsUnsafePathsAndBoundsPendingRows(t *testing.T) {
	unsafeParent := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafeParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOfferNoticeOutbox(filepath.Join(unsafeParent, "outbox.db")); err == nil {
		t.Fatal("world-accessible outbox parent accepted")
	}
	privateParent := privateOutboxDir(t)
	database := filepath.Join(privateParent, "outbox.db")
	if err := os.WriteFile(database, []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOfferNoticeOutbox(database); err == nil {
		t.Fatal("group-readable outbox database accepted")
	}
	if err := os.Remove(database); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.db")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, database); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOfferNoticeOutbox(database); err == nil {
		t.Fatal("symlinked outbox database accepted")
	}
	if err := os.Remove(database); err != nil {
		t.Fatal(err)
	}
	outbox, err := OpenOfferNoticeOutbox(database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	raw := testV3OfferNotice(t)
	for index := 0; index < maxOfferNoticeOutboxRows; index++ {
		if err := outbox.EnqueueV3OfferNotice(context.Background(), "conversation-1", "agent/a", raw, fmt.Sprintf("offer-%d", index)); err != nil {
			t.Fatalf("enqueue %d: %v", index, err)
		}
	}
	if err := outbox.EnqueueV3OfferNotice(context.Background(), "conversation-1", "agent/a", raw, "offer-overflow"); err == nil {
		t.Fatal("unbounded offer notice outbox accepted another row")
	}
	if err := outbox.EnqueueV3OfferNotice(context.Background(), strings.Repeat("c", maxOfferNoticeConversationBytes+1), "agent/a", raw, "offer-route-too-large"); err == nil {
		t.Fatal("oversized outbox conversation accepted")
	}
	if err := outbox.EnqueueV3OfferNotice(context.Background(), "conversation-1", "agent/a", raw, strings.Repeat("k", maxOfferNoticeIdempotencyBytes+1)); err == nil {
		t.Fatal("oversized outbox idempotency key accepted")
	}
}

func TestOfferNoticeOutboxHeldReservationIsNotFlushedUntilActivated(t *testing.T) {
	outbox, err := OpenOfferNoticeOutbox(filepath.Join(privateOutboxDir(t), "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	raw := testV3OfferNotice(t)
	if err := outbox.ReserveV3OfferNotice(context.Background(), "conversation-1", "agent/a", raw, "offer-1"); err != nil {
		t.Fatal(err)
	}
	sender := &offerNoticeSenderStub{}
	if err := outbox.Flush(context.Background(), sender); err != nil || sender.calls != 0 {
		t.Fatalf("held reservation flushed err=%v calls=%d", err, sender.calls)
	}
	if err := outbox.ActivateV3OfferNotice(context.Background(), "offer-1"); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Flush(context.Background(), sender); err != nil || sender.calls != 1 {
		t.Fatalf("activated reservation was not flushed err=%v calls=%d", err, sender.calls)
	}
}

func TestOfferNoticeOutboxRetainsExpiredHeldReservationsUntilSenderRecovery(t *testing.T) {
	outbox, err := OpenOfferNoticeOutbox(filepath.Join(privateOutboxDir(t), "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	for index := 0; index < maxOfferNoticeOutboxRows; index++ {
		if _, err := outbox.db.Exec(`INSERT INTO v3_offer_notice_outbox(idempotency_key, conversation_id, from_endpoint, body, active, created_at) VALUES (?, 'conversation-1', 'agent/a', 'held', 0, ?)`, fmt.Sprintf("held-%d", index), time.Now().Add(-24*time.Hour).UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	if err := outbox.ReserveV3OfferNotice(context.Background(), "conversation-1", "agent/a", testV3OfferNotice(t), "fresh"); err == nil {
		t.Fatal("stale held reservation was deleted without sender outcome recovery")
	}
}

func TestOfferNoticeOutboxCountsUTF8BytesRatherThanCharacters(t *testing.T) {
	outbox, err := OpenOfferNoticeOutbox(filepath.Join(privateOutboxDir(t), "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	raw := testV3OfferNotice(t)
	notice, err := attachmentv3.EncodeOfferNotice(raw)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := strings.Repeat("é", maxOfferNoticeIdempotencyBytes/len("é"))
	oldConversation, oldEndpoint := "c", "e"
	newKey, newConversation, newEndpoint := "new-key", "room", "agent/a"
	oldFieldBytes := len(oldKey) + len(oldConversation) + len(oldEndpoint)
	newFieldBytes := len(newKey) + len(newConversation) + len(newEndpoint)
	bodyLength := maxOfferNoticeOutboxBytes - oldFieldBytes - len(notice) - newFieldBytes + 1
	if bodyLength <= 0 {
		t.Fatal("invalid UTF-8 capacity test setup")
	}
	if _, err := outbox.db.Exec(`INSERT INTO v3_offer_notice_outbox(idempotency_key, conversation_id, from_endpoint, body, created_at) VALUES (?, ?, ?, ?, 0)`, oldKey, oldConversation, oldEndpoint, strings.Repeat("x", bodyLength)); err != nil {
		t.Fatal(err)
	}
	if err := outbox.EnqueueV3OfferNotice(context.Background(), newConversation, newEndpoint, raw, newKey); err == nil {
		t.Fatal("UTF-8 byte-over-capacity outbox row accepted")
	}
}

func privateOutboxDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

type offerNoticeSenderStub struct {
	calls                             int
	conversation, endpoint, body, key string
	err                               error
	beforeReturn                      func()
}

type terminalOfferNoticeSender struct{}

func (terminalOfferNoticeSender) Send(context.Context, string, string, string, string) (relay.Message, error) {
	return relay.Message{}, terminalOfferNoticeError{}
}

type terminalOfferNoticeError struct{}

func (terminalOfferNoticeError) Error() string                     { return "forbidden" }
func (terminalOfferNoticeError) PermanentOfferNoticeFailure() bool { return true }

func (s *offerNoticeSenderStub) Send(_ context.Context, conversation, endpoint, body, key string) (relay.Message, error) {
	s.calls++
	s.conversation, s.endpoint, s.body, s.key = conversation, endpoint, body, key
	if s.err != nil {
		return relay.Message{}, s.err
	}
	if s.beforeReturn != nil {
		s.beforeReturn()
	}
	return relay.Message{ID: "message-1"}, nil
}
