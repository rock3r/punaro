package telegram

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

type failSecondRichSender struct{ calls int }

func (s *failSecondRichSender) SendRichMessage(context.Context, int64, int64, string) (int64, error) {
	s.calls++
	if s.calls == 2 {
		return 0, errors.New("fixture send failure")
	}
	return int64(s.calls), nil
}

type fakeBridgeRelay struct {
	advertised []string
	deliveries []relay.Delivery
	acked      []string
	recordingClaimRelay
}

func (r *fakeBridgeRelay) Advertise(_ context.Context, endpoints []string) error {
	r.advertised = append([]string(nil), endpoints...)
	return nil
}

func (r *fakeBridgeRelay) Lease(context.Context, string) ([]relay.Delivery, error) {
	return r.deliveries, nil
}

func (r *fakeBridgeRelay) Ack(_ context.Context, delivery relay.Delivery) error {
	r.acked = append(r.acked, delivery.ID)
	return nil
}

func TestBridgeSyncsInboundAndOutboundThroughOneAttachedGatewayEndpoint(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	relayClient := &fakeBridgeRelay{deliveries: []relay.Delivery{{ID: "delivery-1", Message: relay.Message{ConversationID: "conversation-1", FromEndpoint: "agent/a", Body: "reply"}}}}
	richSender := &recordedRichSender{}
	submitted := 0
	bridge := Bridge{
		Relay:    relayClient,
		Endpoint: "telegram/gateway",
		State:    state,
		Poller:   fakePoller{updates: []Update{{ID: 10, UserID: 55, ChatID: 55, ThreadID: 7, Text: "question"}}},
		Gateway: Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error {
			submitted++
			return nil
		}},
		Sender: richSender,
	}
	next, err := bridge.SyncOnce(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if next != 11 || submitted != 1 || len(relayClient.advertised) != 1 || relayClient.advertised[0] != "telegram/gateway" || len(relayClient.acked) != 1 || relayClient.acked[0] != "delivery-1" || len(richSender.html) != 1 {
		t.Fatalf("next=%d submitted=%d advertised=%#v acked=%#v sent=%#v", next, submitted, relayClient.advertised, relayClient.acked, richSender.html)
	}
}

func TestBridgeReportsOutboundHeadProgressBeforeLaterSendFailure(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 7, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	relayClient := &fakeBridgeRelay{deliveries: []relay.Delivery{
		{ID: "delivery-1", Message: relay.Message{ID: "message-1", ConversationID: "conversation-1", FromEndpoint: "agent/a", Body: "first"}},
		{ID: "delivery-2", Message: relay.Message{ID: "message-2", ConversationID: "conversation-1", FromEndpoint: "agent/a", Body: "second"}},
	}}
	bridge := Bridge{
		Relay:    relayClient,
		Endpoint: "telegram/gateway",
		State:    state,
		Poller:   fakePoller{},
		Gateway:  Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error { return nil }},
		Sender:   &failSecondRichSender{},
	}
	_, err = bridge.SyncOnce(t.Context(), 10)
	var cycleErr *GatewayCycleError
	if !errors.As(err, &cycleErr) || cycleErr.Phase != GatewayPhaseSend || !cycleErr.OutboundBlocked || !cycleErr.OutboundProgress || len(relayClient.acked) != 1 || relayClient.acked[0] != "delivery-1" {
		t.Fatalf("err=%#v acked=%#v", cycleErr, relayClient.acked)
	}
}

func TestClassifyGatewayCycleFailureSeparatesRetryAndTerminalPlanes(t *testing.T) {
	t.Parallel()
	permanentRelay := permanentRelayFixtureError{}
	for _, test := range []struct {
		name  string
		err   error
		class GatewayFailureClass
	}{
		{name: "transient unauthorized Telegram", err: &GatewayCycleError{Phase: GatewayPhaseSend, Err: BotAPIStatusError{Method: "sendRichMessage", Status: 401}}, class: GatewayFailureTransient},
		{name: "deleted topic", err: &GatewayCycleError{Phase: GatewayPhaseSend, Err: BotAPIStatusError{Method: "sendRichMessage", Status: 400, Kind: BotAPIErrorDeletedTopic}}, class: GatewayFailureDeletedTopic},
		{name: "permanent outbound Telegram", err: &GatewayCycleError{Phase: GatewayPhaseSend, Err: BotAPIStatusError{Method: "sendRichMessage", Status: 403}}, class: GatewayFailureOutboundTelegramPermanent},
		{name: "permanent inbound relay", err: &GatewayCycleError{Phase: GatewayPhaseInbound, Err: permanentRelay}, class: GatewayFailureInboundRelayPermanent},
		{name: "permanent relay outside inbound", err: &GatewayCycleError{Phase: GatewayPhaseAdvertise, Err: permanentRelay}, class: GatewayFailureTransient},
		{name: "message-less poll", err: &GatewayCycleError{Phase: GatewayPhasePoll, Err: BotAPIStatusError{Method: "getUpdates", Status: 404}}, class: GatewayFailureMessageLessPoll},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyGatewayCycleFailure(test.err); got != test.class {
				t.Fatalf("class=%s want %s", got, test.class)
			}
		})
	}
}

type permanentRelayFixtureError struct{}

func (permanentRelayFixtureError) Error() string               { return "provider controlled" }
func (permanentRelayFixtureError) PermanentRelayFailure() bool { return true }

func TestBridgeResumesIncompleteClaimBeforePollingInbound(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, err := state.InsertPendingExecution("conversation-stuck", "Stuck room"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-stuck", 55, 7); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimRoute(55, 7, "conversation-stuck"); err != nil {
		t.Fatal(err)
	}
	relayClient := &fakeBridgeRelay{}
	submitted := 0
	executor := &ClaimExecutor{State: state, Relay: relayClient, AllowedUserID: 55, Log: func(string, ...any) {}}
	bridge := Bridge{
		Relay:    relayClient,
		Endpoint: relay.TelegramGatewayEndpoint,
		State:    state,
		Poller:   fakePoller{updates: []Update{{ID: 30, UserID: 55, ChatID: 55, ThreadID: 7, Text: "hello"}}},
		Gateway: Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error {
			complete, err := state.ClaimComplete("conversation-stuck")
			if err != nil {
				return err
			}
			if !complete {
				return fmt.Errorf("telegram inbound requires complete claim")
			}
			submitted++
			return nil
		}, Log: func(string, ...any) {}},
		Sender: &recordedRichSender{},
		Claims: executor,
	}
	next, err := bridge.SyncOnce(context.Background(), 30)
	if err != nil {
		t.Fatal(err)
	}
	resume, found, err := state.ClaimExecution("conversation-stuck")
	if err != nil || !found || resume.Phase != ClaimPhaseComplete {
		t.Fatalf("resume=%#v found=%v err=%v", resume, found, err)
	}
	if next != 31 || submitted != 1 || len(relayClient.completes) != 1 {
		t.Fatalf("next=%d submitted=%d completes=%#v", next, submitted, relayClient.completes)
	}
}

func TestBridgeResumesIncompleteClaimAndStartsPendingWithoutLocalRow(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, err := state.InsertPendingExecution("conversation-resume", "Resume room"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-resume", 55, 11); err != nil {
		t.Fatal(err)
	}
	relayClient := &fakeBridgeRelay{recordingClaimRelay: recordingClaimRelay{
		claim:   relay.TelegramClaim{ConversationID: "conversation-pending", Status: "pending", DisplayName: "Pending room"},
		pending: []relay.TelegramClaim{{ConversationID: "conversation-pending", Status: "pending", DisplayName: "Pending room"}},
	}}
	topics := &recordingTopicCreator{threadID: 22}
	var logs []string
	executor := &ClaimExecutor{State: state, Relay: relayClient, Topics: topics, AllowedUserID: 55, Log: func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }}
	bridge := Bridge{
		Relay:    relayClient,
		Endpoint: relay.TelegramGatewayEndpoint,
		State:    state,
		Poller:   fakePoller{},
		Gateway:  Gateway{AllowedUserID: 55, State: state, Submit: func(context.Context, Submission) error { return nil }, Log: func(string, ...any) {}},
		Sender:   &recordedRichSender{},
		Claims:   executor,
	}
	if _, err := bridge.SyncOnce(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	resume, found, err := state.ClaimExecution("conversation-resume")
	if err != nil || !found || resume.Phase != ClaimPhaseComplete || resume.ThreadID != 11 {
		t.Fatalf("resume=%#v found=%v err=%v", resume, found, err)
	}
	pending, found, err := state.ClaimExecution("conversation-pending")
	if err != nil || !found || pending.Phase != ClaimPhaseComplete || pending.ThreadID != 22 || !pending.SkipReserve {
		t.Fatalf("pending=%#v found=%v err=%v", pending, found, err)
	}
	if len(relayClient.reserves) != 0 {
		t.Fatalf("pending poll reserved again: %#v", relayClient.reserves)
	}
	if len(topics.names) != 1 || topics.names[0] != "Pending room" {
		t.Fatalf("pending createForumTopic=%#v", topics.names)
	}
}

func TestBridgeCallbackPersistsReservedBeforeConsumingToken(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	notify := &recordingNotify{}
	raw, err := state.IssueCallbackToken("conversation-1", testCallbackNow)
	if err != nil {
		t.Fatal(err)
	}
	relayClient := &fakeBridgeRelay{recordingClaimRelay: recordingClaimRelay{
		claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "Ops"},
	}}
	topics := &recordingTopicCreator{threadID: 33}
	executor := &ClaimExecutor{State: state, Relay: relayClient, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	bridge := Bridge{
		Relay:    relayClient,
		Endpoint: relay.TelegramGatewayEndpoint,
		State:    state,
		Poller:   fakePoller{updates: []Update{{ID: 20, UserID: 55, ChatID: 55, CallbackID: "cbq-1", CallbackData: raw}}},
		Gateway: Gateway{
			AllowedUserID: 55,
			State:         state,
			Submit:        func(context.Context, Submission) error { t.Fatal("callback submitted"); return nil },
			Notify:        notify,
			Claims:        executor,
			Now:           func() time.Time { return testCallbackNow },
			Log:           func(string, ...any) {},
		},
		Sender: &recordedRichSender{},
		Claims: executor,
	}
	next, err := bridge.SyncOnce(context.Background(), 20)
	if err != nil || next != 21 {
		t.Fatalf("next=%d err=%v", next, err)
	}
	if _, found, consumed, err := state.lookupCallbackToken(raw, testCallbackNow); err != nil || !found || !consumed {
		t.Fatalf("token found=%v consumed=%v err=%v", found, consumed, err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 33 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
}
