package telegram

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/rock3r/punaro/internal/relay"
)

type claimReserveCall struct {
	conversation string
	endpoint     string
	key          string
}

type recordingClaimRelay struct {
	reserves   []claimReserveCall
	completes  []string
	pending    []relay.TelegramClaim
	claim      relay.TelegramClaim
	reserveErr error
	complete   relay.TelegramClaim
	pendingErr error
}

func (r *recordingClaimRelay) ClaimConversation(_ context.Context, conversationID, endpoint, idempotencyKey string) (relay.TelegramClaim, error) {
	r.reserves = append(r.reserves, claimReserveCall{conversation: conversationID, endpoint: endpoint, key: idempotencyKey})
	if r.reserveErr != nil {
		return relay.TelegramClaim{}, r.reserveErr
	}
	claim := r.claim
	if claim.ConversationID == "" {
		claim.ConversationID = conversationID
	}
	if claim.Status == "" {
		claim.Status = "pending"
	}
	return claim, nil
}

func (r *recordingClaimRelay) CompleteTelegramClaim(_ context.Context, conversationID string) (relay.TelegramClaim, error) {
	r.completes = append(r.completes, conversationID)
	if r.complete.ConversationID != "" {
		return r.complete, nil
	}
	return relay.TelegramClaim{ConversationID: conversationID, Status: "complete", DisplayName: r.claim.DisplayName}, nil
}

func (r *recordingClaimRelay) PendingTelegramClaims(context.Context, int) ([]relay.TelegramClaim, error) {
	if r.pendingErr != nil {
		return nil, r.pendingErr
	}
	return r.pending, nil
}

type recordingTopicCreator struct {
	chatIDs  []int64
	names    []string
	threadID int64
	err      error
}

func (c *recordingTopicCreator) CreateForumTopic(_ context.Context, chatID int64, name string) (int64, error) {
	c.chatIDs = append(c.chatIDs, chatID)
	c.names = append(c.names, name)
	if c.err != nil {
		return 0, c.err
	}
	if c.threadID == 0 {
		return 1, nil
	}
	return c.threadID, nil
}

func TestExecuteClaimCreatesTopicPersistsThreadThenCompletes(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	var logs []string
	topics := &recordingTopicCreator{threadID: 795446}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }}
	if err := executor.Execute(context.Background(), "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if len(topics.names) != 1 || topics.names[0] != "How is it going" || topics.chatIDs[0] != 55 {
		t.Fatalf("createForumTopic names=%#v chats=%#v", topics.names, topics.chatIDs)
	}
	if len(claims.reserves) != 1 || claims.reserves[0].key != GatewayClaimKey("conversation-1") || claims.reserves[0].endpoint != relay.TelegramGatewayEndpoint {
		t.Fatalf("reserves=%#v", claims.reserves)
	}
	if len(claims.completes) != 1 || claims.completes[0] != "conversation-1" {
		t.Fatalf("completes=%#v", claims.completes)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795446 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
	conversation, found, err := state.Route(55, 795446)
	if err != nil || !found || conversation != "conversation-1" {
		t.Fatalf("route conversation=%q found=%v err=%v", conversation, found, err)
	}
	if !hasLogClass(logs, "telegram_claim_completed") {
		t.Fatalf("logs=%#v", logs)
	}
}

func TestExecuteClaimReusesStoredThreadAndNeverCreatesTwice(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-1", 795446); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 1}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic called again: %#v", topics.names)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795446 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestExecuteClaimSkipsReserveWhenPulledFromPending(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, err := state.InsertPendingExecution("conversation-1", "Agent room"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 88}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "Agent room"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if len(claims.reserves) != 0 {
		t.Fatalf("pending execution reserved again: %#v", claims.reserves)
	}
	if len(claims.completes) != 1 {
		t.Fatalf("completes=%#v", claims.completes)
	}
}

func TestExecuteClaimTreatsExistingPendingOrCompleteAsSuccess(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 9}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "complete", DisplayName: "Already"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if len(claims.reserves) != 1 || claims.reserves[0].key != GatewayClaimKey("conversation-1") {
		t.Fatalf("reserves=%#v", claims.reserves)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestAdoptUsesExistingRouteWithoutCreateForumTopic(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 795446, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	if err := Adopt(context.Background(), state, claims, "conversation-1", func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if len(claims.reserves) != 1 || claims.reserves[0].key != AdoptClaimKey("conversation-1") || claims.reserves[0].endpoint != relay.TelegramGatewayEndpoint {
		t.Fatalf("reserves=%#v", claims.reserves)
	}
	if len(claims.completes) != 1 {
		t.Fatalf("completes=%#v", claims.completes)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795446 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestAdoptAlreadyCompleteIsNoopSuccess(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 795625, "conversation-2"); err != nil {
		t.Fatal(err)
	}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-2", Status: "complete", DisplayName: "Other"}}
	if err := Adopt(context.Background(), state, claims, "conversation-2", func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if len(claims.completes) != 0 {
		t.Fatalf("complete-status adopt was not a no-op: completes=%#v", claims.completes)
	}
	execution, found, err := state.ClaimExecution("conversation-2")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795625 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestAdoptRequiresExistingRoute(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{Status: "pending", DisplayName: "Ops"}}
	if err := Adopt(context.Background(), state, claims, "conversation-missing", func(string, ...any) {}); err == nil {
		t.Fatal("adopt without route succeeded")
	}
	if len(claims.reserves) != 0 {
		t.Fatalf("missing-route adopt reserved: %#v", claims.reserves)
	}
}

func (s *State) ReserveClaimAndConsumeTokenMust(t *testing.T, conversationID string) (string, bool, error) {
	t.Helper()
	raw, err := s.IssueCallbackToken(conversationID, testCallbackNow)
	if err != nil {
		return "", false, err
	}
	return s.ReserveClaimAndConsumeToken(raw, testCallbackNow)
}
