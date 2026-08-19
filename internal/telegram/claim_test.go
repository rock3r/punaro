package telegram

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rock3r/punaro/internal/relay"
)

type claimReserveCall struct {
	conversation string
	endpoint     string
	key          string
}

type recordingClaimRelay struct {
	reserves         []claimReserveCall
	completes        []string
	pending          []relay.TelegramClaim
	claim            relay.TelegramClaim
	reserveErr       error
	complete         relay.TelegramClaim
	pendingErr       error
	lastPendingLimit int
	pendingAfter     []string
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

func (r *recordingClaimRelay) PendingTelegramClaims(_ context.Context, limit int, after string) ([]relay.TelegramClaim, error) {
	r.lastPendingLimit = limit
	r.pendingAfter = append(r.pendingAfter, after)
	if r.pendingErr != nil {
		return nil, r.pendingErr
	}
	start := 0
	if after != "" {
		for i, claim := range r.pending {
			if claim.ConversationID == after {
				start = i + 1
				break
			}
		}
	}
	if start >= len(r.pending) {
		return nil, nil
	}
	rest := r.pending[start:]
	if limit < 1 || len(rest) <= limit {
		return rest, nil
	}
	return rest[:limit], nil
}

type adoptFenceRelay struct {
	state        *State
	claim        relay.TelegramClaim
	sawExecution bool
	completes    []string
}

func (r *adoptFenceRelay) ClaimConversation(_ context.Context, conversationID, _, _ string) (relay.TelegramClaim, error) {
	_, found, err := r.state.ClaimExecution(conversationID)
	if err != nil {
		return relay.TelegramClaim{}, err
	}
	r.sawExecution = found
	claim := r.claim
	if claim.ConversationID == "" {
		claim.ConversationID = conversationID
	}
	return claim, nil
}

func (r *adoptFenceRelay) CompleteTelegramClaim(_ context.Context, conversationID string) (relay.TelegramClaim, error) {
	r.completes = append(r.completes, conversationID)
	return relay.TelegramClaim{ConversationID: conversationID, Status: "complete", DisplayName: r.claim.DisplayName}, nil
}

func (r *adoptFenceRelay) PendingTelegramClaims(context.Context, int, string) ([]relay.TelegramClaim, error) {
	return nil, nil
}

type recordingTopicCreator struct {
	chatIDs  []int64
	names    []string
	threadID int64
	err      error
	onCreate func()
}

func (c *recordingTopicCreator) CreateForumTopic(_ context.Context, chatID int64, name string) (int64, error) {
	if c.onCreate != nil {
		c.onCreate()
	}
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

func TestExecuteClaimAdoptsRouteInsertedBetweenCheckAndCreatingFence(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 99}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	executor.beforeCreatingFence = func() {
		if err := state.SetRoute(55, 42, "conversation-1"); err != nil {
			t.Fatalf("inject SetRoute: %v", err)
		}
	}
	if err := executor.Execute(context.Background(), "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic after emergency route: %#v", topics.names)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 42 || execution.ChatID != 55 {
		t.Fatalf("adopted emergency route execution=%#v found=%v err=%v", execution, found, err)
	}
	conversation, found, err := state.Route(55, 42)
	if err != nil || !found || conversation != "conversation-1" {
		t.Fatalf("route conversation=%q found=%v err=%v", conversation, found, err)
	}
}

func TestExecuteClaimDoesNotWedgeOnForeignRacedRoute(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 99}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	executor.beforeCreatingFence = func() {
		if err := state.SetRoute(99, 42, "conversation-1"); err != nil {
			t.Fatalf("inject SetRoute: %v", err)
		}
	}
	if err := executor.Execute(context.Background(), "conversation-1"); err == nil || err.Error() != "telegram_route_persist_failed" {
		t.Fatalf("foreign route err=%v", err)
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic after foreign route: %#v", topics.names)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseReserved || execution.ThreadID != 0 {
		t.Fatalf("wedged execution=%#v found=%v err=%v", execution, found, err)
	}
	if err := state.RouteBlocked(55, 8, "conversation-1"); err != nil {
		t.Fatalf("reserved execution blocked route correction: %v", err)
	}
}

func TestExecuteClaimPersistsCreatingFenceBeforeCreateForumTopic(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 795446, onCreate: func() {
		execution, found, err := state.ClaimExecution("conversation-1")
		if err != nil || !found || execution.Phase != ClaimPhaseCreating || execution.ThreadID != 0 {
			t.Fatalf("createForumTopic without creating fence execution=%#v found=%v err=%v", execution, found, err)
		}
	}}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if len(topics.names) != 1 {
		t.Fatalf("createForumTopic names=%#v", topics.names)
	}
}

func TestExecuteClaimKeepsCreatingFenceAfterAmbiguousTopicCreateError(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{err: fmt.Errorf("telegram createForumTopic failed")}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err == nil {
		t.Fatal("ambiguous createForumTopic error was treated as success")
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseCreating || execution.ThreadID != 0 {
		t.Fatalf("fenced after ambiguous error execution=%#v found=%v err=%v", execution, found, err)
	}
	if err := executor.Execute(context.Background(), "conversation-1"); err == nil {
		t.Fatal("retry after ambiguous create cleared the fence")
	}
	if len(topics.names) != 1 {
		t.Fatalf("createForumTopic retried after ambiguous error: %#v", topics.names)
	}
}

func TestExecuteClaimRetriesAfterDefinitiveTopicCreateRejection(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{err: BotAPIStatusError{Method: "createForumTopic", Status: 429}}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err == nil {
		t.Fatal("HTTP 429 createForumTopic error was treated as success")
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseReserved || execution.ThreadID != 0 {
		t.Fatalf("retryable after HTTP 429 execution=%#v found=%v err=%v", execution, found, err)
	}
	topics.err = nil
	topics.threadID = 795446
	if err := executor.Execute(context.Background(), "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if len(topics.names) != 2 {
		t.Fatalf("createForumTopic after HTTP 429 names=%#v", topics.names)
	}
	execution, found, err = state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795446 {
		t.Fatalf("completed after HTTP 429 retry execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestExecuteClaimDoesNotRecreateTopicAfterCreatingFenceCrash(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "telegram.db")
	state, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	if err := state.PersistClaimDisplayName("conversation-1", "How is it going"); err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	if err := state.PersistClaimCreating("conversation-1"); err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	topics := &recordingTopicCreator{threadID: 1}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: restarted, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.ResumeAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic after creating-fence crash: %#v", topics.names)
	}
	execution, found, err := restarted.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseCreating || execution.ThreadID != 0 {
		t.Fatalf("fenced execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestExecuteClaimRecoversUnthreadedCreatingViaEmergencyRoute(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "telegram.db")
	state, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	if err := state.PersistClaimDisplayName("conversation-1", "How is it going"); err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	if err := state.PersistClaimCreating("conversation-1"); err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if err := restarted.SetRoute(55, 795446, "conversation-1"); err != nil {
		t.Fatalf("emergency route during unthreaded creating: %v", err)
	}
	topics := &recordingTopicCreator{threadID: 1}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: restarted, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.ResumeAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic after emergency route recovery: %#v", topics.names)
	}
	execution, found, err := restarted.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795446 || execution.ChatID != 55 {
		t.Fatalf("recovered execution=%#v found=%v err=%v", execution, found, err)
	}
	conversation, found, err := restarted.Route(55, 795446)
	if err != nil || !found || conversation != "conversation-1" {
		t.Fatalf("route conversation=%q found=%v err=%v", conversation, found, err)
	}
}

func TestExecuteClaimCreatingEmergencyRouteRejectsForeignChat(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimCreating("conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.SetRoute(99, 42, "conversation-1"); err != nil {
		t.Fatalf("emergency route during unthreaded creating: %v", err)
	}
	topics := &recordingTopicCreator{threadID: 1}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err == nil || err.Error() != "telegram_route_persist_failed" {
		t.Fatalf("foreign creating route err=%v", err)
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic after foreign creating route: %#v", topics.names)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseTopicCreated || execution.ThreadID != 42 || execution.ChatID != 99 {
		t.Fatalf("foreign bound execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestExecuteClaimTopicCreatedDoesNotRebindThreadToNewChat(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.PersistClaimThread("conversation-1", 55, 795446); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 1}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 99, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err == nil || err.Error() != "telegram_route_persist_failed" {
		t.Fatalf("topic_created thread was bound to a new allowed chat: err=%v", err)
	}
	if _, found, err := state.Route(99, 795446); err != nil || found {
		t.Fatalf("new chat route found=%v err=%v", found, err)
	}
	if _, found, err := state.Route(55, 795446); err != nil || found {
		t.Fatalf("mismatched resume inserted original chat route found=%v err=%v", found, err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseTopicCreated || execution.ThreadID != 795446 || execution.ChatID != 55 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
	if len(claims.completes) != 0 {
		t.Fatalf("completed after chat mismatch: %#v", claims.completes)
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic after topic_created: %#v", topics.names)
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
	if err := state.PersistClaimThread("conversation-1", 55, 795446); err != nil {
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
	if err := state.SetRoute(55, 9, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 99}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "complete", DisplayName: "Already"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic after complete+route: %#v", topics.names)
	}
	if len(claims.reserves) != 1 || claims.reserves[0].key != GatewayClaimKey("conversation-1") {
		t.Fatalf("reserves=%#v", claims.reserves)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 9 {
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
	if err := Adopt(context.Background(), state, claims, "conversation-1", 55, func(string, ...any) {}); err != nil {
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
	if err := Adopt(context.Background(), state, claims, "conversation-2", 55, func(string, ...any) {}); err != nil {
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

func TestExecuteClaimReusesExistingTopicRouteWithoutCreateForumTopic(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 795446, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 1}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic on already-routed conversation: %#v", topics.names)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795446 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
	conversation, found, err := state.Route(55, 795446)
	if err != nil || !found || conversation != "conversation-1" {
		t.Fatalf("route conversation=%q found=%v err=%v", conversation, found, err)
	}
}

func TestExecuteClaimFailsClosedWhenRelayClaimCompleteWithoutLocalRoute(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 99}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "complete", DisplayName: "Already"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err == nil {
		t.Fatal("complete relay claim without local route created a topic")
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic after complete without route: %#v", topics.names)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseReserved || execution.ThreadID != 0 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestExecuteClaimReusesRouteWhenRelayClaimAlreadyComplete(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 795625, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.ReserveClaimAndConsumeTokenMust(t, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 99}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "complete", DisplayName: "Already"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if len(topics.names) != 0 {
		t.Fatalf("createForumTopic after complete+route: %#v", topics.names)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795625 {
		t.Fatalf("execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestAdoptDoesNotDowngradeCompleteExecution(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 795446, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.AdoptExecution("conversation-1", 795446); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkClaimComplete("conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.AdoptExecution("conversation-1", 1); err != nil {
		t.Fatal(err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795446 {
		t.Fatalf("AdoptExecution downgraded complete: %#v found=%v err=%v", execution, found, err)
	}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "complete", DisplayName: "How is it going"}}
	if err := Adopt(context.Background(), state, claims, "conversation-1", 55, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if len(claims.completes) != 0 {
		t.Fatalf("complete adopt retried complete: %#v", claims.completes)
	}
	execution, found, err = state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795446 {
		t.Fatalf("downgraded execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestStartPendingSkipsLocalRowAndStartsLaterClaim(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if _, err := state.InsertPendingExecution("conversation-stuck", "Stuck"); err != nil {
		t.Fatal(err)
	}
	claims := &recordingClaimRelay{
		claim: relay.TelegramClaim{Status: "pending", DisplayName: "Next room"},
		pending: []relay.TelegramClaim{
			{ConversationID: "conversation-stuck", Status: "pending", DisplayName: "Stuck"},
			{ConversationID: "conversation-next", Status: "pending", DisplayName: "Next room"},
		},
	}
	topics := &recordingTopicCreator{threadID: 44}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.StartPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if claims.lastPendingLimit < 2 {
		t.Fatalf("pending poll limit=%d, want >= 2 so later rows are visible", claims.lastPendingLimit)
	}
	next, found, err := state.ClaimExecution("conversation-next")
	if err != nil || !found || next.Phase != ClaimPhaseComplete || next.ThreadID != 44 {
		t.Fatalf("later pending was not started: %#v found=%v err=%v", next, found, err)
	}
	stuck, found, err := state.ClaimExecution("conversation-stuck")
	if err != nil || !found || stuck.Phase != ClaimPhaseReserved {
		t.Fatalf("stuck local row was rewritten: %#v found=%v err=%v", stuck, found, err)
	}
}

func TestStartPendingPagesPastLocallyKnownClaims(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	pending := make([]relay.TelegramClaim, 0, 11)
	for i := 1; i <= 11; i++ {
		id := fmt.Sprintf("conversation-%02d", i)
		pending = append(pending, relay.TelegramClaim{ConversationID: id, Status: "pending", DisplayName: id})
		if i <= 10 {
			if _, err := state.InsertPendingExecution(id, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{Status: "pending", DisplayName: "Later"}, pending: pending}
	topics := &recordingTopicCreator{threadID: 99}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.StartPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(claims.pendingAfter) != 1 || claims.pendingAfter[0] != "" {
		t.Fatalf("first cycle pending after cursors=%#v", claims.pendingAfter)
	}
	if _, found, err := state.ClaimExecution("conversation-11"); err != nil || found {
		t.Fatal("eleventh pending started before scan budget rolled over")
	}
	if err := executor.StartPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(claims.pendingAfter) < 2 || claims.pendingAfter[1] != "conversation-10" {
		t.Fatalf("second cycle pending after cursors=%#v", claims.pendingAfter)
	}
	later, found, err := state.ClaimExecution("conversation-11")
	if err != nil || !found || later.Phase != ClaimPhaseComplete || later.ThreadID != 99 {
		t.Fatalf("eleventh pending was not started: %#v found=%v err=%v", later, found, err)
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
	if err := Adopt(context.Background(), state, claims, "conversation-missing", 55, func(string, ...any) {}); err == nil {
		t.Fatal("adopt without route succeeded")
	}
	if len(claims.reserves) != 0 {
		t.Fatalf("missing-route adopt reserved: %#v", claims.reserves)
	}
}

func TestExecuteCompleteRejectsRouteForDifferentTelegramChat(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(99, 795446, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	if err := state.AdoptExecution("conversation-1", 795446); err != nil {
		t.Fatal(err)
	}
	if err := state.MarkClaimComplete("conversation-1"); err != nil {
		t.Fatal(err)
	}
	topics := &recordingTopicCreator{threadID: 1}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "complete", DisplayName: "Ops"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.Execute(context.Background(), "conversation-1"); err == nil {
		t.Fatal("complete execution kept a foreign telegram chat")
	}
	if err := executor.ResumeAll(context.Background()); err == nil {
		t.Fatal("startup resume kept a completed foreign telegram chat")
	}
	if len(topics.names) != 0 || len(claims.completes) != 0 {
		t.Fatalf("foreign complete route touched bot/relay: topics=%#v completes=%#v", topics.names, claims.completes)
	}
}

func TestAdoptPersistsExecutionFromCurrentRouteTransaction(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("claim.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	start := strings.Index(src, "func Adopt(")
	if start < 0 {
		t.Fatal("Adopt missing")
	}
	rest := src[start:]
	end := strings.Index(rest[1:], "\nfunc ")
	if end < 0 {
		t.Fatal("Adopt unbounded")
	}
	fn := rest[:end+1]
	if !strings.Contains(fn, "AdoptExistingRoute") {
		t.Fatal("Adopt must persist claim_executions from the same transaction that re-reads topic_routes")
	}
	if strings.Contains(fn, "AdoptExecution") {
		t.Fatal("Adopt must not persist a stale thread id from a prior route lookup")
	}
	routeIdx := strings.Index(fn, "AdoptExistingRoute")
	reserveIdx := strings.Index(fn, "ClaimConversation")
	if routeIdx < 0 || reserveIdx < 0 || routeIdx > reserveIdx {
		t.Fatal("Adopt must persist the local route fence before the remote reservation")
	}
}

func TestAdoptFencesLocalRouteBeforeRemoteReserve(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(55, 795446, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	claims := &adoptFenceRelay{state: state, claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	if err := Adopt(context.Background(), state, claims, "conversation-1", 55, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if !claims.sawExecution {
		t.Fatal("remote reserve ran before the local adoption fence")
	}
}

func TestStartPendingBoundsExecuteWorkPerCycle(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	pending := make([]relay.TelegramClaim, 0, 11)
	for i := 1; i <= 11; i++ {
		id := fmt.Sprintf("conversation-%02d", i)
		pending = append(pending, relay.TelegramClaim{ConversationID: id, Status: "pending", DisplayName: id})
	}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{Status: "pending"}, pending: pending}
	topics := &recordingTopicCreator{}
	topics.onCreate = func() { topics.threadID++ }
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.StartPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	eleventh, found, err := state.ClaimExecution("conversation-11")
	if err != nil || found {
		t.Fatalf("eleventh claim consumed the cycle budget: %#v found=%v err=%v", eleventh, found, err)
	}
	tenth, found, err := state.ClaimExecution("conversation-10")
	if err != nil || !found || tenth.Phase != ClaimPhaseComplete {
		t.Fatalf("tenth pending was not started: %#v found=%v err=%v", tenth, found, err)
	}
	if err := executor.StartPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(claims.pendingAfter) < 2 || claims.pendingAfter[0] != "" || claims.pendingAfter[1] != "conversation-10" {
		t.Fatalf("pending after cursors=%#v", claims.pendingAfter)
	}
	later, found, err := state.ClaimExecution("conversation-11")
	if err != nil || !found || later.Phase != ClaimPhaseComplete {
		t.Fatalf("next cycle did not start the remaining claim: %#v found=%v err=%v", later, found, err)
	}
}

func TestResumeAllPagesCompletedRouteRevalidation(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile("claim.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	start := strings.Index(src, "func (e ClaimExecutor) rejectCompletedRouteMismatches")
	if start < 0 {
		t.Fatal("completed-route revalidation missing")
	}
	rest := src[start:]
	end := strings.Index(rest[1:], "\nfunc ")
	if end < 0 {
		t.Fatal("completed-route revalidation unbounded")
	}
	fn := rest[:end+1]
	if !strings.Contains(fn, "CompletedClaimExecutionsAfter") || !strings.Contains(fn, "pendingClaimPollLimit") {
		t.Fatal("completed-route revalidation must page with the per-cycle work budget")
	}
}

func TestResumeAllBoundsExecuteWorkPerCycle(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	for i := 1; i <= 11; i++ {
		id := fmt.Sprintf("conversation-%02d", i)
		if _, err := state.InsertPendingExecution(id, id); err != nil {
			t.Fatal(err)
		}
	}
	topics := &recordingTopicCreator{}
	topics.onCreate = func() { topics.threadID++ }
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{Status: "pending", DisplayName: "room"}}
	executor := ClaimExecutor{State: state, Relay: claims, Topics: topics, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.ResumeAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	eleventh, found, err := state.ClaimExecution("conversation-11")
	if err != nil || !found || eleventh.Phase != ClaimPhaseReserved {
		t.Fatalf("eleventh resume consumed the cycle budget: %#v found=%v err=%v", eleventh, found, err)
	}
	tenth, found, err := state.ClaimExecution("conversation-10")
	if err != nil || !found || tenth.Phase != ClaimPhaseComplete {
		t.Fatalf("tenth resume was not executed: %#v found=%v err=%v", tenth, found, err)
	}
	if err := executor.ResumeAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	later, found, err := state.ClaimExecution("conversation-11")
	if err != nil || !found || later.Phase != ClaimPhaseComplete {
		t.Fatalf("next cycle did not resume remaining claim: %#v found=%v err=%v", later, found, err)
	}
}

func TestResumeAllReservesAdoptingExecutionInsteadOfCompleting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "telegram.db")
	state, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetRoute(55, 795446, "conversation-1"); err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	if _, err := state.AdoptExistingRoute("conversation-1", 55); err != nil {
		_ = state.Close()
		t.Fatal(err)
	}
	execution, found, err := state.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseAdopting || execution.ThreadID != 795446 {
		_ = state.Close()
		t.Fatalf("pre-reserve adopt fence execution=%#v found=%v err=%v", execution, found, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	executor := ClaimExecutor{State: restarted, Relay: claims, AllowedUserID: 55, Log: func(string, ...any) {}}
	if err := executor.ResumeAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(claims.reserves) != 1 || claims.reserves[0].key != AdoptClaimKey("conversation-1") || claims.reserves[0].endpoint != relay.TelegramGatewayEndpoint {
		t.Fatalf("adopting resume reserves=%#v", claims.reserves)
	}
	if len(claims.completes) != 1 || claims.completes[0] != "conversation-1" {
		t.Fatalf("adopting resume completes=%#v", claims.completes)
	}
	execution, found, err = restarted.ClaimExecution("conversation-1")
	if err != nil || !found || execution.Phase != ClaimPhaseComplete || execution.ThreadID != 795446 {
		t.Fatalf("resumed adopting execution=%#v found=%v err=%v", execution, found, err)
	}
}

func TestAdoptRejectsRouteForDifferentTelegramChat(t *testing.T) {
	t.Parallel()
	state, err := Open(filepath.Join(t.TempDir(), "telegram.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if err := state.SetRoute(99, 795446, "conversation-1"); err != nil {
		t.Fatal(err)
	}
	claims := &recordingClaimRelay{claim: relay.TelegramClaim{ConversationID: "conversation-1", Status: "pending", DisplayName: "How is it going"}}
	if err := Adopt(context.Background(), state, claims, "conversation-1", 55, func(string, ...any) {}); err == nil {
		t.Fatal("adopt completed a route for a different telegram chat")
	}
	if len(claims.reserves) != 0 || len(claims.completes) != 0 {
		t.Fatalf("foreign-chat adopt touched relay: reserves=%#v completes=%#v", claims.reserves, claims.completes)
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
