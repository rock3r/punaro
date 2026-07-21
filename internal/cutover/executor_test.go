package cutover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rock3r/punaro/internal/operator"
	"github.com/rock3r/punaro/internal/postgres"
	"github.com/rock3r/punaro/internal/relay"
)

func TestExecutorCrossesBoundariesInOrderAndPublishesLast(t *testing.T) {
	t.Parallel()
	manifest := testManifest(relay.MigrationSourceActive)
	var events []string
	source := &fakeSource{manifest: manifest, events: &events}
	destination := &fakeDestination{identity: manifest.TargetIdentity, events: &events}
	publisher := func(_ context.Context, publication operator.MailCutoverPublication) error {
		events = append(events, "publish")
		if publication.EpochID != manifest.EpochID || publication.SourceFingerprint == "" {
			t.Fatalf("publication=%#v", publication)
		}
		return nil
	}
	executor := Executor{Source: source, Destination: destination, Publish: publisher, BatchSize: 1, Enrollment: "test-enrollment"}
	result, err := executor.Execute(context.Background(), Request{ActorPrincipalID: "11111111-1111-4111-8111-111111111111", EpochID: manifest.EpochID, ExpectedSourceFingerprint: manifest.Fingerprint, Cutoff: time.Now().UTC()})
	if err != nil || result.Phase != postgres.MailCutoverActive || result.SourcePhase != relay.MigrationSourceRetired {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	want := []string{"schema-readiness", "identity", "inspect", "coverage", "prepare", "coverage", "begin", "checkpoint:mail_endpoints", "read:mail_endpoints", "stage:mail_endpoints"}
	if len(events) < len(want) || !reflect.DeepEqual(events[:len(want)], want) {
		t.Fatalf("events=%v want prefix=%v", events, want)
	}
	readinessIndex, retireIndex, activateIndex, publishIndex := indexOf(events, "activation-readiness"), indexOf(events, "retire"), indexOf(events, "activate"), indexOf(events, "publish")
	if readinessIndex < 0 || retireIndex <= readinessIndex || activateIndex <= retireIndex || publishIndex <= activateIndex || events[len(events)-1] != "publish" {
		t.Fatalf("irreversible ordering=%v", events)
	}
}

func TestExecutorDoesNotSealAfterImportFailureAndRecoversActivePublication(t *testing.T) {
	t.Parallel()
	manifest := testManifest(relay.MigrationSourceActive)
	var failedEvents []string
	failing := &fakeDestination{identity: manifest.TargetIdentity, events: &failedEvents, stageErr: errors.New("injected stage failure")}
	if _, err := (Executor{Source: &fakeSource{manifest: manifest, events: &failedEvents}, Destination: failing, Publish: func(context.Context, operator.MailCutoverPublication) error {
		failedEvents = append(failedEvents, "publish")
		return nil
	}, BatchSize: 1, Enrollment: "test-enrollment"}).Execute(context.Background(), Request{ActorPrincipalID: "11111111-1111-4111-8111-111111111111", EpochID: manifest.EpochID, ExpectedSourceFingerprint: manifest.Fingerprint, Cutoff: time.Now().UTC()}); err == nil {
		t.Fatal("injected import failure succeeded")
	}
	if indexOf(failedEvents, "retire") >= 0 || indexOf(failedEvents, "activate") >= 0 || indexOf(failedEvents, "publish") >= 0 {
		t.Fatalf("failure crossed irreversible boundary: %v", failedEvents)
	}

	retired := testManifest(relay.MigrationSourceRetired)
	var recoveryEvents []string
	recoveryDestination := &fakeDestination{identity: retired.TargetIdentity, phase: postgres.MailCutoverActive, events: &recoveryEvents}
	result, err := (Executor{Source: &fakeSource{manifest: retired, events: &recoveryEvents}, Destination: recoveryDestination, Publish: func(context.Context, operator.MailCutoverPublication) error {
		recoveryEvents = append(recoveryEvents, "publish")
		return nil
	}, BatchSize: 1, Enrollment: "test-enrollment"}).Execute(context.Background(), Request{ActorPrincipalID: "11111111-1111-4111-8111-111111111111", EpochID: retired.EpochID, ExpectedSourceFingerprint: retired.ExpectedFingerprint, Cutoff: time.Now().UTC()})
	if err != nil || result.Phase != postgres.MailCutoverActive || !reflect.DeepEqual(recoveryEvents, []string{"schema-readiness", "identity", "inspect", "coverage", "begin", "publish"}) {
		t.Fatalf("recovery result=%#v events=%v err=%v", result, recoveryEvents, err)
	}
	changedEvents := []string{}
	if _, err := (Executor{Source: &fakeSource{manifest: retired, events: &changedEvents}, Destination: &fakeDestination{identity: retired.TargetIdentity, phase: postgres.MailCutoverActive, events: &changedEvents}, Publish: func(context.Context, operator.MailCutoverPublication) error { return nil }, BatchSize: 1, Enrollment: "test-enrollment"}).Execute(context.Background(), Request{ActorPrincipalID: "11111111-1111-4111-8111-111111111111", EpochID: retired.EpochID, ExpectedSourceFingerprint: strings.Repeat("f", 64), Cutoff: time.Now().UTC()}); err == nil || indexOf(changedEvents, "begin") >= 0 {
		t.Fatalf("changed recovery binding events=%v err=%v", changedEvents, err)
	}
}

func TestExecutorChecksActivationReadinessBeforeRetiringSource(t *testing.T) {
	t.Parallel()
	prepared := testManifest(relay.MigrationSourcePrepared)
	var events []string
	readinessErr := errors.New("pending legacy machine")
	source := &fakeSource{manifest: prepared, events: &events}
	destination := &fakeDestination{identity: prepared.TargetIdentity, phase: postgres.MailCutoverVerified, events: &events, readinessErr: readinessErr}
	executor := Executor{Source: source, Destination: destination, Publish: func(context.Context, operator.MailCutoverPublication) error { return nil }, Enrollment: "test-enrollment"}
	_, err := executor.Execute(context.Background(), Request{ActorPrincipalID: "11111111-1111-4111-8111-111111111111", EpochID: prepared.EpochID, ExpectedSourceFingerprint: prepared.ExpectedFingerprint, Cutoff: time.Now().UTC()})
	if !errors.Is(err, readinessErr) || source.manifest.Phase != relay.MigrationSourcePrepared || indexOf(events, "activation-readiness") < 0 || indexOf(events, "retire") >= 0 {
		t.Fatalf("source=%#v events=%v err=%v", source.manifest, events, err)
	}
}

func TestDryRunDoesNotMutateEitherAuthority(t *testing.T) {
	t.Parallel()
	manifest := testManifest(relay.MigrationSourceActive)
	var events []string
	plan, err := (Executor{Source: &fakeSource{manifest: manifest, events: &events}, Destination: &fakeDestination{identity: manifest.TargetIdentity, events: &events}}).DryRun(context.Background())
	if err != nil || plan.SourceFingerprint != manifest.Fingerprint || plan.TargetIdentity != manifest.TargetIdentity || !reflect.DeepEqual(events, []string{"schema-readiness", "identity", "inspect"}) {
		t.Fatalf("plan=%#v events=%v err=%v", plan, events, err)
	}
}

func TestExecutorRequiresCurrentDestinationSchemaBeforeInspectingSource(t *testing.T) {
	t.Parallel()
	manifest := testManifest(relay.MigrationSourceActive)
	var events []string
	readinessErr := errors.New("destination schema is not current")
	executor := Executor{
		Source:      &fakeSource{manifest: manifest, events: &events},
		Destination: &fakeDestination{identity: manifest.TargetIdentity, events: &events, schemaReadinessErr: readinessErr},
		Publish:     func(context.Context, operator.MailCutoverPublication) error { return nil },
		Enrollment:  "test-enrollment",
	}
	_, err := executor.Execute(context.Background(), Request{ActorPrincipalID: "11111111-1111-4111-8111-111111111111", EpochID: manifest.EpochID, ExpectedSourceFingerprint: manifest.Fingerprint, Cutoff: time.Now().UTC()})
	if !errors.Is(err, readinessErr) || !reflect.DeepEqual(events, []string{"schema-readiness"}) {
		t.Fatalf("events=%v err=%v", events, err)
	}
}

func TestExecutorRefusesUncoveredEnrollmentBeforePreparingSource(t *testing.T) {
	t.Parallel()
	manifest := testManifest(relay.MigrationSourceActive)
	var events []string
	coverageErr := errors.New("enrollment does not cover source")
	source := &fakeSource{manifest: manifest, events: &events, coverageErr: coverageErr}
	executor := Executor{
		Source:      source,
		Destination: &fakeDestination{identity: manifest.TargetIdentity, events: &events},
		Publish:     func(context.Context, operator.MailCutoverPublication) error { return nil },
		Enrollment:  "test-enrollment",
	}
	_, err := executor.Execute(context.Background(), Request{ActorPrincipalID: "11111111-1111-4111-8111-111111111111", EpochID: manifest.EpochID, ExpectedSourceFingerprint: manifest.Fingerprint, Cutoff: time.Now().UTC()})
	if !errors.Is(err, coverageErr) || !reflect.DeepEqual(events, []string{"schema-readiness", "identity", "inspect", "coverage"}) || source.manifest.Phase != relay.MigrationSourceActive {
		t.Fatalf("source=%#v events=%v err=%v", source.manifest, events, err)
	}
}

func TestAbortReopensSourceBeforeDestinationAndRefusesActiveBarrier(t *testing.T) {
	t.Parallel()
	prepared := testManifest(relay.MigrationSourcePrepared)
	var events []string
	result, err := (Executor{Source: &fakeSource{manifest: prepared, events: &events}, Destination: &fakeDestination{identity: prepared.TargetIdentity, phase: postgres.MailCutoverVerified, events: &events}}).Abort(context.Background(), "11111111-1111-4111-8111-111111111111", prepared.EpochID)
	if err != nil || result.SourcePhase != relay.MigrationSourceActive || result.Phase != postgres.MailCutoverAborted || indexOf(events, "source-abort") >= indexOf(events, "destination-abort") {
		t.Fatalf("abort result=%#v events=%v err=%v", result, events, err)
	}
	events = nil
	if _, err := (Executor{Source: &fakeSource{manifest: prepared, events: &events}, Destination: &fakeDestination{identity: prepared.TargetIdentity, phase: postgres.MailCutoverActive, events: &events}}).Abort(context.Background(), "11111111-1111-4111-8111-111111111111", prepared.EpochID); err == nil || indexOf(events, "source-abort") >= 0 {
		t.Fatalf("active abort events=%v err=%v", events, err)
	}
}

func TestAbortRetryCompletesDestinationAfterSourceReopensAndChanges(t *testing.T) {
	t.Parallel()
	prepared := testManifest(relay.MigrationSourcePrepared)
	var events []string
	source := &fakeSource{manifest: prepared, events: &events}
	destination := &fakeDestination{identity: prepared.TargetIdentity, phase: postgres.MailCutoverVerified, events: &events, abortErr: errors.New("injected destination abort failure")}
	executor := Executor{Source: source, Destination: destination}
	if _, err := executor.Abort(context.Background(), "11111111-1111-4111-8111-111111111111", prepared.EpochID); err == nil || source.manifest.Phase != relay.MigrationSourceActive {
		t.Fatalf("first abort source=%#v events=%v err=%v", source.manifest, events, err)
	}
	// Simulate an old daemon writing after SQLite reopened but before the
	// uncertain PostgreSQL abort was recovered.
	source.manifest.Fingerprint = strings.Repeat("c", 64)
	destination.abortErr = nil
	result, err := executor.Abort(context.Background(), "11111111-1111-4111-8111-111111111111", prepared.EpochID)
	if err != nil || result.Phase != postgres.MailCutoverAborted || result.SourcePhase != relay.MigrationSourceActive || events[len(events)-1] != "destination-abort" {
		t.Fatalf("retry result=%#v source=%#v events=%v err=%v", result, source.manifest, events, err)
	}
}

func TestAbortRecoversPreparedSourceWhenDestinationRejectedBeforeEpochInsert(t *testing.T) {
	t.Parallel()
	prepared := testManifest(relay.MigrationSourcePrepared)
	var events []string
	source := &fakeSource{manifest: prepared, events: &events}
	destination := &fakeDestination{identity: prepared.TargetIdentity, events: &events, statusErr: postgres.ErrNotFound}
	executor := Executor{Source: source, Destination: destination}
	result, err := executor.Abort(context.Background(), "11111111-1111-4111-8111-111111111111", prepared.EpochID)
	if err != nil || result.SourcePhase != relay.MigrationSourceActive || result.Phase != postgres.MailCutoverAborted || indexOf(events, "reserve-abort") >= indexOf(events, "source-abort") || indexOf(events, "source-abort") >= indexOf(events, "destination-abort") {
		t.Fatalf("missing epoch abort result=%#v events=%v err=%v", result, events, err)
	}
	// A delayed begin observes the durable aborted tombstone instead of
	// resurrecting an importing fence, even after a fresh source journal exists.
	source.manifest = testManifest(relay.MigrationSourcePrepared)
	source.manifest.EpochID = "019f7f07-7b88-7c12-a394-b663274a6555"
	request, requestErr := destinationRequest(prepared, prepared.EpochID, prepared.TargetIdentity)
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	delayed, err := destination.BeginMailCutover(context.Background(), "11111111-1111-4111-8111-111111111111", request)
	if err != nil || delayed.Phase != postgres.MailCutoverAborted {
		t.Fatalf("delayed begin epoch=%#v err=%v", delayed, err)
	}
	source.manifest = prepared
	source.manifest.Phase = relay.MigrationSourceActive
	result, err = executor.Abort(context.Background(), "11111111-1111-4111-8111-111111111111", prepared.EpochID)
	if err != nil || result.SourcePhase != relay.MigrationSourceActive || result.Phase != postgres.MailCutoverAborted {
		t.Fatalf("missing epoch abort retry result=%#v events=%v err=%v", result, events, err)
	}
}

type fakeSource struct {
	manifest    relay.MigrationSourceManifest
	events      *[]string
	coverageErr error
}

func (s *fakeSource) Inspect(context.Context) (relay.MigrationSourceManifest, error) {
	*s.events = append(*s.events, "inspect")
	return s.manifest, nil
}
func (s *fakeSource) CheckEnrollmentCoverage(context.Context, string) error {
	*s.events = append(*s.events, "coverage")
	return s.coverageErr
}
func (s *fakeSource) Prepare(_ context.Context, epoch, target, expected string, _ time.Time) (relay.MigrationSourceManifest, error) {
	*s.events = append(*s.events, "prepare")
	if s.manifest.Phase != relay.MigrationSourceActive || expected != s.manifest.Fingerprint {
		return relay.MigrationSourceManifest{}, errors.New("unexpected prepare")
	}
	s.manifest.Phase, s.manifest.EpochID, s.manifest.TargetIdentity = relay.MigrationSourcePrepared, epoch, target
	s.manifest.ExpectedFingerprint = expected
	return s.manifest, nil
}
func (s *fakeSource) ReadBatch(_ context.Context, table, after string, _ int) (relay.MigrationSourceBatch, error) {
	*s.events = append(*s.events, "read:"+table)
	if table != "mail_endpoints" {
		return relay.MigrationSourceBatch{Done: true}, nil
	}
	row := testEndpointRow()
	if after == row.Key {
		return relay.MigrationSourceBatch{Done: true}, nil
	}
	return relay.MigrationSourceBatch{Rows: []relay.MigrationSourceRow{row}, NextKey: row.Key, Done: true}, nil
}
func (s *fakeSource) Retire(context.Context, string, string, string) (relay.MigrationSourceManifest, error) {
	*s.events = append(*s.events, "retire")
	s.manifest.Phase = relay.MigrationSourceRetired
	return s.manifest, nil
}
func (s *fakeSource) Abort(context.Context, string, string, string) (relay.MigrationSourceManifest, error) {
	*s.events = append(*s.events, "source-abort")
	s.manifest.Phase = relay.MigrationSourceActive
	return s.manifest, nil
}

type fakeDestination struct {
	identity           string
	phase              postgres.MailCutoverPhase
	events             *[]string
	stageErr           error
	abortErr           error
	statusErr          error
	readinessErr       error
	schemaReadinessErr error
}

func (d *fakeDestination) CheckMailCutoverSchemaReadiness(context.Context) error {
	*d.events = append(*d.events, "schema-readiness")
	return d.schemaReadinessErr
}
func (d *fakeDestination) Identity(context.Context) (string, error) {
	*d.events = append(*d.events, "identity")
	return d.identity, nil
}
func (d *fakeDestination) BeginMailCutover(_ context.Context, _ string, request postgres.MailCutoverRequest) (postgres.MailCutoverEpoch, error) {
	*d.events = append(*d.events, "begin")
	if d.phase == "" {
		d.phase = postgres.MailCutoverImporting
	}
	return postgres.MailCutoverEpoch{MailCutoverRequest: request, Phase: d.phase}, nil
}
func (d *fakeDestination) MailCutoverStatus(_ context.Context, _ string, epoch string) (postgres.MailCutoverEpoch, error) {
	*d.events = append(*d.events, "status")
	if d.statusErr != nil {
		return postgres.MailCutoverEpoch{}, d.statusErr
	}
	return postgres.MailCutoverEpoch{MailCutoverRequest: postgres.MailCutoverRequest{EpochID: epoch, TargetIdentity: d.identity, SourceFingerprint: strings.Repeat("b", 64)}, Phase: d.phase}, nil
}
func (d *fakeDestination) ReserveMailCutoverAbort(_ context.Context, _ string, request postgres.MailCutoverRequest) (postgres.MailCutoverEpoch, error) {
	*d.events = append(*d.events, "reserve-abort")
	d.phase = postgres.MailCutoverAborted
	d.statusErr = nil
	return postgres.MailCutoverEpoch{MailCutoverRequest: request, Phase: d.phase}, nil
}
func (d *fakeDestination) MailCutoverCheckpoint(_ context.Context, _ string, _ string, table string) (postgres.MailCutoverCheckpoint, error) {
	*d.events = append(*d.events, "checkpoint:"+table)
	return postgres.MailCutoverCheckpoint{Table: table, RollingSHA256: hex.EncodeToString(sha256.New().Sum(nil))}, nil
}
func (d *fakeDestination) StageMailCutoverBatch(_ context.Context, _ string, batch postgres.MailCutoverBatch) (postgres.MailCutoverCheckpoint, error) {
	*d.events = append(*d.events, "stage:"+batch.Table)
	if d.stageErr != nil {
		return postgres.MailCutoverCheckpoint{}, d.stageErr
	}
	return postgres.MailCutoverCheckpoint{Table: batch.Table, RowCount: int64(len(batch.Rows))}, nil
}
func (d *fakeDestination) VerifyMailCutover(_ context.Context, _ string, _ string, _ string) (postgres.MailCutoverEpoch, error) {
	*d.events = append(*d.events, "verify")
	d.phase = postgres.MailCutoverVerified
	return postgres.MailCutoverEpoch{Phase: d.phase}, nil
}
func (d *fakeDestination) CheckMailCutoverActivationReadiness(context.Context, string, string, string, string) error {
	*d.events = append(*d.events, "activation-readiness")
	return d.readinessErr
}
func (d *fakeDestination) ActivateMailCutover(_ context.Context, _ string, _ string, _ string, _ relay.MigrationSourceManifest) (postgres.MailCutoverEpoch, error) {
	*d.events = append(*d.events, "activate")
	d.phase = postgres.MailCutoverActive
	return postgres.MailCutoverEpoch{Phase: d.phase}, nil
}
func (d *fakeDestination) AbortMailCutover(context.Context, string, string, string) error {
	*d.events = append(*d.events, "destination-abort")
	if d.abortErr != nil {
		return d.abortErr
	}
	d.phase = postgres.MailCutoverAborted
	return nil
}

func testManifest(phase relay.MigrationSourcePhase) relay.MigrationSourceManifest {
	row := testEndpointRow()
	hasher, _ := relay.NewMigrationTableHasher("mail_endpoints")
	_ = hasher.Add(row)
	count, digest := hasher.Evidence()
	empty := sha256.Sum256(nil)
	emptyDigest := hex.EncodeToString(empty[:])
	return relay.MigrationSourceManifest{Version: 1, SourceID: "019f7f07-9b88-7c12-a394-b663274a6555", Phase: phase, EpochID: "019f7f07-8b88-7c12-a394-b663274a6555", TargetIdentity: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64), ExpectedFingerprint: strings.Repeat("b", 64), Counts: relay.MigrationSourceCounts{Endpoints: count}, TableSHA256: relay.MigrationSourceHashes{Endpoints: digest, Conversations: emptyDigest, Memberships: emptyDigest, Messages: emptyDigest, Deliveries: emptyDigest, RecipientCursors: emptyDigest, MessageIdempotency: emptyDigest, ConversationIdempotency: emptyDigest, RequestNonces: emptyDigest}}
}

func testEndpointRow() relay.MigrationSourceRow {
	payload, _ := json.Marshal(map[string]any{"endpoint": "agent/a", "machine_id": "machine-a", "lease_until": int64(1), "ownership_generation": int64(1), "consumer_id": nil, "consumer_generation": int64(0), "consumer_lease_until": nil})
	digest := sha256.Sum256(payload)
	return relay.MigrationSourceRow{Table: "mail_endpoints", Key: hex.EncodeToString([]byte("agent/a")), Payload: payload, SHA256: hex.EncodeToString(digest[:])}
}

func indexOf(values []string, target string) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return -1
}
