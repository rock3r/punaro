package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

const (
	testPrincipalA = "11111111-1111-4111-8111-111111111111"
	testPrincipalB = "22222222-2222-4222-8222-222222222222"
	testProjectA   = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testRequestKey = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

func TestGrantValidationEncodesExplicitScope(t *testing.T) {
	if CapabilityProjectAttachUnclaimed != "project.identity.attach-unclaimed" {
		t.Fatalf("persisted attach-unclaimed token=%q", CapabilityProjectAttachUnclaimed)
	}
	tests := []struct {
		name    string
		grant   Grant
		wantErr bool
	}{
		{name: "installation create", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeInstallation, Capability: CapabilityProjectCreate}},
		{name: "selected discover", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeProject, ProjectID: testProjectA, Capability: CapabilityProjectDiscover}},
		{name: "selected project", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeProject, ProjectID: testProjectA, Capability: CapabilityProjectWrite}},
		{name: "dynamic all projects", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeAllProjects, Capability: CapabilityMemoryRead}},
		{name: "friendly project is not authority", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeProject, ProjectID: "friendly-name", Capability: CapabilityProjectRead}, wantErr: true},
		{name: "missing selected project", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeProject, Capability: CapabilityProjectRead}, wantErr: true},
		{name: "project on all-projects grant", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeAllProjects, ProjectID: testProjectA, Capability: CapabilityProjectRead}, wantErr: true},
		{name: "project capability at installation", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeInstallation, Capability: CapabilityProjectWrite}, wantErr: true},
		{name: "catalog-wide discover", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeInstallation, Capability: CapabilityProjectDiscover}, wantErr: true},
		{name: "installation capability at project", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeProject, ProjectID: testProjectA, Capability: CapabilityProjectCreate}, wantErr: true},
		{name: "unknown capability", grant: Grant{PrincipalID: testPrincipalA, Scope: ScopeProject, ProjectID: testProjectA, Capability: Capability("project.superuser")}, wantErr: true},
		{name: "invalid principal", grant: Grant{PrincipalID: "principal-a", Scope: ScopeInstallation, Capability: CapabilityProjectCreate}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.grant.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error=%v, wantErr=%t", err, test.wantErr)
			}
		})
	}
}

func TestIdempotencyRequestValidationAndDigest(t *testing.T) {
	request := IdempotencyRequest{PrincipalID: testPrincipalA, Operation: "project.create", Key: testRequestKey, Body: []byte(`{"name":"alpha"}`)}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	first := requestDigest(request.Body)
	second := requestDigest(append([]byte(nil), request.Body...))
	changed := requestDigest([]byte(`{"name":"beta"}`))
	if !bytes.Equal(first[:], second[:]) || bytes.Equal(first[:], changed[:]) {
		t.Fatal("request digest is not stable and body-bound")
	}
	for name, invalid := range map[string]IdempotencyRequest{
		"principal": {PrincipalID: "friendly", Operation: request.Operation, Key: request.Key, Body: request.Body},
		"operation": {PrincipalID: request.PrincipalID, Operation: "Project Create", Key: request.Key, Body: request.Body},
		"key":       {PrincipalID: request.PrincipalID, Operation: request.Operation, Key: "reused-human-key", Body: request.Body},
		"body":      {PrincipalID: request.PrincipalID, Operation: request.Operation, Key: request.Key, Body: bytes.Repeat([]byte("x"), maxIdempotencyRequestBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := invalid.Validate(); err == nil {
				t.Fatal("invalid idempotency request accepted")
			}
		})
	}
}

func TestOutcomeAuditAndJobBounds(t *testing.T) {
	outcome := IdempotencyOutcome{Status: OutcomeSucceeded, ResourceID: testProjectA, Result: json.RawMessage(`{"project_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`)}
	if err := outcome.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (IdempotencyOutcome{Status: OutcomeStatus("success with details"), Result: json.RawMessage(`{}`)}).Validate(); err == nil {
		t.Fatal("free-form outcome status accepted")
	}
	if err := (IdempotencyOutcome{Status: OutcomeSucceeded, Result: bytes.Repeat([]byte("x"), maxIdempotencyResultBytes+1)}).Validate(); err == nil {
		t.Fatal("oversized idempotency result accepted")
	}

	event := AuditEvent{PrincipalID: testPrincipalA, ProjectID: testProjectA, Action: "project.create", Outcome: "succeeded", TargetKind: "project", TargetID: testProjectA}
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	badEvent := event
	badEvent.Action = "created project containing a request body"
	if err := badEvent.Validate(); err == nil {
		t.Fatal("free-form audit content accepted")
	}

	job := EnqueueJob{Kind: "project.reconcile", ProjectID: testProjectA, Payload: json.RawMessage(`{"project_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`), MaxAttempts: 4, AvailableAt: time.Now().UTC()}
	if err := job.Validate(); err != nil {
		t.Fatal(err)
	}
	job.Payload = bytes.Repeat([]byte("x"), maxJobPayloadBytes+1)
	if err := job.Validate(); err == nil {
		t.Fatal("oversized job payload accepted")
	}
}

func TestClaimOptionsAreHardBounded(t *testing.T) {
	valid := ClaimJobs{Kind: "project.reconcile", Holder: testPrincipalB, Limit: 10, LeaseDuration: time.Minute}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]ClaimJobs{
		"limit":    {Kind: valid.Kind, Holder: valid.Holder, Limit: maxJobClaimBatch + 1, LeaseDuration: valid.LeaseDuration},
		"lease":    {Kind: valid.Kind, Holder: valid.Holder, Limit: valid.Limit, LeaseDuration: maxJobLeaseDuration + time.Second},
		"holder":   {Kind: valid.Kind, Holder: "worker-1", Limit: valid.Limit, LeaseDuration: valid.LeaseDuration},
		"job kind": {Kind: "project reconcile", Holder: valid.Holder, Limit: valid.Limit, LeaseDuration: valid.LeaseDuration},
	} {
		t.Run(name, func(t *testing.T) {
			if err := invalid.Validate(); err == nil {
				t.Fatal("invalid claim accepted")
			}
		})
	}
}
