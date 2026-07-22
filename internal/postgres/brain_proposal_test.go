package postgres

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMemoryProposalCreateRequestNormalizesClosedActionShapes(t *testing.T) {
	t.Parallel()
	principal := "18181818-1818-4818-8818-181818181801"
	project := "18181818-1818-4818-8818-181818181802"
	target := "18181818-1818-4818-8818-181818181803"
	evidence := "18181818-1818-4818-8818-181818181804"
	etag := memoryETag(target, 3)
	create := MemoryProposalStepInput{Operation: MemoryProposalStepCreate, LogicalKey: "decision.new", Kind: "decision", Trust: "proposed", Document: json.RawMessage(`{"b":2,"a":1}`)}
	update := MemoryProposalStepInput{Operation: MemoryProposalStepUpdate, ItemID: target, ExpectedETag: etag, LogicalKey: "decision.current", Kind: "decision", Trust: "proposed", Document: json.RawMessage(`{"updated":true}`)}
	archive := MemoryProposalStepInput{Operation: MemoryProposalStepArchive, ItemID: "18181818-1818-4818-8818-181818181805", ExpectedETag: memoryETag("18181818-1818-4818-8818-181818181805", 1), Archived: true}

	for name, request := range map[string]MemoryProposalCreateRequest{
		"create":               {PrincipalID: principal, ProjectID: project, IdempotencyKey: "18181818-1818-4818-8818-181818181811", Action: MemoryProposalCreate, Steps: []MemoryProposalStepInput{create}},
		"update":               {PrincipalID: principal, ProjectID: project, IdempotencyKey: "18181818-1818-4818-8818-181818181812", Action: MemoryProposalUpdate, Steps: []MemoryProposalStepInput{update}},
		"archive":              {PrincipalID: principal, ProjectID: project, IdempotencyKey: "18181818-1818-4818-8818-181818181813", Action: MemoryProposalArchive, Steps: []MemoryProposalStepInput{archive}},
		"merge":                {PrincipalID: principal, ProjectID: project, IdempotencyKey: "18181818-1818-4818-8818-181818181814", Action: MemoryProposalMerge, Steps: []MemoryProposalStepInput{update, archive}},
		"split":                {PrincipalID: principal, ProjectID: project, IdempotencyKey: "18181818-1818-4818-8818-181818181815", Action: MemoryProposalSplit, Steps: []MemoryProposalStepInput{archive, create, {Operation: MemoryProposalStepCreate, LogicalKey: "decision.second", Kind: "decision", Trust: "proposed", Document: json.RawMessage(`{"part":2}`)}}, Evidence: []MemoryProposalEvidenceInput{{ItemID: evidence, Revision: 2}}},
		"split anonymous keys": {PrincipalID: principal, ProjectID: project, IdempotencyKey: "18181818-1818-4818-8818-181818181816", Action: MemoryProposalSplit, Steps: []MemoryProposalStepInput{archive, {Operation: MemoryProposalStepCreate, Kind: "decision", Trust: "proposed", Document: json.RawMessage(`{"part":1}`)}, {Operation: MemoryProposalStepCreate, Kind: "decision", Trust: "proposed", Document: json.RawMessage(`{"part":2}`)}}},
	} {
		t.Run(name, func(t *testing.T) {
			normalized, err := request.normalized()
			if err != nil {
				t.Fatalf("valid %s proposal: %v", name, err)
			}
			for _, step := range normalized.Steps {
				if step.Operation == MemoryProposalStepCreate && string(step.Document) == `{"b":2,"a":1}` {
					t.Fatal("proposal document was not canonicalized")
				}
			}
		})
	}
}

func TestMemoryProposalCreateRequestRejectsAmbiguousOrUnboundedShapes(t *testing.T) {
	t.Parallel()
	principal := "18181818-1818-4818-8818-181818181821"
	project := "18181818-1818-4818-8818-181818181822"
	target := "18181818-1818-4818-8818-181818181823"
	create := MemoryProposalStepInput{Operation: MemoryProposalStepCreate, Kind: "decision", Trust: "proposed", Document: json.RawMessage(`{"ok":true}`)}
	archive := MemoryProposalStepInput{Operation: MemoryProposalStepArchive, ItemID: target, ExpectedETag: memoryETag(target, 1), Archived: true}
	base := MemoryProposalCreateRequest{PrincipalID: principal, ProjectID: project, IdempotencyKey: "18181818-1818-4818-8818-181818181824", Action: MemoryProposalCreate, Steps: []MemoryProposalStepInput{create}}

	cases := map[string]MemoryProposalCreateRequest{
		"unknown action":                func() MemoryProposalCreateRequest { r := base; r.Action = "execute"; return r }(),
		"create with target":            func() MemoryProposalCreateRequest { r := base; r.Steps[0].ItemID = target; return r }(),
		"archive without target":        {PrincipalID: principal, ProjectID: project, IdempotencyKey: base.IdempotencyKey, Action: MemoryProposalArchive, Steps: []MemoryProposalStepInput{{Operation: MemoryProposalStepArchive, Archived: true}}},
		"archive restoring target":      {PrincipalID: principal, ProjectID: project, IdempotencyKey: base.IdempotencyKey, Action: MemoryProposalArchive, Steps: []MemoryProposalStepInput{{Operation: MemoryProposalStepArchive, ItemID: target, ExpectedETag: memoryETag(target, 1)}}},
		"merge without archived source": {PrincipalID: principal, ProjectID: project, IdempotencyKey: base.IdempotencyKey, Action: MemoryProposalMerge, Steps: []MemoryProposalStepInput{{Operation: MemoryProposalStepUpdate, ItemID: target, ExpectedETag: memoryETag(target, 1), Kind: "decision", Trust: "proposed", Document: json.RawMessage(`{"ok":true}`)}, create}},
		"split with one child":          {PrincipalID: principal, ProjectID: project, IdempotencyKey: base.IdempotencyKey, Action: MemoryProposalSplit, Steps: []MemoryProposalStepInput{archive, create}},
		"duplicate target":              {PrincipalID: principal, ProjectID: project, IdempotencyKey: base.IdempotencyKey, Action: MemoryProposalMerge, Steps: []MemoryProposalStepInput{{Operation: MemoryProposalStepUpdate, ItemID: target, ExpectedETag: memoryETag(target, 1), Kind: "decision", Trust: "proposed", Document: json.RawMessage(`{"ok":true}`)}, archive}},
		"duplicate create logical key":  {PrincipalID: principal, ProjectID: project, IdempotencyKey: base.IdempotencyKey, Action: MemoryProposalSplit, Steps: []MemoryProposalStepInput{archive, {Operation: MemoryProposalStepCreate, LogicalKey: "decision.duplicate", Kind: "decision", Trust: "proposed", Document: json.RawMessage(`{"part":1}`)}, {Operation: MemoryProposalStepCreate, LogicalKey: "decision.duplicate", Kind: "decision", Trust: "proposed", Document: json.RawMessage(`{"part":2}`)}}},
		"too many steps": func() MemoryProposalCreateRequest {
			r := base
			r.Steps = make([]MemoryProposalStepInput, maxMemoryProposalSteps+1)
			for i := range r.Steps {
				r.Steps[i] = create
			}
			return r
		}(),
		"too many evidence": func() MemoryProposalCreateRequest {
			r := base
			r.Evidence = make([]MemoryProposalEvidenceInput, maxMemoryProposalEvidence+1)
			return r
		}(),
		"duplicate evidence": func() MemoryProposalCreateRequest {
			r := base
			r.Evidence = []MemoryProposalEvidenceInput{{ItemID: target, Revision: 1}, {ItemID: target, Revision: 2}}
			return r
		}(),
		"oversized document": func() MemoryProposalCreateRequest {
			r := base
			r.Steps[0].Document = json.RawMessage(`{"x":"` + strings.Repeat("x", maxMemoryDocumentBytes) + `"}`)
			return r
		}(),
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := request.normalized(); err == nil {
				t.Fatal("invalid proposal accepted")
			}
		})
	}
}

func TestMemoryProposalDecisionRequestRequiresProposalCAS(t *testing.T) {
	t.Parallel()
	proposalID := "18181818-1818-4818-8818-181818181831"
	payloadSHA := make([]byte, 32)
	valid := MemoryProposalDecisionRequest{
		PrincipalID: "18181818-1818-4818-8818-181818181832", ProjectID: "18181818-1818-4818-8818-181818181833",
		ProposalID: proposalID, IdempotencyKey: "18181818-1818-4818-8818-181818181834", ExpectedETag: memoryProposalETag(proposalID, MemoryProposalPending, payloadSHA),
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid decision rejected: %v", err)
	}
	valid.ExpectedETag = "invalid"
	if err := valid.validate(); err == nil {
		t.Fatal("malformed proposal ETag accepted")
	}
}

func TestMemoryProposalETagBindsPayload(t *testing.T) {
	t.Parallel()
	proposalID := "18181818-1818-4818-8818-181818181841"
	first := make([]byte, 32)
	second := make([]byte, 32)
	second[0] = 1
	firstETag := memoryProposalETag(proposalID, MemoryProposalPending, first)
	if memoryProposalETagMatches(firstETag, proposalID, MemoryProposalPending, second) {
		t.Fatal("proposal ETag accepted a different payload digest")
	}
	if !validMemoryProposalETagShape(firstETag) {
		t.Fatal("generated proposal ETag has an invalid shape")
	}
}

func TestMemoryProposalPayloadPreservesCanonicalNumberBytes(t *testing.T) {
	t.Parallel()
	request := MemoryProposalCreateRequest{
		PrincipalID: "18181818-1818-4818-8818-181818181851", ProjectID: "18181818-1818-4818-8818-181818181852",
		IdempotencyKey: "18181818-1818-4818-8818-181818181853", Action: MemoryProposalCreate,
		Steps: []MemoryProposalStepInput{{Operation: MemoryProposalStepCreate, Kind: "decision", Trust: "curated", Document: json.RawMessage(`{"number":1e2}`)}},
	}
	normalized, err := request.normalized()
	if err != nil {
		t.Fatal(err)
	}
	payload, digest := memoryProposalPayloadSHA(normalized.ProjectID, normalized.Action, normalized.Steps, normalized.Evidence)
	if !strings.Contains(string(payload), `"number":1e2`) || len(digest) != 32 {
		t.Fatalf("payload=%s digest-bytes=%d", payload, len(digest))
	}
}
