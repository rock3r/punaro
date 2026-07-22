package memoryclient

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResponseValidatorsAcceptExactSchemas(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		validate func([]byte) error
	}{
		{"resolve", `{"identity_id":"` + testInstallation + `","project_id":"` + testProject + `","kind":"git_remote"}`, validateResolveResponse},
		{"memory", memoryResponse(), validateMemoryResponse},
		{"search", `{"results":[],"more":false}`, validateSearchResponse},
		{"brief", briefResponse(), validateBriefResponse},
		{"changes", `{"changes":[],"cursor":{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `","change_sequence":0},"more":false}`, validateChangesResponse},
		{"mutation", `{"item_id":"` + testItem + `","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"state":"active","change_sequence":1}`, validateMutationResponse},
		{"purge", `{"item_id":"` + testItem + `","revision":1,"change_sequence":1}`, validatePurgeResponse},
		{"proposal", proposalResponse(), validateProposalResponse},
		{"proposal result", `{"proposal_id":"` + testProposal + `","state":"pending","etag":` + jsonETag(testProposalETag) + `}`, validateProposalResultResponse},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.validate([]byte(test.raw)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestResponseValidatorsRejectMissingUnknownNullAndMalformedNestedFields(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		validate func([]byte) error
	}{
		{"resolve missing", `{"project_id":"` + testProject + `","kind":"git_remote"}`, validateResolveResponse},
		{"memory unknown", memoryResponse()[:len(memoryResponse())-1] + `,"route":"https://evil.test"}`, validateMemoryResponse},
		{"search nested unknown", `{"results":[{"item_id":"` + testItem + `","kind":"decision","trust":"curated","layer":"curated","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"match":"lexical","score":1,"destination":"evil"}],"more":false}`, validateSearchResponse},
		{"search missing score", `{"results":[{"item_id":"` + testItem + `","kind":"decision","trust":"curated","layer":"curated","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"match":"lexical"}],"more":false}`, validateSearchResponse},
		{"search optional null", `{"results":[{"item_id":"` + testItem + `","kind":"decision","trust":"curated","layer":"curated","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"title":null,"match":"lexical","score":1}],"more":false}`, validateSearchResponse},
		{"brief cursor unknown", `{"cursor":{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `","change_sequence":0,"route":"evil"},"project_id":"` + testProject + `","project_content_generation":1,"project_acl_generation":1,"retrieval_mode":"lexical","semantic_status":"not_configured","budget_version":"prompt-brief-v1","entries":[],"context":"{}","truncated":false}`, validateBriefResponse},
		{"brief cursor missing sequence", `{"cursor":{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `"},"project_id":"` + testProject + `","project_content_generation":1,"project_acl_generation":1,"retrieval_mode":"lexical","semantic_status":"not_configured","budget_version":"prompt-brief-v1","entries":[],"context":"{}","truncated":false}`, validateBriefResponse},
		{"changes null", `{"changes":null,"cursor":{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `","change_sequence":0},"more":false}`, validateChangesResponse},
		{"changes invalid type", `{"changes":[{"timeline_id":"` + testTimeline + `","change_sequence":1,"scope_id":"` + testScope + `","item_id":"` + testItem + `","type":"route_change","revision":1,"occurred_at":"2026-01-01T00:00:00Z"}],"cursor":{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `","change_sequence":1},"more":false}`, validateChangesResponse},
		{"mutation missing state", `{"item_id":"` + testItem + `","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"change_sequence":1}`, validateMutationResponse},
		{"purge carries state", `{"item_id":"` + testItem + `","revision":1,"state":"active","change_sequence":1}`, validatePurgeResponse},
		{"proposal nested unknown", strings.Replace(proposalResponse(), `"operation":"create"`, `"operation":"create","route":"evil"`, 1), validateProposalResponse},
		{"proposal null ordinal", strings.Replace(proposalResponse(), `"ordinal":0`, `"ordinal":null`, 1), validateProposalResponse},
		{"proposal incoherent action", strings.Replace(proposalResponse(), `"action":"create"`, `"action":"archive"`, 1), validateProposalResponse},
		{"proposal result mutation unknown", `{"proposal_id":"` + testProposal + `","state":"approved","etag":` + jsonETag(testProposalETag) + `,"mutations":[{"item_id":"` + testItem + `","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"state":"active","change_sequence":1,"route":"evil"}]}`, validateProposalResultResponse},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.validate([]byte(test.raw)); err == nil {
				t.Fatalf("accepted %s", test.raw)
			}
		})
	}
}

func TestResolveResponseMustMatchRequestedKind(t *testing.T) {
	raw := []byte(`{"identity_id":"` + testInstallation + `","project_id":"` + testProject + `","kind":"workspace"}`)
	if err := validateResolveKind(raw, "git_remote"); err == nil {
		t.Fatal("mismatched resolver kind accepted")
	}
}

func TestResponseValidatorsEnforceCollectionBounds(t *testing.T) {
	entry := `{"item_id":"` + testItem + `","kind":"decision","trust":"curated","layer":"curated","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"match":"lexical","score":1}`
	search := `{"results":[` + strings.Repeat(entry+",", 50) + entry + `],"more":false}`
	if err := validateSearchResponse([]byte(search)); err == nil {
		t.Fatal("51 search results accepted")
	}
	step := `{"ordinal":0,"operation":"create","kind":"decision","trust":"curated","document":{}}`
	proposal := strings.Replace(proposalResponse(), `"steps":[`+step+`]`, `"steps":[`+strings.Repeat(step+",", 8)+step+`]`, 1)
	if err := validateProposalResponse([]byte(proposal)); err == nil {
		t.Fatal("9 proposal steps accepted")
	}
}

func TestBriefEnvelopeMustMatchOuterFraming(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(briefResponse(), promptBriefWarning, "ordinary data", 1),
		strings.Replace(briefResponse(), `\"change_sequence\":0},\"retrieval_mode\"`, `\"change_sequence\":1},\"retrieval_mode\"`, 1),
	} {
		if err := validateBriefResponse([]byte(raw)); err == nil {
			t.Fatal("divergent brief envelope accepted")
		}
	}
	var duplicate briefWire
	if err := json.Unmarshal([]byte(briefResponse()), &duplicate); err != nil {
		t.Fatal(err)
	}
	duplicate.Context = strings.Replace(duplicate.Context, `"warning":`, `"warning":"wrong","warning":`, 1)
	raw, _ := json.Marshal(duplicate)
	if err := validateBriefResponse(raw); err == nil {
		t.Fatal("duplicate brief warning accepted")
	}
}

func TestChangesResponseIsBoundToRequestedCursorAndLimit(t *testing.T) {
	requested := json.RawMessage(`{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `","change_sequence":3}`)
	valid := `{"changes":[],"cursor":{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `","change_sequence":3},"more":false}`
	if err := validateChangesFor([]byte(valid), requested, 1); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(valid, testInstallation, testAuthor, 1),
		strings.Replace(valid, `"change_sequence":3`, `"change_sequence":2`, 1),
		`{"changes":[{"timeline_id":"` + testTimeline + `","change_sequence":3,"scope_id":"` + testScope + `","item_id":"` + testItem + `","type":"update","revision":2,"occurred_at":"2026-01-01T00:00:00Z"}],"cursor":{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `","change_sequence":3},"more":false}`,
		`{"changes":[{"timeline_id":"` + testTimeline + `","change_sequence":4,"scope_id":"` + testScope + `","item_id":"` + testItem + `","type":"update","revision":2,"occurred_at":"2026-01-01T00:00:00Z"}],"cursor":{"installation_id":"` + testInstallation + `","timeline_id":"` + testTimeline + `","change_sequence":100},"more":true}`,
	} {
		if err := validateChangesFor([]byte(raw), requested, 1); err == nil {
			t.Fatal("unbound changes response accepted")
		}
	}
}

func TestMutationAndProposalResultsAreBoundToRequestedOutcome(t *testing.T) {
	active := []byte(`{"item_id":"` + testItem + `","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"state":"active","change_sequence":1}`)
	if validateMutationState(active, "active") != nil || validateMutationState(active, "archived") == nil {
		t.Fatal("mutation outcome was not state-bound")
	}
	if validateCreateMutation(active) != nil || validateCreateMutation([]byte(strings.Replace(string(active), `"revision":1`, `"revision":2`, 1))) == nil {
		t.Fatal("create outcome was not revision-bound")
	}
	pending := []byte(`{"proposal_id":"` + testProposal + `","state":"pending","etag":` + jsonETag(testProposalETag) + `}`)
	approved := []byte(`{"proposal_id":"` + testProposal + `","state":"approved","etag":` + jsonETag(testProposalETag) + `,"mutations":[{"item_id":"` + testItem + `","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"state":"active","change_sequence":1}]}`)
	if validateProposalResultFor(pending, "pending", false, true) != nil || validateProposalResultFor(approved, "approved", true, false) != nil || validateProposalResultFor(pending, "approved", true, false) == nil || validateProposalResultFor(approved, "pending", false, true) == nil {
		t.Fatal("proposal outcome was not action-bound")
	}
	duplicate := []byte(`{"proposal_id":"` + testProposal + `","state":"approved","etag":` + jsonETag(testProposalETag) + `,"mutations":[{"item_id":"` + testItem + `","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"state":"active","change_sequence":1},{"item_id":"` + testItem + `","revision":2,"etag":` + jsonETag(testMemoryETag) + `,"state":"active","change_sequence":2}]}`)
	if validateProposalResultResponse(duplicate) == nil {
		t.Fatal("duplicate proposal mutation accepted")
	}
}

func TestSearchResponseIsBoundToRequestedLimit(t *testing.T) {
	first := `{"item_id":"` + testItem + `","kind":"decision","trust":"curated","layer":"curated","revision":1,"etag":` + jsonETag(testMemoryETag) + `,"match":"lexical","score":1}`
	second := `{"item_id":"` + testProposal + `","kind":"decision","trust":"curated","layer":"curated","revision":1,"etag":` + jsonETag(memoryETagFor(testProposal, 1)) + `,"match":"lexical","score":1}`
	raw := []byte(`{"results":[` + first + `,` + second + `],"more":false}`)
	if validateSearchFor(raw, 2) != nil || validateSearchFor(raw, 1) == nil {
		t.Fatal("search result count was not request-bound")
	}
}

func TestMemoryETagsAreBoundToItemAndRevision(t *testing.T) {
	wrong := memoryETagFor(testProposal, 1)
	changed := strings.Replace(memoryResponse(), jsonETag(testMemoryETag), jsonETag(wrong), 1)
	if changed == memoryResponse() {
		t.Fatal("test did not replace the memory ETag")
	}
	if err := validateMemoryResponse([]byte(changed)); err == nil {
		t.Fatal("memory response accepted a syntactically valid foreign ETag")
	}
	mutation := []byte(`{"item_id":"` + testItem + `","revision":1,"etag":` + jsonETag(wrong) + `,"state":"active","change_sequence":1}`)
	if err := validateMutationResponse(mutation); err == nil {
		t.Fatal("mutation response accepted a syntactically valid foreign ETag")
	}
}

func TestProposalLifecycleFieldsAndResultsAreStateConsistent(t *testing.T) {
	approved := strings.Replace(proposalResponse(), `"state":"pending"`, `"state":"approved"`, 1)
	approved = strings.Replace(approved, `"created_at"`, `"decided_by":"`+testAuthor+`","decided_at":"2026-01-01T12:00:00Z","results":[{"ordinal":0,"item_id":"`+testItem+`","revision":1}],"created_at"`, 1)
	if err := validateProposalResponse([]byte(approved)); err != nil {
		t.Fatal(err)
	}
	if err := validateProposalResponse([]byte(strings.Replace(approved, `"state":"approved"`, `"state":"pending"`, 1))); err == nil {
		t.Fatal("pending proposal with decision metadata accepted")
	}
}

func TestApprovedProposalResultsCannotReuseItemIDs(t *testing.T) {
	raw := `{"proposal_id":"` + testProposal + `","scope_id":"` + testScope + `","project_id":"` + testProject + `","action":"split","state":"approved","etag":` + jsonETag(testProposalETag) + `,"proposed_by":"` + testAuthor + `","decided_by":"` + testAuthor + `","created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z","decided_at":"2026-01-01T12:00:00Z","steps":[{"ordinal":0,"operation":"archive","item_id":"` + testItem + `","expected_etag":` + jsonETag(testMemoryETag) + `,"archived":true},{"ordinal":1,"operation":"create","kind":"decision","trust":"curated","document":{}},{"ordinal":2,"operation":"create","kind":"decision","trust":"curated","document":{}}],"evidence":[],"results":[{"ordinal":0,"item_id":"` + testItem + `","revision":2},{"ordinal":1,"item_id":"` + testInstallation + `","revision":1},{"ordinal":2,"item_id":"` + testInstallation + `","revision":1}]}`
	if err := validateProposalResponse([]byte(raw)); err == nil {
		t.Fatal("approved proposal reused a create result item ID")
	}
}

func TestBriefEntryPerFieldBoundsAreCanonical(t *testing.T) {
	raw := []byte(`{"title":"` + strings.Repeat("a", 257) + `"}`)
	if validBoundedOptionalString(raw, "title", strings.Repeat("a", 257), 256) {
		t.Fatal("oversized brief title accepted")
	}
}

func TestCanonicalMemoryDocumentDepthIsLimitedTo32(t *testing.T) {
	document := `{}`
	for range 32 {
		document = `{"nested":` + document + `}`
	}
	raw := strings.Replace(memoryResponse(), `"document":{}`, `"document":`+document, 1)
	if err := validateMemoryResponse([]byte(raw)); err == nil {
		t.Fatal("depth-33 canonical document accepted")
	}
}
