package postgres

import (
	"encoding/json"
	"testing"
)

func TestMemoryEvidenceCreateRequestValidation(t *testing.T) {
	valid := MemoryEvidenceCreateRequest{
		PrincipalID:    "11111111-1111-4111-8111-111111111111",
		ProjectID:      "22222222-2222-4222-8222-222222222222",
		IdempotencyKey: "33333333-3333-4333-8333-333333333333",
		LogicalKey:     "evidence.release-gate",
		Kind:           "evidence.excerpt",
		Trust:          "observed",
		Document:       json.RawMessage(`{"excerpt":"bounded source fact"}`),
		Sources: []MemoryEvidenceSourceInput{{
			Mode: MemorySourceCopied, Kind: MemorySourceMessage,
			ReferenceSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
		Claims: []MemoryEvidenceClaimInput{{
			Type: MemoryEdgeSupports, TargetItemID: "44444444-4444-4444-8444-444444444444", TargetRevision: 2,
		}},
	}
	if normalized, err := valid.normalized(); err != nil || string(normalized.Document) != `{"excerpt":"bounded source fact"}` {
		t.Fatalf("valid evidence request normalized=%#v err=%v", normalized, err)
	}

	tests := []struct {
		name   string
		mutate func(*MemoryEvidenceCreateRequest)
	}{
		{"no sources", func(request *MemoryEvidenceCreateRequest) { request.Sources = nil }},
		{"too many sources", func(request *MemoryEvidenceCreateRequest) {
			request.Sources = make([]MemoryEvidenceSourceInput, maxMemoryEvidenceSources+1)
		}},
		{"unknown source mode", func(request *MemoryEvidenceCreateRequest) { request.Sources[0].Mode = "linked" }},
		{"unknown source kind", func(request *MemoryEvidenceCreateRequest) { request.Sources[0].Kind = "url" }},
		{"copied locator", func(request *MemoryEvidenceCreateRequest) {
			request.Sources[0].ProjectID = "55555555-5555-4555-8555-555555555555"
		}},
		{"bad reference digest", func(request *MemoryEvidenceCreateRequest) { request.Sources[0].ReferenceSHA256 = "aa" }},
		{"non-canonical reference digest", func(request *MemoryEvidenceCreateRequest) {
			request.Sources[0].ReferenceSHA256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		}},
		{"live digest", func(request *MemoryEvidenceCreateRequest) {
			request.Sources[0] = MemoryEvidenceSourceInput{
				Mode: MemorySourceLive, Kind: MemorySourceMessage,
				ProjectID: "55555555-5555-4555-8555-555555555555", ResourceID: "66666666-6666-4666-8666-666666666666",
				ReferenceSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			}
		}},
		{"live external", func(request *MemoryEvidenceCreateRequest) {
			request.Sources[0] = MemoryEvidenceSourceInput{
				Mode: MemorySourceLive, Kind: MemorySourceExternal,
				ProjectID: "55555555-5555-4555-8555-555555555555", ResourceID: "66666666-6666-4666-8666-666666666666",
			}
		}},
		{"live memory without revision", func(request *MemoryEvidenceCreateRequest) {
			request.Sources[0] = MemoryEvidenceSourceInput{
				Mode: MemorySourceLive, Kind: MemorySourceMemory,
				ProjectID: "55555555-5555-4555-8555-555555555555", ResourceID: "66666666-6666-4666-8666-666666666666",
			}
		}},
		{"live message with revision", func(request *MemoryEvidenceCreateRequest) {
			request.Sources[0] = MemoryEvidenceSourceInput{
				Mode: MemorySourceLive, Kind: MemorySourceMessage,
				ProjectID: "55555555-5555-4555-8555-555555555555", ResourceID: "66666666-6666-4666-8666-666666666666", ResourceRevision: 1,
			}
		}},
		{"duplicate source", func(request *MemoryEvidenceCreateRequest) {
			request.Sources = append(request.Sources, request.Sources[0])
		}},
		{"too many claims", func(request *MemoryEvidenceCreateRequest) {
			request.Claims = make([]MemoryEvidenceClaimInput, maxMemoryEvidenceClaims+1)
		}},
		{"unknown claim", func(request *MemoryEvidenceCreateRequest) { request.Claims[0].Type = "agrees" }},
		{"invalid target", func(request *MemoryEvidenceCreateRequest) { request.Claims[0].TargetItemID = "nope" }},
		{"invalid revision", func(request *MemoryEvidenceCreateRequest) { request.Claims[0].TargetRevision = 0 }},
		{"duplicate claim", func(request *MemoryEvidenceCreateRequest) { request.Claims = append(request.Claims, request.Claims[0]) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			request.Sources = append([]MemoryEvidenceSourceInput(nil), valid.Sources...)
			request.Claims = append([]MemoryEvidenceClaimInput(nil), valid.Claims...)
			test.mutate(&request)
			if _, err := request.normalized(); err == nil {
				t.Fatal("invalid evidence request accepted")
			}
		})
	}
}

func TestMemoryEvidenceLookupValidation(t *testing.T) {
	valid := MemoryEvidenceGetRequest{
		PrincipalID: "11111111-1111-4111-8111-111111111111",
		ProjectID:   "22222222-2222-4222-8222-222222222222",
		ItemID:      "33333333-3333-4333-8333-333333333333",
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid lookup rejected: %v", err)
	}
	valid.ItemID = "bad"
	if err := valid.validate(); err == nil {
		t.Fatal("invalid lookup accepted")
	}
}
