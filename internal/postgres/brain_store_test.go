package postgres

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalMemoryDocument(t *testing.T) {
	canonical, err := canonicalMemoryDocument(json.RawMessage(` { "z": 1, "a": { "b": true } } `))
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != `{"a":{"b":true},"z":1}` {
		t.Fatalf("canonical document=%s", canonical)
	}
	second, err := canonicalMemoryDocument(json.RawMessage(`{"a":{"b":true},"z":1}`))
	if err != nil || !bytes.Equal(second, canonical) {
		t.Fatalf("equivalent JSON was not canonical: document=%s err=%v", second, err)
	}

	for _, test := range []struct {
		name string
		doc  json.RawMessage
	}{
		{name: "empty", doc: nil},
		{name: "array", doc: json.RawMessage(`[]`)},
		{name: "trailing", doc: json.RawMessage(`{} {}`)},
		{name: "duplicate key", doc: json.RawMessage(`{"a":1,"a":2}`)},
		{name: "too deep", doc: json.RawMessage(strings.Repeat(`{"a":`, maxMemoryDocumentDepth+1) + `0` + strings.Repeat(`}`, maxMemoryDocumentDepth+1))},
		{name: "too large", doc: json.RawMessage(`{"a":"` + strings.Repeat("x", maxMemoryDocumentBytes) + `"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := canonicalMemoryDocument(test.doc); err == nil {
				t.Fatal("invalid memory document accepted")
			}
		})
	}
}

func TestMemoryRequestValidation(t *testing.T) {
	base := MemoryCreateRequest{
		PrincipalID:    "11111111-1111-4111-8111-111111111111",
		ProjectID:      "22222222-2222-4222-8222-222222222222",
		IdempotencyKey: "33333333-3333-4333-8333-333333333333",
		LogicalKey:     "agent.preference",
		Kind:           "preference",
		Trust:          "curated",
		Document:       json.RawMessage(`{"title":"Use focused tests"}`),
	}
	if _, err := base.normalized(); err != nil {
		t.Fatalf("valid create rejected: %v", err)
	}
	for _, mutate := range []func(*MemoryCreateRequest){
		func(request *MemoryCreateRequest) { request.PrincipalID = "friendly" },
		func(request *MemoryCreateRequest) { request.ProjectID = "friendly" },
		func(request *MemoryCreateRequest) { request.IdempotencyKey = "friendly" },
		func(request *MemoryCreateRequest) {
			request.LogicalKey = strings.Repeat("k", maxMemoryLogicalKeyRunes+1)
		},
		func(request *MemoryCreateRequest) { request.LogicalKey = "has\ncontrol" },
		func(request *MemoryCreateRequest) { request.Kind = "UPPER" },
		func(request *MemoryCreateRequest) { request.Trust = "" },
	} {
		request := base
		mutate(&request)
		if _, err := request.normalized(); err == nil {
			t.Fatalf("invalid create accepted: %#v", request)
		}
	}
}

func TestMemoryETagIsStrictAndOpaque(t *testing.T) {
	itemID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	etag := memoryETag(itemID, 42)
	if etag == "" || strings.Contains(etag, itemID) || strings.Contains(etag, "42") {
		t.Fatalf("etag exposes internal coordinates: %q", etag)
	}
	if !memoryETagMatches(etag, itemID, 42) || memoryETagMatches(etag, itemID, 41) || memoryETagMatches(etag+" ", itemID, 42) {
		t.Fatalf("etag comparison is not exact: %q", etag)
	}
}

func TestMemoryOutcomeAllowsCurrentTimelineOrigin(t *testing.T) {
	itemID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	result := MemoryMutationResult{
		ItemID: itemID, Revision: 4, ETag: memoryETag(itemID, 4),
		State: MemoryActive, ChangeSequence: 0,
	}
	outcome, err := memoryOutcome(result)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		decoded, err := decodeMemoryOutcome(outcome)
		if err != nil || decoded != result {
			t.Fatalf("timeline-origin replay attempt=%d result=%#v err=%v", attempt, decoded, err)
		}
	}
	result.ChangeSequence = -1
	outcome, err = memoryOutcome(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeMemoryOutcome(outcome); err == nil {
		t.Fatal("negative memory change sequence accepted")
	}
}
