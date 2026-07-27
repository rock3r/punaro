package postgres

import "testing"

func TestFuseMemorySearchRanks(t *testing.T) {
	lexical := []MemorySearchResult{
		{ItemID: "11111111-1111-4111-8111-111111111111", Revision: 1},
		{ItemID: "22222222-2222-4222-8222-222222222222", Revision: 2},
	}
	semantic := []MemorySemanticSearchResult{
		{ItemID: "22222222-2222-4222-8222-222222222222", Revision: 2},
		{ItemID: "33333333-3333-4333-8333-333333333333", Revision: 3},
		{ItemID: "11111111-1111-4111-8111-111111111111", Revision: 1},
	}

	got, more, err := fuseMemorySearchRanks(lexical, semantic, 3)
	if err != nil {
		t.Fatalf("fuse ranks: %v", err)
	}
	if more {
		t.Fatal("complete fused candidates reported more")
	}
	if len(got) != 3 {
		t.Fatalf("fused result count=%d", len(got))
	}
	if got[0].ItemID != lexical[1].ItemID || got[0].LexicalRank != 2 || got[0].SemanticRank != 1 {
		t.Fatalf("first fused result=%#v", got[0])
	}
	if got[1].ItemID != lexical[0].ItemID || got[1].LexicalRank != 1 || got[1].SemanticRank != 3 {
		t.Fatalf("second fused result=%#v", got[1])
	}
	if got[2].ItemID != semantic[1].ItemID || got[2].LexicalRank != 0 || got[2].SemanticRank != 2 {
		t.Fatalf("third fused result=%#v", got[2])
	}
}

func TestFuseMemorySearchRanksRejectsInconsistentCandidates(t *testing.T) {
	itemID := "11111111-1111-4111-8111-111111111111"
	if _, _, err := fuseMemorySearchRanks(
		[]MemorySearchResult{{ItemID: itemID, Revision: 1}},
		[]MemorySemanticSearchResult{{ItemID: itemID, Revision: 2}},
		1,
	); err == nil {
		t.Fatal("revision-mismatched candidate lists were fused")
	}
	if _, _, err := fuseMemorySearchRanks(
		[]MemorySearchResult{{ItemID: itemID, Revision: 1}, {ItemID: itemID, Revision: 1}},
		nil,
		1,
	); err == nil {
		t.Fatal("duplicate lexical candidate was fused")
	}
}

func TestFuseMemorySearchRanksReportsUnionTruncation(t *testing.T) {
	got, more, err := fuseMemorySearchRanks(
		[]MemorySearchResult{{ItemID: "11111111-1111-4111-8111-111111111111", Revision: 1}},
		[]MemorySemanticSearchResult{{ItemID: "22222222-2222-4222-8222-222222222222", Revision: 1}},
		1,
	)
	if err != nil || len(got) != 1 || !more {
		t.Fatalf("truncated fused candidates=%#v more=%t err=%v", got, more, err)
	}
}

func TestFuseMemorySearchRanksRanksBeforeTruncating(t *testing.T) {
	got, more, err := fuseMemorySearchRanks(
		[]MemorySearchResult{
			{ItemID: "11111111-1111-4111-8111-111111111111", Revision: 1},
			{ItemID: "22222222-2222-4222-8222-222222222222", Revision: 1},
		},
		[]MemorySemanticSearchResult{
			{ItemID: "33333333-3333-4333-8333-333333333333", Revision: 1},
			{ItemID: "22222222-2222-4222-8222-222222222222", Revision: 1},
		},
		1,
	)
	if err != nil || len(got) != 1 || !more || got[0].ItemID != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("ranked then truncated candidates=%#v more=%t err=%v", got, more, err)
	}
}

func TestMemoryHybridCandidateWindowExceedsOutputPage(t *testing.T) {
	if memoryHybridCandidateLimit <= maxMemorySearchResults || memoryHybridCandidateLimit > maxMemorySearchCandidates {
		t.Fatalf("invalid hybrid candidate window=%d", memoryHybridCandidateLimit)
	}
}

func TestMemoryHybridSearchTimeoutCoversBothStatements(t *testing.T) {
	if memoryHybridSearchTimeout != 2*memorySearchTimeout {
		t.Fatalf("hybrid timeout=%s", memoryHybridSearchTimeout)
	}
}

func TestMemoryHybridSearchRequestValidation(t *testing.T) {
	valid := MemoryHybridSearchRequest{
		PrincipalID: "11111111-1111-4111-8111-111111111111",
		ProjectID:   "22222222-2222-4222-8222-222222222222",
		Query:       "release decision",
		Embedding:   []float64{1, 0.5},
		Limit:       2,
	}
	if _, err := valid.normalized(); err != nil {
		t.Fatalf("valid hybrid request rejected: %v", err)
	}
	valid.Embedding = []float64{0, 0}
	if _, err := valid.normalized(); err == nil {
		t.Fatal("zero hybrid embedding accepted")
	}
}
