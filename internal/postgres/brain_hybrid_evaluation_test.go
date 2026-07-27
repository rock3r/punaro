package postgres

import (
	"math"
	"testing"
)

func TestEvaluateMemoryHybridRanking(t *testing.T) {
	evaluation, err := EvaluateMemoryHybridRanking([]MemoryHybridRankingEvaluationCase{
		{
			ID: "11111111-1111-4111-8111-111111111111",
			Results: []MemoryHybridSearchResult{
				{ItemID: "22222222-2222-4222-8222-222222222222", Revision: 1},
				{ItemID: "33333333-3333-4333-8333-333333333333", Revision: 1},
			},
			Relevance: map[string]int{"33333333-3333-4333-8333-333333333333": 2},
		},
		{
			ID:        "44444444-4444-4444-8444-444444444444",
			Results:   []MemoryHybridSearchResult{{ItemID: "55555555-5555-4555-8555-555555555555", Revision: 1}},
			Relevance: map[string]int{"55555555-5555-4555-8555-555555555555": 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Queries != 2 || evaluation.HitsAtOne != 1 || math.Abs(evaluation.MeanReciprocalRank-0.75) > 1e-9 || math.Abs(evaluation.NormalizedDiscountedCumulativeGain-0.8154648768) > 1e-9 {
		t.Fatalf("evaluation=%#v", evaluation)
	}
}
