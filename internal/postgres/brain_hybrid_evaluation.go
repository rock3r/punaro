package postgres

import (
	"errors"
	"math"
	"sort"
)

// MemoryHybridRankingEvaluationCase is one content-free relevance judgment for
// deterministic hybrid candidate ranking evaluation.
type MemoryHybridRankingEvaluationCase struct {
	ID        string
	Results   []MemoryHybridSearchResult
	Relevance map[string]int
}

// MemoryHybridRankingEvaluation aggregates rank-quality metrics across a
// fixed corpus. It contains no query text, memory summaries, or provider data.
type MemoryHybridRankingEvaluation struct {
	Queries                            int     `json:"queries"`
	HitsAtOne                          int     `json:"hits_at_one"`
	MeanReciprocalRank                 float64 `json:"mean_reciprocal_rank"`
	NormalizedDiscountedCumulativeGain float64 `json:"normalized_discounted_cumulative_gain"`
}

// EvaluateMemoryHybridRanking reports deterministic MRR, hit@1, and NDCG for
// a relevance-judged hybrid candidate corpus.
func EvaluateMemoryHybridRanking(cases []MemoryHybridRankingEvaluationCase) (MemoryHybridRankingEvaluation, error) {
	if len(cases) < 1 {
		return MemoryHybridRankingEvaluation{}, errors.New("memory hybrid ranking evaluation is empty")
	}
	var evaluation MemoryHybridRankingEvaluation
	seenCases := make(map[string]struct{}, len(cases))
	for _, fixture := range cases {
		if !validOpaqueID(fixture.ID) || len(fixture.Relevance) < 1 {
			return MemoryHybridRankingEvaluation{}, errors.New("invalid memory hybrid ranking evaluation")
		}
		if _, duplicate := seenCases[fixture.ID]; duplicate {
			return MemoryHybridRankingEvaluation{}, errors.New("invalid memory hybrid ranking evaluation")
		}
		seenCases[fixture.ID] = struct{}{}
		ideal := make([]int, 0, len(fixture.Relevance))
		for itemID, grade := range fixture.Relevance {
			if !validOpaqueID(itemID) || grade < 1 || grade > 3 {
				return MemoryHybridRankingEvaluation{}, errors.New("invalid memory hybrid ranking evaluation")
			}
			ideal = append(ideal, grade)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(ideal)))
		seen := make(map[string]struct{}, len(fixture.Results))
		var reciprocalRank, discountedGain float64
		for index, result := range fixture.Results {
			if !validOpaqueID(result.ItemID) || result.Revision < 1 {
				return MemoryHybridRankingEvaluation{}, errors.New("invalid memory hybrid ranking evaluation")
			}
			if _, duplicate := seen[result.ItemID]; duplicate {
				return MemoryHybridRankingEvaluation{}, errors.New("invalid memory hybrid ranking evaluation")
			}
			seen[result.ItemID] = struct{}{}
			grade := fixture.Relevance[result.ItemID]
			if grade > 0 {
				if reciprocalRank == 0 {
					reciprocalRank = 1 / float64(index+1)
				}
				discountedGain += (math.Pow(2, float64(grade)) - 1) / math.Log2(float64(index+2))
			}
		}
		var idealGain float64
		for index, grade := range ideal[:min(len(ideal), len(fixture.Results))] {
			idealGain += (math.Pow(2, float64(grade)) - 1) / math.Log2(float64(index+2))
		}
		evaluation.Queries++
		if len(fixture.Results) > 0 && fixture.Relevance[fixture.Results[0].ItemID] > 0 {
			evaluation.HitsAtOne++
		}
		evaluation.MeanReciprocalRank += reciprocalRank
		evaluation.NormalizedDiscountedCumulativeGain += discountedGain / idealGain
	}
	evaluation.MeanReciprocalRank /= float64(evaluation.Queries)
	evaluation.NormalizedDiscountedCumulativeGain /= float64(evaluation.Queries)
	return evaluation, nil
}
