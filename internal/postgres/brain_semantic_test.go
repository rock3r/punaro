package postgres

import (
	"math"
	"testing"
)

func TestMemorySemanticSearchRequestValidation(t *testing.T) {
	valid := MemorySemanticSearchRequest{
		PrincipalID: "11111111-1111-4111-8111-111111111111",
		ProjectID:   "22222222-2222-4222-8222-222222222222",
		Embedding:   []float64{0.25, 0.5, 0.75},
		Limit:       10,
	}
	if _, err := valid.normalized(); err != nil {
		t.Fatalf("valid semantic search rejected: %v", err)
	}
	for name, request := range map[string]MemorySemanticSearchRequest{
		"zero vector": {PrincipalID: valid.PrincipalID, ProjectID: valid.ProjectID, Embedding: []float64{0, 0, 0}, Limit: 1},
		"nan":         {PrincipalID: valid.PrincipalID, ProjectID: valid.ProjectID, Embedding: []float64{math.NaN()}, Limit: 1},
		"overflow":    {PrincipalID: valid.PrincipalID, ProjectID: valid.ProjectID, Embedding: []float64{math.MaxFloat64}, Limit: 1},
		"no limit":    {PrincipalID: valid.PrincipalID, ProjectID: valid.ProjectID, Embedding: valid.Embedding},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := request.normalized(); err == nil {
				t.Fatal("invalid semantic search accepted")
			}
		})
	}
}

func TestMemorySemanticVector(t *testing.T) {
	if got := memorySemanticVector([]float64{0.25, -1, 0}); got != "[0.25,-1,0]" {
		t.Fatalf("semantic vector=%q", got)
	}
}
