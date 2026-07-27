package postgres

import (
	"math"
	"testing"
	"time"
)

func TestMemoryEmbeddingGenerationValidation(t *testing.T) {
	valid := MemoryEmbeddingGeneration{
		ID:         "11111111-1111-4111-8111-111111111111",
		Model:      "local.e5-base",
		Revision:   "2026-07-01",
		Dimensions: 768,
		State:      MemoryEmbeddingGenerationActive,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid generation rejected: %v", err)
	}
	building := valid
	building.State = MemoryEmbeddingGenerationBuilding
	if err := building.Validate(); err != nil {
		t.Fatalf("valid building generation rejected: %v", err)
	}

	for name, generation := range map[string]MemoryEmbeddingGeneration{
		"friendly ID":          {ID: "friendly", Model: valid.Model, Revision: valid.Revision, Dimensions: valid.Dimensions, State: valid.State},
		"empty model":          {ID: valid.ID, Revision: valid.Revision, Dimensions: valid.Dimensions, State: valid.State},
		"control model":        {ID: valid.ID, Model: "local\nmodel", Revision: valid.Revision, Dimensions: valid.Dimensions, State: valid.State},
		"empty revision":       {ID: valid.ID, Model: valid.Model, Dimensions: valid.Dimensions, State: valid.State},
		"oversized dimensions": {ID: valid.ID, Model: valid.Model, Revision: valid.Revision, Dimensions: maxMemoryEmbeddingDimensions + 1, State: valid.State},
		"inactive state":       {ID: valid.ID, Model: valid.Model, Revision: valid.Revision, Dimensions: valid.Dimensions, State: "retired"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := generation.Validate(); err == nil {
				t.Fatalf("invalid generation accepted: %#v", generation)
			}
		})
	}
}

func TestMemoryEmbeddingWorkValidation(t *testing.T) {
	valid := MemoryEmbeddingWork{
		GenerationID:  "11111111-1111-4111-8111-111111111111",
		ItemID:        "22222222-2222-4222-8222-222222222222",
		Revision:      1,
		ContentSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid embedding work rejected: %v", err)
	}

	for name, work := range map[string]MemoryEmbeddingWork{
		"friendly generation": {GenerationID: "generation", ItemID: valid.ItemID, Revision: valid.Revision, ContentSHA256: valid.ContentSHA256},
		"friendly item":       {GenerationID: valid.GenerationID, ItemID: "item", Revision: valid.Revision, ContentSHA256: valid.ContentSHA256},
		"zero revision":       {GenerationID: valid.GenerationID, ItemID: valid.ItemID, Revision: 0, ContentSHA256: valid.ContentSHA256},
		"short hash":          {GenerationID: valid.GenerationID, ItemID: valid.ItemID, Revision: valid.Revision, ContentSHA256: "0123"},
		"uppercase hash":      {GenerationID: valid.GenerationID, ItemID: valid.ItemID, Revision: valid.Revision, ContentSHA256: "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := work.Validate(); err == nil {
				t.Fatalf("invalid embedding work accepted: %#v", work)
			}
		})
	}
}

func TestMemoryEmbeddingClaimValidation(t *testing.T) {
	valid := MemoryEmbeddingClaimRequest{
		WorkerID:      "33333333-3333-4333-8333-333333333333",
		Limit:         8,
		LeaseDuration: memoryEmbeddingMinLease,
	}
	if _, err := valid.normalized(); err != nil {
		t.Fatalf("valid claim rejected: %v", err)
	}
	for name, request := range map[string]MemoryEmbeddingClaimRequest{
		"friendly worker": {WorkerID: "worker", Limit: valid.Limit, LeaseDuration: valid.LeaseDuration},
		"zero limit":      {WorkerID: valid.WorkerID, LeaseDuration: valid.LeaseDuration},
		"oversize limit":  {WorkerID: valid.WorkerID, Limit: maxMemoryEmbeddingClaimBatch + 1, LeaseDuration: valid.LeaseDuration},
		"short lease":     {WorkerID: valid.WorkerID, Limit: valid.Limit, LeaseDuration: memoryEmbeddingMinLease - 1},
		"long lease":      {WorkerID: valid.WorkerID, Limit: valid.Limit, LeaseDuration: memoryEmbeddingMaxLease + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := request.normalized(); err == nil {
				t.Fatalf("invalid claim accepted: %#v", request)
			}
		})
	}
}

func TestMemoryEmbeddingPublicationValidation(t *testing.T) {
	lease := MemoryEmbeddingLease{MemoryEmbeddingWork: MemoryEmbeddingWork{
		GenerationID:  "11111111-1111-4111-8111-111111111111",
		ItemID:        "22222222-2222-4222-8222-222222222222",
		Revision:      1,
		ContentSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}, Attempts: 1, Holder: "33333333-3333-4333-8333-333333333333", Token: "44444444-4444-4444-8444-444444444444", LeaseGeneration: 1, LeaseUntil: time.Now()}
	valid := MemoryEmbeddingPublication{Lease: lease, Chunks: []MemoryEmbeddingChunk{{Ordinal: 0, ContentSHA256: lease.ContentSHA256, StartOffset: 0, EndOffset: 32, Vector: []float64{0.25, 0.5, 0.75}}}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid embedding publication rejected: %v", err)
	}
	for name, publication := range map[string]MemoryEmbeddingPublication{
		"no chunks":         {Lease: lease},
		"nonzero first":     {Lease: lease, Chunks: []MemoryEmbeddingChunk{{Ordinal: 1, ContentSHA256: lease.ContentSHA256, EndOffset: 32, Vector: []float64{0.25}}}},
		"invalid digest":    {Lease: lease, Chunks: []MemoryEmbeddingChunk{{ContentSHA256: "bad", EndOffset: 32, Vector: []float64{0.25}}}},
		"empty range":       {Lease: lease, Chunks: []MemoryEmbeddingChunk{{ContentSHA256: lease.ContentSHA256, EndOffset: 0, Vector: []float64{0.25}}}},
		"empty vector":      {Lease: lease, Chunks: []MemoryEmbeddingChunk{{ContentSHA256: lease.ContentSHA256, EndOffset: 32}}},
		"infinite vector":   {Lease: lease, Chunks: []MemoryEmbeddingChunk{{ContentSHA256: lease.ContentSHA256, EndOffset: 32, Vector: []float64{math.Inf(1)}}}},
		"overlapping range": {Lease: lease, Chunks: []MemoryEmbeddingChunk{{ContentSHA256: lease.ContentSHA256, EndOffset: 32, Vector: []float64{0.25}}, {Ordinal: 1, ContentSHA256: lease.ContentSHA256, StartOffset: 31, EndOffset: 64, Vector: []float64{0.5}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := publication.Validate(); err == nil {
				t.Fatalf("invalid embedding publication accepted: %#v", publication)
			}
		})
	}
}
