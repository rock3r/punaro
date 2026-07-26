package postgres

import "testing"

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
