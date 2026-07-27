package embeddingprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rock3r/punaro/internal/postgres"
)

func TestOpenAICompatibleProviderUsesPinnedGenerationModel(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer provider-key" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request method=%s authorization=%q content-type=%q", r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"embedding":[0.25,0.75]}]}`))
	}))
	defer server.Close()
	provider, err := NewOpenAICompatible(server.URL, "provider-key", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	generation := postgres.MemoryEmbeddingGeneration{ID: "11111111-1111-4111-8111-111111111111", Model: "text-embedding-3-small", Revision: "2026-07-27", Dimensions: 2, State: postgres.MemoryEmbeddingGenerationActive}
	vector, err := provider.EmbedMemoryQuery(context.Background(), generation, "release decision")
	if err != nil || len(vector) != 2 || vector[0] != 0.25 || vector[1] != 0.75 {
		t.Fatalf("vector=%v err=%v", vector, err)
	}
}
