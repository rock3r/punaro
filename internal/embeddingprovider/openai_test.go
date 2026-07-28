package embeddingprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rock3r/punaro/internal/postgres"
)

func TestOpenAICompatibleProviderUsesPinnedGenerationModel(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer provider-key" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request method=%s authorization=%q content-type=%q", r.Method, r.Header.Get("Authorization"), r.Header.Get("Content-Type"))
		}
		var request struct {
			Model      string `json:"model"`
			Input      string `json:"input"`
			Dimensions int    `json:"dimensions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Model != "text-embedding-3-small:2026-07-27" || request.Input != "release decision" || request.Dimensions != 2 {
			t.Fatalf("request=%+v err=%v", request, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"text-embedding-3-small:2026-07-27","data":[{"embedding":[0.25,0.75]}]}`))
	}))
	defer server.Close()
	provider, err := NewOpenAICompatible(server.URL, "provider-key", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	generation := activeGeneration()
	vector, err := provider.EmbedMemoryQuery(context.Background(), generation, "release decision")
	if err != nil || len(vector) != 2 || vector[0] != 0.25 || vector[1] != 0.75 {
		t.Fatalf("vector=%v err=%v", vector, err)
	}
}

func TestOpenAICompatibleProviderEmbedsOneFencedCanonicalChunk(t *testing.T) {
	const document = `{"title":"release decision"}`
	digest := sha256.Sum256([]byte(document))
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Model      string `json:"model"`
			Input      string `json:"input"`
			Dimensions int    `json:"dimensions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Model != "text-embedding-3-small:2026-07-27" || request.Input != document || request.Dimensions != 2 {
			t.Fatalf("request=%+v err=%v", request, err)
		}
		_, _ = w.Write([]byte(`{"model":"text-embedding-3-small:2026-07-27","data":[{"embedding":[0.25,0.75]}]}`))
	}))
	defer server.Close()
	provider, err := NewOpenAICompatible(server.URL, "provider-key", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	generation := activeGeneration()
	generation.State = postgres.MemoryEmbeddingGenerationBuilding
	vectors, err := provider.Embed(context.Background(), generation, []postgres.MemoryEmbeddingSourceChunk{{Ordinal: 0, ContentSHA256: hex.EncodeToString(digest[:]), StartOffset: 0, EndOffset: len(document), Text: document}})
	if err != nil || len(vectors) != 1 || len(vectors[0]) != 2 || vectors[0][0] != 0.25 || vectors[0][1] != 0.75 {
		t.Fatalf("vectors=%v err=%v", vectors, err)
	}
}

func TestOpenAICompatibleProviderRejectsUnfencedWorkerChunksBeforeNetwork(t *testing.T) {
	provider, err := NewOpenAICompatible("https://example.com/embeddings", "provider-key", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	for name, chunks := range map[string][]postgres.MemoryEmbeddingSourceChunk{
		"multiple":  {{}, {}},
		"empty":     {{Ordinal: 0, ContentSHA256: strings.Repeat("0", 64), StartOffset: 0, EndOffset: 1, Text: ""}},
		"bad hash":  {{Ordinal: 0, ContentSHA256: strings.Repeat("0", 64), StartOffset: 0, EndOffset: 1, Text: "x"}},
		"oversized": {{Ordinal: 0, ContentSHA256: strings.Repeat("0", 64), StartOffset: 0, EndOffset: maxSourceBytes + 1, Text: strings.Repeat("x", maxSourceBytes+1)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := provider.Embed(context.Background(), activeGeneration(), chunks); err == nil {
				t.Fatal("Embed accepted an unfenced worker chunk")
			}
		})
	}
}

func TestOpenAICompatibleProviderRejectsRedirects(t *testing.T) {
	var redirected atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirected.Store(true)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	provider, err := NewOpenAICompatible(server.URL, "provider-key", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.EmbedMemoryQuery(context.Background(), activeGeneration(), "release decision"); err == nil {
		t.Fatal("EmbedMemoryQuery accepted redirect")
	}
	if redirected.Load() {
		t.Fatal("EmbedMemoryQuery followed redirect")
	}
}

func TestOpenAICompatibleProviderRejectsOversizedOrTrailingResponses(t *testing.T) {
	for name, response := range map[string]string{
		"oversized": strings.Repeat(" ", maxResponseBytes+1),
		"trailing":  `{"model":"text-embedding-3-small:2026-07-27","data":[{"embedding":[0.25,0.75]}]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				_, _ = w.Write([]byte(response))
			}))
			defer server.Close()
			provider, err := NewOpenAICompatible(server.URL, "provider-key", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.EmbedMemoryQuery(context.Background(), activeGeneration(), "release decision"); err == nil {
				t.Fatalf("EmbedMemoryQuery accepted %s response", name)
			}
		})
	}
}

func TestOpenAICompatibleProviderOmitsDimensionsForUnsupportedModel(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if _, ok := request["dimensions"]; ok {
			t.Fatalf("request unexpectedly includes dimensions: %+v", request)
		}
		_, _ = w.Write([]byte(`{"model":"text-embedding-ada-002:2026-07-27","data":[{"embedding":[0.25,0.75]}]}`))
	}))
	defer server.Close()
	provider, err := NewOpenAICompatible(server.URL, "provider-key", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	generation := activeGeneration()
	generation.Model = "text-embedding-ada-002:2026-07-27"
	if _, err := provider.EmbedMemoryQuery(context.Background(), generation, "release decision"); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAICompatibleProviderRejectsUnexpectedResponseModel(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"model":"unexpected-model","data":[{"embedding":[0.25,0.75]}]}`))
	}))
	defer server.Close()
	provider, err := NewOpenAICompatible(server.URL, "provider-key", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.EmbedMemoryQuery(context.Background(), activeGeneration(), "release decision"); err == nil {
		t.Fatal("EmbedMemoryQuery accepted mismatched response model")
	}
}

func TestOpenAICompatibleProviderRejectsDuplicateResponseMembers(t *testing.T) {
	for name, response := range map[string]string{
		"model":     `{"model":"unexpected","model":"text-embedding-3-small:2026-07-27","data":[{"embedding":[0.25,0.75]}]}`,
		"case":      `{"model":"unexpected","MODEL":"text-embedding-3-small:2026-07-27","data":[{"embedding":[0.25,0.75]}]}`,
		"data":      `{"model":"text-embedding-3-small:2026-07-27","data":[],"data":[{"embedding":[0.25,0.75]}]}`,
		"embedding": `{"model":"text-embedding-3-small:2026-07-27","data":[{"embedding":[],"embedding":[0.25,0.75]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(response))
			}))
			defer server.Close()
			provider, err := NewOpenAICompatible(server.URL, "provider-key", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.EmbedMemoryQuery(context.Background(), activeGeneration(), "release decision"); err == nil {
				t.Fatalf("EmbedMemoryQuery accepted duplicate %s member", name)
			}
		})
	}
}

func TestRejectDuplicateJSONMembersRejectsExcessiveNesting(t *testing.T) {
	deepJSON := strings.Repeat("[", maxJSONDepth+1) + "0" + strings.Repeat("]", maxJSONDepth+1)
	if err := rejectDuplicateJSONMembers([]byte(deepJSON)); err == nil {
		t.Fatal("rejectDuplicateJSONMembers accepted excessive nesting")
	}
}

func TestOpenAICompatibleProviderRejectsUnderflowingNumericLiteral(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"model":"text-embedding-3-small:2026-07-27","data":[{"embedding":[1e-1000,0.75]}]}`))
	}))
	defer server.Close()
	provider, err := NewOpenAICompatible(server.URL, "provider-key", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.EmbedMemoryQuery(context.Background(), activeGeneration(), "release decision"); err == nil {
		t.Fatal("EmbedMemoryQuery accepted an underflowing numeric literal")
	}
}

func TestOpenAICompatibleProviderRejectsOversizedQuery(t *testing.T) {
	provider, err := NewOpenAICompatible("https://example.com/embeddings", "provider-key", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.EmbedMemoryQuery(context.Background(), activeGeneration(), strings.Repeat("x", maxQueryBytes+1)); err == nil {
		t.Fatal("EmbedMemoryQuery accepted oversized query")
	}
}

func activeGeneration() postgres.MemoryEmbeddingGeneration {
	return postgres.MemoryEmbeddingGeneration{ID: "11111111-1111-4111-8111-111111111111", Model: "text-embedding-3-small:2026-07-27", Revision: "2026-07-27", Dimensions: 2, State: postgres.MemoryEmbeddingGenerationActive}
}
