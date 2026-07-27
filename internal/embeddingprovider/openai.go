// Package embeddingprovider contains bounded transport adapters for external
// embedding providers. It contains no database, authorization, or route code.
package embeddingprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"

	"github.com/rock3r/punaro/internal/postgres"
)

const maxResponseBytes = 1 << 20

// OpenAICompatible implements the bounded embeddings request/response shape
// used by OpenAI-compatible HTTPS services.
type OpenAICompatible struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// NewOpenAICompatible constructs a provider transport with an explicit HTTPS
// endpoint and a caller-supplied credential. Credential-file loading remains
// at the process configuration boundary.
func NewOpenAICompatible(endpoint, apiKey string, client *http.Client) (*OpenAICompatible, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.TrimSpace(apiKey) == "" || client == nil {
		return nil, errors.New("OpenAI-compatible embedding provider is invalid")
	}
	return &OpenAICompatible{endpoint: endpoint, apiKey: apiKey, client: client}, nil
}

// EmbedMemoryQuery derives exactly one finite vector for the active pinned
// generation. Provider failures are deliberately content-free to callers.
func (p *OpenAICompatible) EmbedMemoryQuery(ctx context.Context, generation postgres.MemoryEmbeddingGeneration, query string) ([]float64, error) {
	if p == nil || generation.Validate() != nil || generation.State != postgres.MemoryEmbeddingGenerationActive || query == "" {
		return nil, errors.New("embedding provider request is invalid")
	}
	body, err := json.Marshal(struct {
		Model          string `json:"model"`
		Input          string `json:"input"`
		EncodingFormat string `json:"encoding_format"`
	}{Model: generation.Model, Input: query, EncodingFormat: "float"})
	if err != nil {
		return nil, errors.New("embedding provider request is unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("embedding provider request is unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+p.apiKey)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil || response == nil {
		return nil, errors.New("embedding provider is unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxResponseBytes {
		return nil, errors.New("embedding provider is unavailable")
	}
	var decoded struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	if decoder.Decode(&decoded) != nil || len(decoded.Data) != 1 || len(decoded.Data[0].Embedding) != generation.Dimensions {
		return nil, errors.New("embedding provider response is invalid")
	}
	vector := append([]float64(nil), decoded.Data[0].Embedding...)
	for _, value := range vector {
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > math.MaxFloat32 || (value != 0 && float64(float32(value)) == 0) {
			return nil, errors.New("embedding provider response is invalid")
		}
	}
	return vector, nil
}
