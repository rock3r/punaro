// Package embeddingprovider contains bounded transport adapters for external
// embedding providers. It contains no database, authorization, or route code.
package embeddingprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/rock3r/punaro/internal/postgres"
)

const (
	maxResponseBytes = 1 << 20
	maxQueryBytes    = 1024
	maxQueryRunes    = 256
	maxSourceBytes   = 256 << 10
	maxJSONDepth     = 32
)

// OpenAICompatible implements the bounded embeddings request/response shape
// used by OpenAI-compatible HTTPS services.
type OpenAICompatible struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// NewOpenAICompatible constructs a provider transport with an explicit HTTPS
// endpoint and caller-supplied credential. Credential-file loading remains at
// the process configuration boundary.
func NewOpenAICompatible(endpoint, apiKey string, client *http.Client) (*OpenAICompatible, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.TrimSpace(apiKey) == "" || client == nil {
		return nil, errors.New("OpenAI-compatible embedding provider is invalid")
	}
	boundedClient := *client
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &OpenAICompatible{endpoint: endpoint, apiKey: apiKey, client: &boundedClient}, nil
}

// EmbedMemoryQuery derives exactly one finite vector for the active pinned
// generation. Provider failures are deliberately content-free to callers.
func (p *OpenAICompatible) EmbedMemoryQuery(ctx context.Context, generation postgres.MemoryEmbeddingGeneration, query string) ([]float64, error) {
	if p == nil || generation.Validate() != nil || generation.State != postgres.MemoryEmbeddingGenerationActive || !immutableProviderModel(generation.Model, generation.Revision) || query == "" || !utf8.ValidString(query) || len(query) > maxQueryBytes || utf8.RuneCountInString(query) > maxQueryRunes {
		return nil, errors.New("embedding provider request is invalid")
	}
	return p.embed(ctx, generation, query)
}

// Embed derives one vector for the current single, fenced canonical-document
// chunk. Later source chunking must extend this transport deliberately rather
// than silently increasing a provider request's content or response bounds.
func (p *OpenAICompatible) Embed(ctx context.Context, generation postgres.MemoryEmbeddingGeneration, chunks []postgres.MemoryEmbeddingSourceChunk) ([][]float64, error) {
	if p == nil || generation.Validate() != nil || !immutableProviderModel(generation.Model, generation.Revision) || len(chunks) != 1 {
		return nil, errors.New("embedding provider request is invalid")
	}
	chunk := chunks[0]
	digest := sha256.Sum256([]byte(chunk.Text))
	if chunk.Ordinal != 0 || chunk.StartOffset != 0 || chunk.EndOffset != len(chunk.Text) || chunk.EndOffset < 1 || len(chunk.Text) > maxSourceBytes || !utf8.ValidString(chunk.Text) || len(chunk.ContentSHA256) != 64 || hex.EncodeToString(digest[:]) != chunk.ContentSHA256 {
		return nil, errors.New("embedding provider request is invalid")
	}
	vector, err := p.embed(ctx, generation, chunk.Text)
	if err != nil {
		return nil, err
	}
	return [][]float64{vector}, nil
}

func (p *OpenAICompatible) embed(ctx context.Context, generation postgres.MemoryEmbeddingGeneration, input string) ([]float64, error) {
	var dimensions *int
	if strings.HasPrefix(generation.Model, "text-embedding-3-") {
		dimensions = &generation.Dimensions
	}
	body, err := json.Marshal(struct {
		Model          string `json:"model"`
		Input          string `json:"input"`
		Dimensions     *int   `json:"dimensions,omitempty"`
		EncodingFormat string `json:"encoding_format"`
	}{Model: generation.Model, Input: input, Dimensions: dimensions, EncodingFormat: "float"})
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
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(responseBody) > maxResponseBytes {
		return nil, errors.New("embedding provider response is invalid")
	}
	var decoded struct {
		Model string `json:"model"`
		Data  []struct {
			Embedding []json.Number `json:"embedding"`
		} `json:"data"`
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.UseNumber()
	if rejectDuplicateJSONMembers(responseBody) != nil || decoder.Decode(&decoded) != nil || decoded.Model != generation.Model || len(decoded.Data) != 1 || len(decoded.Data[0].Embedding) != generation.Dimensions {
		return nil, errors.New("embedding provider response is invalid")
	}
	vector := make([]float64, len(decoded.Data[0].Embedding))
	for index, number := range decoded.Data[0].Embedding {
		value, err := number.Float64()
		literal, ok := new(big.Rat).SetString(string(number))
		if err != nil || !ok || (literal.Sign() != 0 && value == 0) || math.IsNaN(value) || math.IsInf(value, 0) || math.Abs(value) > math.MaxFloat32 || (value != 0 && float64(float32(value)) == 0) {
			return nil, errors.New("embedding provider response is invalid")
		}
		vector[index] = value
	}
	return vector, nil
}

func immutableProviderModel(model, revision string) bool {
	return strings.HasSuffix(model, ":"+revision)
}

func rejectDuplicateJSONMembers(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := consumeJSONValue(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("unexpected JSON value")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			member, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := member.(string)
			if !ok {
				return errors.New("JSON object member is invalid")
			}
			if name != strings.ToLower(name) {
				return errors.New("JSON object member is noncanonical")
			}
			if _, exists := members[name]; exists {
				return errors.New("JSON object has duplicate member")
			}
			members[name] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("JSON delimiter is invalid")
	}
}
