package postgres

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxMemoryDocumentBytes   = 256 << 10
	maxMemoryDocumentDepth   = 32
	maxMemoryLogicalKeyRunes = 128
	maxMemoryLogicalKeyBytes = 512
	maxMemoryTokenRunes      = 64
	maxMemoryChangePage      = 100
)

var (
	// ErrMemoryLogicalKeyConflict is content-free and reveals no existing item.
	ErrMemoryLogicalKeyConflict = errors.New("memory logical key is already in use")
	// ErrStaleMemoryETag reports a failed compare-and-swap without revealing content.
	ErrStaleMemoryETag = errors.New("memory ETag is stale")
)

// MemoryState is the closed canonical lifecycle state.
type MemoryState string

const (
	// MemoryActive marks a current canonical memory.
	MemoryActive MemoryState = "active"
	// MemoryArchived marks a reversibly hidden canonical memory.
	MemoryArchived MemoryState = "archived"
)

// MemoryCreateRequest creates one project-scoped curated memory.
type MemoryCreateRequest struct {
	PrincipalID    string
	ProjectID      string
	IdempotencyKey string
	LogicalKey     string
	Kind           string
	Trust          string
	Document       json.RawMessage
}

// MemoryUpdateRequest replaces the canonical document and descriptive metadata.
type MemoryUpdateRequest struct {
	PrincipalID    string
	ProjectID      string
	ItemID         string
	IdempotencyKey string
	ExpectedETag   string
	LogicalKey     string
	Kind           string
	Trust          string
	Document       json.RawMessage
}

// MemoryArchiveRequest changes reversible archive state through exact CAS.
type MemoryArchiveRequest struct {
	PrincipalID    string
	ProjectID      string
	ItemID         string
	IdempotencyKey string
	ExpectedETag   string
	Archived       bool
}

// MemoryDeleteRequest irreversibly purges canonical content through exact CAS.
type MemoryDeleteRequest struct {
	PrincipalID    string
	ProjectID      string
	ItemID         string
	IdempotencyKey string
	ExpectedETag   string
}

// MemoryItem is one authorized current canonical revision.
type MemoryItem struct {
	ItemID         string          `json:"item_id"`
	ScopeID        string          `json:"scope_id"`
	ProjectID      string          `json:"project_id"`
	LogicalKey     string          `json:"logical_key,omitempty"`
	Kind           string          `json:"kind"`
	State          MemoryState     `json:"state"`
	Trust          string          `json:"trust"`
	Revision       int64           `json:"revision"`
	ETag           string          `json:"etag"`
	Document       json.RawMessage `json:"document"`
	ContentSHA256  string          `json:"content_sha256"`
	AuthorID       string          `json:"author_id"`
	CreatedAt      time.Time       `json:"created_at"`
	RevisionAt     time.Time       `json:"revision_at"`
	ChangeSequence int64           `json:"change_sequence"`
}

// MemoryMutationResult is deliberately content-free for durable idempotency.
type MemoryMutationResult struct {
	ItemID         string      `json:"item_id"`
	Revision       int64       `json:"revision"`
	ETag           string      `json:"etag,omitempty"`
	State          MemoryState `json:"state,omitempty"`
	ChangeSequence int64       `json:"change_sequence"`
}

// MemoryChangeType is a closed content-free change classification.
type MemoryChangeType string

const (
	// MemoryChangeCreate records creation.
	MemoryChangeCreate MemoryChangeType = "create"
	// MemoryChangeUpdate records canonical content or metadata replacement.
	MemoryChangeUpdate MemoryChangeType = "update"
	// MemoryChangeArchive records a transition to archived state.
	MemoryChangeArchive MemoryChangeType = "archive"
	// MemoryChangeRestore records a transition to active state.
	MemoryChangeRestore MemoryChangeType = "restore"
	// MemoryChangeDelete records irreversible canonical-content purge.
	MemoryChangeDelete MemoryChangeType = "delete"
	// MemoryChangeQuarantine records automatic-retrieval suppression.
	MemoryChangeQuarantine MemoryChangeType = "quarantine"
	// MemoryChangeQuarantineRelease records restored automatic visibility.
	MemoryChangeQuarantineRelease MemoryChangeType = "quarantine_release"
)

// MemoryChange contains no canonical content or logical key.
type MemoryChange struct {
	TimelineID     string           `json:"timeline_id"`
	ChangeSequence int64            `json:"change_sequence"`
	ScopeID        string           `json:"scope_id"`
	ItemID         string           `json:"item_id"`
	Type           MemoryChangeType `json:"type"`
	Revision       int64            `json:"revision"`
	OccurredAt     time.Time        `json:"occurred_at"`
}

// MemoryChangeRequest fetches one authorized project feed after a durable cursor.
type MemoryChangeRequest struct {
	PrincipalID string
	ProjectID   string
	Cursor      InstallationState
	Limit       int
}

// MemoryChangePage carries legal global-sequence gaps without exposing other projects.
type MemoryChangePage struct {
	Changes []MemoryChange    `json:"changes"`
	Cursor  InstallationState `json:"cursor"`
	More    bool              `json:"more"`
}

func (r MemoryCreateRequest) normalized() (MemoryCreateRequest, error) {
	if !validOpaqueID(r.PrincipalID) || !validOpaqueID(r.ProjectID) || !validOpaqueID(r.IdempotencyKey) ||
		!validMemoryLogicalKey(r.LogicalKey) || !validMemoryToken(r.Kind) || !validMemoryToken(r.Trust) {
		return MemoryCreateRequest{}, errors.New("invalid memory create request")
	}
	document, err := canonicalMemoryDocument(r.Document)
	if err != nil {
		return MemoryCreateRequest{}, err
	}
	r.Document = document
	return r, nil
}

func validMemoryLogicalKey(value string) bool {
	if value == "" {
		return true
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxMemoryLogicalKeyRunes || len(value) > maxMemoryLogicalKeyBytes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validMemoryToken(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= maxMemoryTokenRunes && boundedTokenPattern.MatchString(value)
}

func canonicalMemoryDocument(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxMemoryDocumentBytes {
		return nil, errors.New("invalid memory document")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	value, err := decodeUniqueJSON(decoder, 1)
	if err != nil {
		return nil, errors.New("invalid memory document")
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("memory document must be an object")
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return nil, errors.New("invalid memory document")
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > maxMemoryDocumentBytes {
		return nil, errors.New("invalid memory document")
	}
	return canonical, nil
}

func decodeUniqueJSON(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxMemoryDocumentDepth {
		return nil, errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("invalid object key")
			}
			if _, exists := object[key]; exists {
				return nil, errors.New("duplicate object key")
			}
			value, err := decodeUniqueJSON(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("unterminated object")
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := decodeUniqueJSON(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("unterminated array")
		}
		return array, nil
	default:
		return nil, errors.New("invalid JSON delimiter")
	}
}

func memoryETag(itemID string, revision int64) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("punaro-memory-etag-v1\x00%s\x00%d", itemID, revision)))
	return `"m1-` + hex.EncodeToString(digest[:]) + `"`
}

func memoryETagMatches(candidate, itemID string, revision int64) bool {
	expected := memoryETag(itemID, revision)
	return len(candidate) == len(expected) && subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1
}
