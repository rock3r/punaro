package attachment

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
)

var errImmutableChunk = errors.New("attachment chunk replacement is forbidden")

// BlobKey identifies one recipient-specific encrypted artifact at the relay.
type BlobKey struct {
	TransferID string
	Recipient  string
	ArtifactID string
}

// BlobStore holds only ciphertext frames. It makes retrying an identical upload
// safe while rejecting any attempt to replace a stored index.
type BlobStore struct {
	mu     sync.RWMutex
	frames map[BlobKey]map[int]Chunk
}

// NewBlobStore creates an empty encrypted relay-blob store.
func NewBlobStore() *BlobStore {
	return &BlobStore{frames: make(map[BlobKey]map[int]Chunk)}
}

// Put validates frame self-consistency and atomically admits it at most once.
func (s *BlobStore) Put(key BlobKey, frame Chunk, maxBytes int) error {
	if key.TransferID == "" || key.Recipient == "" || key.ArtifactID == "" || frame.Index < 0 {
		return fmt.Errorf("invalid blob key or frame index")
	}
	computed := hash("punaro/attachment/ciphertext/v2\x00", frame.Ciphertext)
	if !bytes.Equal(computed[:], frame.Hash[:]) {
		return fmt.Errorf("chunk %d hash mismatch", frame.Index)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	frames := s.frames[key]
	if frames == nil {
		frames = make(map[int]Chunk)
		s.frames[key] = frames
	}
	if existing, exists := frames[frame.Index]; exists {
		if bytes.Equal(existing.Ciphertext, frame.Ciphertext) && bytes.Equal(existing.Hash[:], frame.Hash[:]) {
			return nil
		}
		return errImmutableChunk
	}
	storedBytes := 0
	for _, stored := range frames {
		storedBytes += len(stored.Ciphertext)
	}
	if maxBytes < 1 || storedBytes+len(frame.Ciphertext) > maxBytes {
		return ErrUnauthorized
	}
	frames[frame.Index] = cloneChunk(frame)
	return nil
}

// HasAll reports whether every declared frame index is durably present.
func (s *BlobStore) HasAll(key BlobKey, count int) bool {
	if count < 1 {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	frames := s.frames[key]
	if len(frames) != count {
		return false
	}
	for index := 0; index < count; index++ {
		if _, ok := frames[index]; !ok {
			return false
		}
	}
	return true
}

// Get returns a defensive copy of the immutable stored frame.
func (s *BlobStore) Get(key BlobKey, index int) (Chunk, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	frame, ok := s.frames[key][index]
	if !ok {
		return Chunk{}, false
	}
	return cloneChunk(frame), true
}

func cloneChunk(chunk Chunk) Chunk {
	chunk.Ciphertext = append([]byte(nil), chunk.Ciphertext...)
	return chunk
}
