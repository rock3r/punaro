package attachment

import (
	"bytes"
	"testing"
)

func TestBlobStoreAcceptsIdempotentRetryButRejectsReplacement(t *testing.T) {
	store := NewBlobStore()
	key := BlobKey{TransferID: "transfer", Recipient: "recipient", ArtifactID: "artifact"}
	frame := Chunk{Index: 0, Ciphertext: []byte("ciphertext"), Hash: hash("punaro/attachment/ciphertext/v2\x00", []byte("ciphertext"))}
	if err := store.Put(key, frame, 1024); err != nil {
		t.Fatalf("first Put() error = %v", err)
	}
	if err := store.Put(key, frame, 1024); err != nil {
		t.Fatalf("idempotent Put() error = %v", err)
	}
	replacement := frame
	replacement.Ciphertext = []byte("replacement")
	replacement.Hash = hash("punaro/attachment/ciphertext/v2\x00", replacement.Ciphertext)
	if err := store.Put(key, replacement, 1024); err == nil {
		t.Fatal("replacement Put() succeeded")
	}
	got, ok := store.Get(key, 0)
	if !ok || !bytes.Equal(got.Ciphertext, frame.Ciphertext) {
		t.Fatalf("stored frame = %#v, found = %v", got, ok)
	}
}
