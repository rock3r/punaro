package attachment

import "testing"

func TestServiceCompletionRequiresCurrentRecipientSession(t *testing.T) {
	policy := PolicyFunc(func(_, _, _ string, _ Action) bool { return true })
	service := NewService(policy)
	var plaintextHash [hashSize]byte
	plaintextHash[0] = 1
	spec := OfferSpec{ArtifactID: "artifact", ChunkCount: 1, MaxCiphertextBytes: 32, PlaintextHash: plaintextHash}
	offer, err := service.CreateOfferWithIdempotency(Principal{DeviceID: "sender"}, "conversation", "recipient", "transfer", "request", spec)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := service.AcceptOffer(Principal{DeviceID: "recipient"}, offer.ID)
	if err != nil {
		t.Fatal(err)
	}
	current, err := service.AcceptOffer(Principal{DeviceID: "recipient"}, offer.ID)
	if err != nil {
		t.Fatal(err)
	}
	frame := Chunk{Index: 0, Ciphertext: []byte("ciphertext")}
	frame.Hash = hash("punaro/attachment/ciphertext/v2\x00", frame.Ciphertext)
	if err := service.PutChunk(Principal{DeviceID: "sender"}, offer, "artifact", frame); err != nil {
		t.Fatal(err)
	}
	if err := service.Complete(Principal{DeviceID: "recipient"}, offer.ID, stale, plaintextHash); err == nil {
		t.Fatal("stale session completed attachment")
	}
	if err := service.Complete(Principal{DeviceID: "recipient"}, offer.ID, current, plaintextHash); err != nil {
		t.Fatalf("current session completion error = %v", err)
	}
	if !service.Completed(offer.ID) {
		t.Fatal("completion was not recorded")
	}
}
