package attachment

import "testing"

func TestServiceDerivesOfferRecipientFromMembership(t *testing.T) {
	service := NewService(PolicyFunc(func(sender, conversation, recipient string, action Action) bool {
		return sender == "sender" && conversation == "conversation" && recipient == "recipient" && action == ActionCreate
	}))
	offer, err := service.CreateOffer(Principal{DeviceID: "sender"}, "conversation", "recipient", "transfer")
	if err != nil {
		t.Fatalf("CreateOffer() error = %v", err)
	}
	if offer.Recipient != "recipient" {
		t.Fatalf("recipient = %q", offer.Recipient)
	}
	if _, err := service.AcceptOffer(Principal{DeviceID: "attacker"}, offer.ID); err == nil {
		t.Fatal("unauthorized principal accepted offer")
	}
}

func TestServiceRequiresCurrentFencedSessionForChunkDownload(t *testing.T) {
	policy := PolicyFunc(func(_, _, _ string, _ Action) bool { return true })
	service := NewService(policy)
	offer, err := service.CreateOffer(Principal{DeviceID: "sender"}, "conversation", "recipient", "transfer")
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.AcceptOffer(Principal{DeviceID: "recipient"}, offer.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.AcceptOffer(Principal{DeviceID: "recipient"}, offer.ID)
	if err != nil {
		t.Fatal(err)
	}
	frame := Chunk{Index: 0, Ciphertext: []byte("ciphertext")}
	frame.Hash = hash("punaro/attachment/ciphertext/v2\x00", frame.Ciphertext)
	if err := service.PutChunk(Principal{DeviceID: "sender"}, offer, "artifact", frame); err != nil {
		t.Fatalf("sender upload error = %v", err)
	}
	if _, err := service.GetChunk(Principal{DeviceID: "recipient"}, offer, first, "artifact", 0); err == nil {
		t.Fatal("stale session downloaded chunk")
	}
	if _, err := service.GetChunk(Principal{DeviceID: "recipient"}, offer, second, "artifact", 0); err != nil {
		t.Fatalf("current session download error = %v", err)
	}
}

func TestServiceRejectsUndeclaredOrIncompleteArtifactCompletion(t *testing.T) {
	service := NewService(PolicyFunc(func(_, _, _ string, _ Action) bool { return true }))
	var plaintextHash [hashSize]byte
	plaintextHash[0] = 1
	spec := OfferSpec{ArtifactID: "artifact", ChunkCount: 2, MaxCiphertextBytes: 32, PlaintextHash: plaintextHash}
	offer, err := service.CreateOfferWithIdempotency(Principal{DeviceID: "sender"}, "conversation", "recipient", "transfer", "request", spec)
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.AcceptOffer(Principal{DeviceID: "recipient"}, offer.ID)
	if err != nil {
		t.Fatal(err)
	}
	frame := Chunk{Index: 0, Ciphertext: []byte("ciphertext")}
	frame.Hash = hash("punaro/attachment/ciphertext/v2\x00", frame.Ciphertext)
	if err := service.PutChunk(Principal{DeviceID: "sender"}, offer, "unexpected", frame); err == nil {
		t.Fatal("undeclared artifact was accepted")
	}
	if err := service.PutChunk(Principal{DeviceID: "sender"}, offer, "artifact", frame); err != nil {
		t.Fatal(err)
	}
	if err := service.Complete(Principal{DeviceID: "recipient"}, offer.ID, session, plaintextHash); err == nil {
		t.Fatal("incomplete artifact was marked complete")
	}
	frame.Index = 2
	if err := service.PutChunk(Principal{DeviceID: "sender"}, offer, "artifact", frame); err == nil {
		t.Fatal("out-of-range chunk was accepted")
	}
	frame.Index = 1
	if err := service.PutChunk(Principal{DeviceID: "sender"}, offer, "artifact", frame); err != nil {
		t.Fatal(err)
	}
	wrong := plaintextHash
	wrong[0] = 2
	if err := service.Complete(Principal{DeviceID: "recipient"}, offer.ID, session, wrong); err == nil {
		t.Fatal("mismatched plaintext commitment was accepted")
	}
	if err := service.Complete(Principal{DeviceID: "recipient"}, offer.ID, session, plaintextHash); err != nil {
		t.Fatal(err)
	}
}
