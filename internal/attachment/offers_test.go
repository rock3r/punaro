package attachment

import "testing"

func TestOffersFenceStaleRecipientSessions(t *testing.T) {
	store := NewOfferStore()
	offer, err := store.Create("transfer-1", "recipient-a")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	first, err := store.Accept(offer.ID, "recipient-a")
	if err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}
	second, err := store.Accept(offer.ID, "recipient-a")
	if err != nil {
		t.Fatalf("second Accept() error = %v", err)
	}
	if second.Generation != first.Generation+1 {
		t.Fatalf("generation = %d, want %d", second.Generation, first.Generation+1)
	}
	if store.Authorize(offer.ID, "recipient-a", first.Token, first.Generation) {
		t.Fatal("stale session authorized")
	}
	if !store.Authorize(offer.ID, "recipient-a", second.Token, second.Generation) {
		t.Fatal("current session not authorized")
	}
	if _, err := store.Accept(offer.ID, "recipient-b"); err == nil {
		t.Fatal("wrong recipient accepted offer")
	}
}
