package attachment

import "testing"

func TestServiceSignalsRequireAuthorizedSenderOrCurrentRecipient(t *testing.T) {
	policy := PolicyFunc(func(_, _, _ string, _ Action) bool { return true })
	service := NewService(policy)
	offer, err := service.CreateOffer(Principal{DeviceID: "sender"}, "conversation", "recipient", "transfer")
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Signal(Principal{DeviceID: "attacker"}, offer.ID, Session{}, []byte("offer")); err == nil {
		t.Fatal("attacker posted signal")
	}
	recipient, err := service.AcceptOffer(Principal{DeviceID: "recipient"}, offer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Signal(Principal{DeviceID: "sender"}, offer.ID, Session{}, []byte("offer")); err != nil {
		t.Fatalf("sender signal error = %v", err)
	}
	if err := service.Signal(Principal{DeviceID: "recipient"}, offer.ID, recipient, []byte("answer")); err != nil {
		t.Fatalf("recipient signal error = %v", err)
	}
	if got := service.Signals(offer.ID); len(got) != 2 || string(got[0].Payload) != "offer" || string(got[1].Payload) != "answer" {
		t.Fatalf("signals = %#v", got)
	}
}

func TestServiceSignalsRejectOfferBudgetExhaustion(t *testing.T) {
	service := NewService(PolicyFunc(func(_, _, _ string, _ Action) bool { return true }))
	offer, err := service.CreateOffer(Principal{DeviceID: "sender"}, "conversation", "recipient", "transfer")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxSignalEntries; index++ {
		if err := service.Signal(Principal{DeviceID: "sender"}, offer.ID, Session{}, []byte("signal")); err != nil {
			t.Fatalf("signal %d: %v", index, err)
		}
	}
	if err := service.Signal(Principal{DeviceID: "sender"}, offer.ID, Session{}, []byte("overflow")); err == nil {
		t.Fatal("signal budget accepted an extra record")
	}
}
