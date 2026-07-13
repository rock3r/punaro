package attachment

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSQLiteOffersFenceSessionsAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/attachments.db"
	firstStore, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := firstStore.Create("transfer", "recipient")
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstStore.Accept(offer.ID, "recipient")
	if err != nil {
		t.Fatal(err)
	}
	if err := firstStore.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	second, err := restarted.Accept(offer.ID, "recipient")
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation != first.Generation+1 {
		t.Fatalf("generation = %d, want %d", second.Generation, first.Generation+1)
	}
	if restarted.Authorize(offer.ID, "recipient", first.Token, first.Generation) {
		t.Fatal("pre-restart session remained authorized")
	}
}

func TestSQLiteOfferSessionExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store, err := openSQLiteOfferStore(t.TempDir()+"/attachments.db", func() time.Time { return now }, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	offer, err := store.Create("transfer", "recipient")
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Accept(offer.ID, "recipient")
	if err != nil {
		t.Fatal(err)
	}
	if !store.Authorize(offer.ID, "recipient", session.Token, session.Generation) {
		t.Fatal("fresh session was unauthorized")
	}
	now = now.Add(time.Minute)
	if store.Authorize(offer.ID, "recipient", session.Token, session.Generation) {
		t.Fatal("expired session remained authorized")
	}
}

func TestSQLiteOfferCreationIsIdempotentAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/attachments.db"
	store, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.CreateWithContext("transfer", "recipient", "sender", "conversation", "request-key", defaultOfferSpec())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	second, err := restarted.CreateWithContext("transfer", "recipient", "sender", "conversation", "request-key", defaultOfferSpec())
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("retry offer = %#v, want %#v", second, first)
	}
	if _, sender, conversation, found, err := restarted.LoadContext(first.ID); err != nil || !found || sender != "sender" || conversation != "conversation" {
		t.Fatalf("persisted context = %q/%q/%v/%v", sender, conversation, found, err)
	}
}

func TestSQLiteServiceResumesOfferAuthorizationAfterRestart(t *testing.T) {
	path := t.TempDir() + "/attachments.db"
	policy := PolicyFunc(func(_, _, _ string, _ Action) bool { return true })
	store, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	service := NewServiceWithOfferRepository(policy, store)
	offer, err := service.CreateOffer(Principal{DeviceID: "sender"}, "conversation", "recipient", "transfer")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restartedStore, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restartedStore.Close() }()
	restartedService := NewServiceWithOfferRepository(policy, restartedStore)
	if _, err := restartedService.AcceptOffer(Principal{DeviceID: "recipient"}, offer.ID); err != nil {
		t.Fatalf("AcceptOffer() after restart error = %v", err)
	}
}

func TestSQLiteServiceWithOfferRepositoryKeepsCiphertextDurable(t *testing.T) {
	path := t.TempDir() + "/attachments.db"
	policy := PolicyFunc(func(_, _, _ string, _ Action) bool { return true })
	store, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	service := NewServiceWithOfferRepository(policy, store)
	var plaintextHash [hashSize]byte
	spec := OfferSpec{ArtifactID: "artifact", ChunkCount: 1, MaxCiphertextBytes: 32, PlaintextHash: plaintextHash}
	offer, err := service.CreateOfferWithIdempotency(Principal{DeviceID: "sender"}, "conversation", "recipient", "transfer", "request", spec)
	if err != nil {
		t.Fatal(err)
	}
	frame := Chunk{Index: 0, Ciphertext: []byte("ciphertext")}
	frame.Hash = hash("punaro/attachment/ciphertext/v2\x00", frame.Ciphertext)
	if err := service.PutChunk(Principal{DeviceID: "sender"}, offer, "artifact", frame); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restartedStore, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restartedStore.Close() }()
	restarted := NewServiceWithOfferRepository(policy, restartedStore)
	session, err := restarted.AcceptOffer(Principal{DeviceID: "recipient"}, offer.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.GetChunkByOfferID(Principal{DeviceID: "recipient"}, offer.ID, session, "artifact", 0)
	if err != nil || string(got.Ciphertext) != "ciphertext" {
		t.Fatalf("durable chunk = %#v, %v", got, err)
	}
}

func TestSQLiteBlobFramesAreImmutableAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/attachments.db"
	store, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	key := BlobKey{TransferID: "transfer", Recipient: "recipient", ArtifactID: "artifact"}
	frame := Chunk{Index: 0, Ciphertext: []byte("ciphertext")}
	frame.Hash = hash("punaro/attachment/ciphertext/v2\x00", frame.Ciphertext)
	if err := store.Put(key, frame, 1024); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	got, ok := restarted.Get(key, 0)
	if !ok || string(got.Ciphertext) != "ciphertext" {
		t.Fatalf("Get() = %#v, %v", got, ok)
	}
	replacement := frame
	replacement.Ciphertext = []byte("replacement")
	replacement.Hash = hash("punaro/attachment/ciphertext/v2\x00", replacement.Ciphertext)
	if err := restarted.Put(key, replacement, 1024); err == nil {
		t.Fatal("replacement chunk accepted after restart")
	}
}

func TestSQLiteCompletionIsIdempotentAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/attachments.db"
	store, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	var hash [hashSize]byte
	hash[0] = 1
	if err := store.RecordCompletion("offer", "recipient", hash); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	if err := restarted.RecordCompletion("offer", "recipient", hash); err != nil {
		t.Fatalf("idempotent completion error = %v", err)
	}
	changed := hash
	changed[0] = 2
	if err := restarted.RecordCompletion("offer", "recipient", changed); err == nil {
		t.Fatal("conflicting completion accepted")
	}
}

func TestSQLiteSignalsPersistInSequenceAcrossRestart(t *testing.T) {
	path := t.TempDir() + "/attachments.db"
	store, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendSignal("offer", "sender", []byte("offer")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenSQLiteOfferStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restarted.Close() }()
	if err := restarted.AppendSignal("offer", "recipient", []byte("answer")); err != nil {
		t.Fatal(err)
	}
	signals, err := restarted.ListSignals("offer")
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 2 || signals[0].Sequence != 1 || signals[1].Sequence != 2 {
		t.Fatalf("signals = %#v", signals)
	}
}

func TestSQLiteSignalsSerializeConcurrentAppends(t *testing.T) {
	store, err := OpenSQLiteOfferStore(t.TempDir() + "/attachments.db")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	const writes = 32
	var group sync.WaitGroup
	errs := make(chan error, writes)
	for index := 0; index < writes; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			errs <- store.AppendSignal("offer", "sender", []byte(fmt.Sprintf("signal-%d", index)))
		}(index)
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append: %v", err)
		}
	}
	signals, err := store.ListSignals("offer")
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != writes {
		t.Fatalf("signal count = %d, want %d", len(signals), writes)
	}
	expectedSequence := uint64(1)
	for index, signal := range signals {
		if signal.Sequence != expectedSequence {
			t.Fatalf("signal[%d].sequence = %d", index, signal.Sequence)
		}
		expectedSequence++
	}
}
