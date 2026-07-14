package adapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	attachmentv2 "github.com/rock3r/punaro/internal/attachment/v2"
	"github.com/rock3r/punaro/internal/relay"
)

func TestHTTPRelayClientIssuesHolderSignedPermitRequest(t *testing.T) {
	machinePublic, machinePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, issuerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, holderPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	permitRequest := attachmentv2.PermitRequest{RequestID: [16]byte{1}, HolderDeviceID: [16]byte{2}, HolderGeneration: 1, HolderRole: attachmentv2.PermitHolderSender, TransferID: [16]byte{3}, ConversationID: [16]byte{4}, SenderDeviceID: [16]byte{2}, SenderGeneration: 1, RecipientDeviceID: [16]byte{5}, RecipientGeneration: 1, AttemptGeneration: 1, Operation: attachmentv2.PermitOperationOffer, MembershipCommitment: [32]byte{6}, IssuedAt: uint64(clock.Add(-time.Second).Unix()), ExpiresAt: uint64(clock.Add(20 * time.Second).Unix()), MaxBytes: 1024, MaxChunks: 1, MaxOperations: 1}
	if err := attachmentv2.SignPermitRequest(&permitRequest, holderPrivate); err != nil {
		t.Fatal(err)
	}
	expectedPermit := attachmentv2.Permit{Audience: [32]byte{7}, Serial: [16]byte{8}, IssuerKeyID: [32]byte{9}, HolderDeviceID: permitRequest.HolderDeviceID, HolderGeneration: permitRequest.HolderGeneration, HolderRole: permitRequest.HolderRole, TransferID: permitRequest.TransferID, ConversationID: permitRequest.ConversationID, SenderDeviceID: permitRequest.SenderDeviceID, SenderGeneration: permitRequest.SenderGeneration, RecipientDeviceID: permitRequest.RecipientDeviceID, RecipientGeneration: permitRequest.RecipientGeneration, AttemptGeneration: permitRequest.AttemptGeneration, Operation: permitRequest.Operation, DirectoryHead: [32]byte{10}, MembershipCommitment: permitRequest.MembershipCommitment, RevocationEpoch: 1, IssuedAt: uint64(clock.Unix()), ExpiresAt: uint64(clock.Add(15 * time.Second).Unix()), MaxBytes: permitRequest.MaxBytes, MaxChunks: permitRequest.MaxChunks, MaxOperations: permitRequest.MaxOperations}
	if err := attachmentv2.SignPermit(&expectedPermit, issuerPrivate); err != nil {
		t.Fatal(err)
	}
	expectedRaw, err := attachmentv2.EncodePermit(expectedPermit)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/permits" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/cbor" {
			t.Fatalf("unexpected request %s %s type=%q", r.Method, r.URL.String(), r.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := attachmentv2.DecodePermitRequest(body)
		if err != nil || decoded != permitRequest {
			t.Fatalf("request=%+v err=%v", decoded, err)
		}
		timestamp, err := time.Parse(time.RFC3339Nano, r.Header.Get("X-Punaro-Timestamp"))
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Punaro-Signature"))
		if err != nil || !ed25519.Verify(machinePublic, relay.CanonicalRequest(relay.SignedRequest{MachineID: "machine-a", Method: http.MethodPost, Path: "/v2/permits", Body: body, Timestamp: timestamp, Nonce: r.Header.Get("X-Punaro-Nonce")}), signature) {
			t.Fatal("permit request did not have a valid machine signature")
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(expectedRaw)
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", machinePrivate, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	permit, err := client.IssuePermit(context.Background(), permitRequest)
	if err != nil || permit != expectedPermit {
		t.Fatalf("permit=%+v err=%v", permit, err)
	}
}

func TestHTTPRelayClientFetchesOnlySignedCanonicalDirectorySnapshot(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entry := attachmentv2.DirectoryEntry{Issuer: &attachmentv2.DirectoryPermitIssuer{KeyID: [32]byte{1}, PublicKey: [32]byte{2}}}
	head, err := attachmentv2.EncodeDirectoryHead(attachmentv2.DirectoryHead{Audience: [32]byte{3}, RootKeyID: [32]byte{4}, TreeSize: 1, TreeRoot: [32]byte{5}, Sequence: 1, IssuedAt: 1, ExpiresAt: 2, RevocationEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := attachmentv2.EncodeDirectorySnapshot(attachmentv2.DirectorySnapshot{RawHead: head, Entries: []attachmentv2.DirectoryEntry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/directory" || r.URL.RawQuery != "" {
			t.Fatalf("unexpected directory request %s %s", r.Method, r.URL.String())
		}
		if r.Header.Get("CF-Access-Client-Id") != "access-id" || r.Header.Get("CF-Access-Client-Secret") != "access-secret" {
			t.Fatal("missing Access service-token headers")
		}
		request := signedRequestFromHTTP(t, r, mustReadAll(t, r))
		if !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("directory request was not signed")
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(snapshot)
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{ClientID: "access-id", ClientSecret: "access-secret"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.FetchDirectorySnapshot(context.Background())
	if err != nil || len(got.Entries) != 1 || got.Entries[0].Issuer == nil || got.Entries[0].Issuer.KeyID != entry.Issuer.KeyID {
		t.Fatalf("snapshot=%#v err=%v", got, err)
	}
}

func TestHTTPRelayClientRejectsUnsafeDirectoryResponse(t *testing.T) {
	t.Parallel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/cbor; charset=binary")
		_, _ = w.Write([]byte{0xa0})
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchDirectorySnapshot(context.Background()); err == nil {
		t.Fatal("unsafe directory response accepted")
	}
}

func TestHTTPRelayClientSignsBoundedProtocolRequests(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("CF-Access-Client-Id") != "access-id" || r.Header.Get("CF-Access-Client-Secret") != "access-secret" {
			t.Fatal("missing Access service-token headers")
		}
		var request relay.SignedRequest
		body := mustReadAll(t, r)
		request = signedRequestFromHTTP(t, r, body)
		if request.MachineID != "machine-a" || !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("request was not correctly signed")
		}
		switch r.URL.Path {
		case "/v1/machines/me/endpoints":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"lease_until":"2026-07-13T12:00:00Z"}`))
		case "/v1/deliveries/lease":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"deliveries":[]}`))
		case "/v1/conversations/conversation-1/messages":
			if r.Header.Get("Idempotency-Key") != "send-1" {
				t.Fatal("missing idempotency key")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"message-1","conversation_id":"conversation-1","sequence":1,"from_endpoint":"agent/a","body":"reply","created_at":"2026-07-13T12:00:00Z"}`))
		case "/v1/conversations":
			if r.Header.Get("Idempotency-Key") != "create-1" {
				t.Fatal("missing create idempotency key")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"conversation-created"}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{ClientID: "access-id", ClientSecret: "access-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Advertise(context.Background(), []string{"agent/a"}); err != nil {
		t.Fatal(err)
	}
	deliveries, err := client.Lease(context.Background(), "agent/a")
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("lease = %#v, %v", deliveries, err)
	}
	message, err := client.Send(context.Background(), "conversation-1", "agent/a", "reply", "send-1")
	if err != nil || message.ID != "message-1" {
		t.Fatalf("send = %#v, %v", message, err)
	}
	conversation, err := client.CreateConversation(context.Background(), "agent/a", []relay.Member{{Endpoint: "agent/a", Capabilities: relay.CapSend | relay.CapReceive | relay.CapAdmin}}, "create-1")
	if err != nil || conversation.ID != "conversation-created" {
		t.Fatalf("create=%#v err=%v", conversation, err)
	}
}

func TestHTTPRelayClientReadsPayloadFreeWake(t *testing.T) {
	t.Parallel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/notifications" {
			t.Fatal("unexpected route")
		}
		body := mustReadAll(t, r)
		request := signedRequestFromHTTP(t, r, body)
		if !ed25519.Verify(public, relay.CanonicalRequest(request), request.Signature) {
			t.Fatal("unsigned wake handshake")
		}
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = connection.Close(websocket.StatusNormalClosure, "") }()
		if err := connection.Write(r.Context(), websocket.MessageText, []byte(`{"type":"wake","topic_id":"conversation-1","sequence":7}`)); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()
	client, err := NewHTTPRelayClient(server.URL, "machine-a", private, server.Client(), AccessServiceToken{})
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan relay.WakeEvent, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.ReadNotifications(ctx, func(event relay.WakeEvent) { events <- event }); err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Type != "wake" || event.TopicID != "conversation-1" || event.Sequence != 7 {
			t.Fatalf("event=%#v", event)
		}
	default:
		t.Fatal("wake was not delivered")
	}
}

func TestHTTPRelayClientRejectsInsecureRemoteURLAndPartialAccessToken(t *testing.T) {
	t.Parallel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHTTPRelayClient("http://relay.example", "machine-a", private, http.DefaultClient, AccessServiceToken{}); err == nil {
		t.Fatal("insecure remote URL accepted")
	}
	if _, err := NewHTTPRelayClient("https://relay.example", "machine-a", private, http.DefaultClient, AccessServiceToken{ClientID: "only-id"}); err == nil {
		t.Fatal("partial Access service token accepted")
	}
}

func mustReadAll(t *testing.T, r *http.Request) []byte {
	t.Helper()
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func signedRequestFromHTTP(t *testing.T, request *http.Request, body []byte) relay.SignedRequest {
	t.Helper()
	timestamp, err := time.Parse(time.RFC3339Nano, request.Header.Get("X-Punaro-Timestamp"))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Punaro-Signature"))
	if err != nil {
		t.Fatal(err)
	}
	return relay.SignedRequest{MachineID: request.Header.Get("X-Punaro-Machine"), Method: request.Method, Path: request.URL.Path, Body: body, Timestamp: timestamp, Nonce: request.Header.Get("X-Punaro-Nonce"), Signature: signature}
}
